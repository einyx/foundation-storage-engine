package s3

import (
	"bytes"
	"crypto/md5" //nolint:gosec // MD5 is required for S3 compatibility
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/storage"
)

// initiateMultipartUpload handles the initiation of a multipart upload
func (h *Handler) initiateMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	metadata := make(map[string]string)
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		metadata["Content-Type"] = contentType
	}

	uploadID, err := h.storage.InitiateMultipartUpload(ctx, bucket, key, metadata)
	if err != nil {
		logrus.WithError(err).Error("Failed to initiate multipart upload")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	type initiateMultipartUploadResult struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}

	response := initiateMultipartUploadResult{
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
	}

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to encode initiate multipart response")
	}
}

// uploadPart handles uploading a part for multipart upload
func (h *Handler) uploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID, partNumberStr string) {
	defer func() {
		if rec := recover(); rec != nil {
			logrus.WithFields(logrus.Fields{
				"bucket":     bucket,
				"key":        key,
				"uploadID":   uploadID,
				"partNumber": partNumberStr,
				"panic":      fmt.Sprintf("%v", rec),
				"method":     "PUT (uploadPart)",
			}).Error("Panic recovered in uploadPart")
			if !isResponseStarted(w) {
				h.sendError(w, fmt.Errorf("internal server error"), http.StatusInternalServerError)
			}
		}
	}()

	userAgent := r.Header.Get("User-Agent")
	isAWSCLI := isAWSCLIClient(userAgent)

	logger := logrus.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"uploadID":      uploadID,
		"partNumber":    partNumberStr,
		"userAgent":     userAgent,
		"isAWSCLI":      isAWSCLI,
		"table":         extractTableName(key),
		"isIcebergFile": isIcebergMetadata(key) || isIcebergData(key),
	})

	logger.Info("Upload part request")

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil {
		logger.WithError(err).Error("Invalid part number")
		h.sendError(w, fmt.Errorf("invalid part number: %s", partNumberStr), http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	size := r.ContentLength
	if decoded := r.Header.Get("X-Amz-Decoded-Content-Length"); decoded != "" {
		if decodedSize, parseErr := strconv.ParseInt(decoded, 10, 64); parseErr == nil {
			size = decodedSize
		} else {
			logger.WithError(parseErr).Warn("Failed to parse X-Amz-Decoded-Content-Length header")
		}
	}

	var body io.Reader = r.Body
	if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ||
		r.Header.Get("Content-Encoding") == "aws-chunked" {
		body = storage.NewSmartChunkDecoder(r.Body)
		logger.Info("Using SmartChunkDecoder for chunked part upload")
	}

	partReader := body
	if size < 0 {
		data, readErr := io.ReadAll(partReader)
		if readErr != nil {
			logger.WithError(readErr).Error("Failed to buffer part data with unknown size")
			h.sendError(w, fmt.Errorf("failed to read part data: %w", readErr), http.StatusBadRequest)
			return
		}
		size = int64(len(data))
		partReader = bytes.NewReader(data)
		logger.WithField("bufferedSize", size).Debug("Buffered part data to determine size")
	}

	etag, err := h.storage.UploadPart(r.Context(), bucket, key, uploadID, partNumber, partReader, size)
	if err != nil {
		logger.WithError(err).Error("Failed to upload part to backend")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	logger.WithFields(logrus.Fields{
		"partNumber": partNumber,
		"size":       size,
		"etag":       etag,
		"bodyType":   fmt.Sprintf("%T", partReader),
	}).Info("Part upload completed")

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

// completeMultipartUpload handles completing a multipart upload
func (h *Handler) completeMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	logger := logrus.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"uploadID":      uploadID,
		"table":         extractTableName(key),
		"isIcebergFile": isIcebergMetadata(key) || isIcebergData(key),
	})

	logger.Info("Complete multipart upload request")

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read completion request body")
		h.sendError(w, fmt.Errorf("failed to read completion body: %w", err), http.StatusBadRequest)
		return
	}

	type completePart struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	}

	type completeMultipartUploadRequest struct {
		Parts []completePart `xml:"Part"`
	}

	var req completeMultipartUploadRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		logger.WithError(err).Error("Failed to parse completion XML")
		h.sendError(w, fmt.Errorf("invalid CompleteMultipartUpload XML: %w", err), http.StatusBadRequest)
		return
	}

	if len(req.Parts) == 0 {
		logger.Warn("Complete multipart upload called without parts")
		h.sendError(w, fmt.Errorf("no parts provided for completion"), http.StatusBadRequest)
		return
	}

	completedParts := make([]storage.CompletedPart, 0, len(req.Parts))
	for _, p := range req.Parts {
		if p.PartNumber <= 0 {
			logger.WithField("part", p.PartNumber).Error("Invalid part number in completion request")
			h.sendError(w, fmt.Errorf("invalid part number: %d", p.PartNumber), http.StatusBadRequest)
			return
		}

		etag := strings.TrimSpace(p.ETag)
		etag = strings.Trim(etag, `"`)
		if etag == "" {
			logger.WithField("part", p.PartNumber).Error("Missing ETag in completion request")
			h.sendError(w, fmt.Errorf("missing ETag for part %d", p.PartNumber), http.StatusBadRequest)
			return
		}

		completedParts = append(completedParts, storage.CompletedPart{
			PartNumber: p.PartNumber,
			ETag:       etag,
		})
	}

	if err := h.storage.CompleteMultipartUpload(r.Context(), bucket, key, uploadID, completedParts); err != nil {
		logger.WithError(err).Error("Failed to complete multipart upload in backend")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	finalETag := ""
	if info, headErr := h.storage.HeadObject(r.Context(), bucket, key); headErr == nil {
		finalETag = info.ETag
	} else {
		logger.WithError(headErr).Warn("HeadObject after multipart completion failed; calculating fallback ETag")
		hasher := md5.New() //nolint:gosec // MD5 is required for S3 ETag compatibility
		for _, part := range completedParts {
			if partMD5, decodeErr := hex.DecodeString(part.ETag); decodeErr == nil {
				hasher.Write(partMD5)
			}
		}
		finalETag = fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(hasher.Sum(nil)), len(completedParts))
	}

	if finalETag != "" && !strings.HasPrefix(finalETag, `"`) {
		finalETag = fmt.Sprintf(`"%s"`, strings.Trim(finalETag, `"`))
	}

	type completeMultipartUploadResult struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}

	response := completeMultipartUploadResult{
		Location: fmt.Sprintf("/%s/%s", bucket, key),
		Bucket:   bucket,
		Key:      key,
		ETag:     finalETag,
	}

	logger.WithFields(logrus.Fields{
		"etag":      finalETag,
		"partCount": len(completedParts),
	}).Info("Multipart upload completed")

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logger.WithError(err).Error("Failed to encode completion response")
	}
}

// abortMultipartUpload handles aborting a multipart upload
func (h *Handler) abortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	logger := logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	})

	logger.Info("Abort multipart upload request")

	if err := h.storage.AbortMultipartUpload(r.Context(), bucket, key, uploadID); err != nil {
		logger.WithError(err).Error("Failed to abort multipart upload in backend")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// listParts handles listing uploaded parts for an in-progress multipart upload
func (h *Handler) listParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	logger := logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	})

	maxParts := 1000
	if maxPartsStr := r.URL.Query().Get("max-parts"); maxPartsStr != "" {
		if parsed, err := strconv.Atoi(maxPartsStr); err == nil && parsed > 0 {
			maxParts = parsed
		} else if err != nil {
			logger.WithError(err).Warn("Invalid max-parts parameter, using default")
		}
	}

	partNumberMarker := 0
	if markerStr := r.URL.Query().Get("part-number-marker"); markerStr != "" {
		if parsed, err := strconv.Atoi(markerStr); err == nil && parsed >= 0 {
			partNumberMarker = parsed
		} else if err != nil {
			logger.WithError(err).Warn("Invalid part-number-marker parameter, using default")
		}
	}

	result, err := h.storage.ListParts(r.Context(), bucket, key, uploadID, maxParts, partNumberMarker)
	if err != nil {
		logger.WithError(err).Error("Failed to list multipart upload parts")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	type partInfo struct {
		PartNumber   int    `xml:"PartNumber"`
		LastModified string `xml:"LastModified,omitempty"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
	}

	type listPartsResponse struct {
		XMLName              xml.Name   `xml:"ListPartsResult"`
		Bucket               string     `xml:"Bucket"`
		Key                  string     `xml:"Key"`
		UploadID             string     `xml:"UploadId"`
		PartNumberMarker     int        `xml:"PartNumberMarker"`
		NextPartNumberMarker int        `xml:"NextPartNumberMarker"`
		MaxParts             int        `xml:"MaxParts"`
		IsTruncated          bool       `xml:"IsTruncated"`
		Parts                []partInfo `xml:"Part"`
	}

	response := listPartsResponse{
		Bucket:               bucket,
		Key:                  key,
		UploadID:             uploadID,
		PartNumberMarker:     result.PartNumberMarker,
		NextPartNumberMarker: result.NextPartNumberMarker,
		MaxParts:             result.MaxParts,
		IsTruncated:          result.IsTruncated,
	}

	for _, p := range result.Parts {
		part := partInfo{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
			Size:       p.Size,
		}
		if !p.LastModified.IsZero() {
			part.LastModified = p.LastModified.UTC().Format(time.RFC3339)
		}
		response.Parts = append(response.Parts, part)
	}

	logger.WithFields(logrus.Fields{
		"returnedParts": len(response.Parts),
		"isTruncated":   response.IsTruncated,
	}).Info("List parts completed")

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logger.WithError(err).Error("Failed to encode list parts response")
	}
}
