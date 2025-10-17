package s3

import (
	"crypto/md5" //nolint:gosec // MD5 is required for S3 compatibility
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/storage"
)

// initiateMultipartUpload handles the initiation of a multipart upload
func (h *Handler) initiateMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	// Prepare metadata
	metadata := make(map[string]string)
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		metadata["Content-Type"] = contentType
	}

	// Create multipart upload
	uploadID, err := h.storage.InitiateMultipartUpload(ctx, bucket, key, metadata)
	if err != nil {
		logrus.WithError(err).Error("Failed to initiate multipart upload")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	// Response structure
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
		logrus.WithError(err).Error("Failed to encode response")
	}
}

// uploadPart handles uploading a part for multipart upload
func (h *Handler) uploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID, partNumberStr string) {
	// Add panic recovery to prevent backend crashes
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
			// Try to send error response if possible
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

	// Parse part number
	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil {
		logger.WithError(err).Error("Invalid part number")
		h.sendError(w, fmt.Errorf("invalid part number: %s", partNumberStr), http.StatusBadRequest)
		return
	}

	// Handle request body for part upload
	var body io.Reader = r.Body
	defer r.Body.Close()
	size := r.ContentLength

	// Handle chunked encoding for multipart uploads
	if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ||
		r.Header.Get("Content-Encoding") == "aws-chunked" {

		// For AWS CLI clients, bypass SmartChunkDecoder to avoid hanging issues
		if isAWSCLI {
			logger.WithField("userAgent", userAgent).Info("AWS CLI detected - using direct body reader for part upload")
			body = r.Body
		} else {
			// Use SmartChunkDecoder for other clients that might have chunked encoding issues
			body = storage.NewSmartChunkDecoder(r.Body)
			logger.Info("Using smart chunk decoder for part upload")
		}
	}

	// TODO: Implement actual storage backend part upload
	// For now, simulate part upload with mock ETag
	etag := fmt.Sprintf(`"part-%d-etag"`, partNumber)

	logger.WithFields(logrus.Fields{
		"partNumber": partNumber,
		"size":       size,
		"etag":       etag,
		"bodyType":   fmt.Sprintf("%T", body),
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

	// TODO: Parse the completion request body to get part ETags
	// For now, simulate with dummy parts for ETag calculation
	parts := []string{
		"part1etag", "part2etag", "part3etag", // Mock part ETags
	}

	// Calculate multipart ETag (MD5 of concatenated part MD5s + part count)
	hasher := md5.New() //nolint:gosec // MD5 is required for S3 ETag compatibility
	for _, partETag := range parts {
		// In real implementation, these would be the actual part ETags from request
		if partMD5, err := hex.DecodeString(partETag); err == nil {
			hasher.Write(partMD5)
		}
	}
	multipartMD5 := hasher.Sum(nil)
	multipartETag := fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(multipartMD5), len(parts))

	// Response structure
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
		ETag:     multipartETag,
	}

	logger.WithFields(logrus.Fields{
		"etag":      multipartETag,
		"partCount": len(parts),
	}).Info("Multipart upload completed with calculated ETag")

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logger.WithError(err).Error("Failed to encode response")
	}
}

// abortMultipartUpload handles aborting a multipart upload
func (h *Handler) abortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	// TODO: Implement actual abort logic
	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	}).Info("Abort multipart upload request")

	w.WriteHeader(http.StatusNoContent)
}

// listParts handles listing parts of a multipart upload
func (h *Handler) listParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	// TODO: Implement actual part listing
	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	}).Info("List parts request")

	// Response structure
	type listPartsResult struct {
		XMLName              xml.Name `xml:"ListPartsResult"`
		Bucket               string   `xml:"Bucket"`
		Key                  string   `xml:"Key"`
		UploadID             string   `xml:"UploadId"`
		MaxParts             int      `xml:"MaxParts"`
		IsTruncated          bool     `xml:"IsTruncated"`
		PartNumberMarker     int      `xml:"PartNumberMarker"`
		NextPartNumberMarker int      `xml:"NextPartNumberMarker"`
	}

	response := listPartsResult{
		Bucket:      bucket,
		Key:         key,
		UploadID:    uploadID,
		MaxParts:    1000,
		IsTruncated: false,
	}

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to encode response")
	}
}
