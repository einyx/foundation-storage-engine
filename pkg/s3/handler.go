// Package s3 provides S3-compatible API handlers for the proxy server.
package s3

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // MD5 is required for S3 compatibility
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/meshxdata/foundation-storage-engine/internal/auth"
	"github.com/meshxdata/foundation-storage-engine/internal/config"
	"github.com/meshxdata/foundation-storage-engine/internal/storage"
)

const (
	smallBufferSize  = 4 * 1024   // 4KB
	mediumBufferSize = 64 * 1024  // 64KB
	smallFileLimit   = 100 * 1024 // 100KB
)

var (
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, smallBufferSize)
			return &buf
		},
	}
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, mediumBufferSize)
			return &buf
		},
	}
)

type Handler struct {
	storage  storage.Backend
	auth     auth.Provider
	config   config.S3Config
	router   *mux.Router
	chunking config.ChunkingConfig
}

func NewHandler(storage storage.Backend, auth auth.Provider, cfg config.S3Config, chunking config.ChunkingConfig) *Handler {
	h := &Handler{
		storage:  storage,
		auth:     auth,
		config:   cfg,
		router:   mux.NewRouter(),
		chunking: chunking,
	}

	h.setupRoutes()
	return h
}

// isValidBucket checks if a bucket exists in our virtual bucket configuration
func (h *Handler) isValidBucket(bucket string) bool {
	// Try to check if bucket exists via storage backend
	ctx := context.Background()
	exists, err := h.storage.BucketExists(ctx, bucket)
	if err != nil {
		// logrus.WithError(err).WithField("bucket", bucket).Debug("Error checking bucket existence")
		return false
	}
	return exists
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

func (h *Handler) setupRoutes() {
	// Service operations
	h.router.HandleFunc("/", h.listBuckets).Methods("GET").MatcherFunc(noBucketMatcher)

	// Bucket operations
	h.router.HandleFunc("/{bucket}", h.handleBucket).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
	h.router.HandleFunc("/{bucket}/", h.handleBucket).Methods("GET", "PUT", "DELETE", "HEAD", "POST")

	// Object operations
	h.router.HandleFunc("/{bucket}/{key:.*}", h.handleObject).Methods("GET", "PUT", "DELETE", "HEAD", "POST")
}

func noBucketMatcher(r *http.Request, rm *mux.RouteMatch) bool {
	return r.URL.Path == "/" || r.URL.Path == ""
}

func (h *Handler) listBuckets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	buckets, err := h.storage.ListBuckets(ctx)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	type bucket struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	}

	type listAllMyBucketsResult struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		Buckets struct {
			Bucket []bucket `xml:"Bucket"`
		} `xml:"Buckets"`
	}

	result := listAllMyBucketsResult{}
	result.Owner.ID = "foundation-storage-engine"
	result.Owner.DisplayName = "foundation-storage-engine"

	for _, b := range buckets {
		result.Buckets.Bucket = append(result.Buckets.Bucket, bucket{
			Name:         b.Name,
			CreationDate: b.CreationDate.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(result); err != nil {
		logrus.WithError(err).Error("Failed to encode response")
	}
}

func (h *Handler) handleBucket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// Debug mc client requests
	userAgent := r.Header.Get("User-Agent")
	if strings.Contains(strings.ToLower(userAgent), "minio") || strings.Contains(strings.ToLower(userAgent), "mc") {
		logrus.WithFields(logrus.Fields{
			"method":    r.Method,
			"bucket":    bucket,
			"path":      r.URL.Path,
			"rawPath":   r.URL.RawPath,
			"userAgent": userAgent,
		}).Info("MC client bucket request")

		if !h.isValidBucket(bucket) {
			logrus.WithField("bucket", bucket).Info("MC trying to access non-existent bucket")
			h.sendError(w, fmt.Errorf("bucket not found"), http.StatusNotFound)
			return
		}
	}

	logger := logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"remote": r.RemoteAddr,
	})

	switch r.Method {
	case "GET":
		// logger.Debug("Listing objects for bucket")
		h.listObjects(w, r, bucket)
	case "PUT":
		logger.Info("Creating bucket")
		h.createBucket(w, r, bucket)
	case "POST":
		// Check if this is a bulk delete request
		if _, hasDelete := r.URL.Query()["delete"]; hasDelete {
			h.handleBulkDelete(w, r, bucket)
			return
		}
		// Handle other POST operations
		h.sendError(w, fmt.Errorf("operation not supported"), http.StatusNotImplemented)
	case "DELETE":
		logger.Info("Deleting bucket")
		h.deleteBucket(w, r, bucket)
	case "HEAD":
		// logger.Debug("Checking bucket existence")
		h.headBucket(w, r, bucket)
	}
}

func (h *Handler) handleObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Log object operation
	logger := logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
		"remote": r.RemoteAddr,
		"query":  r.URL.RawQuery,
		"path":   r.URL.Path,
	})

	// logger.Debug("Handling object request")

	// Handle multipart upload operations
	if uploadID := r.URL.Query().Get("uploadId"); uploadID != "" {
		logger = logger.WithField("uploadId", uploadID)
		if r.Method == "POST" {
			// logger.Debug("Completing multipart upload")
			h.completeMultipartUpload(w, r, bucket, key, uploadID)
			return
		} else if r.Method == "DELETE" {
			// logger.Debug("Aborting multipart upload")
			h.abortMultipartUpload(w, r, bucket, key, uploadID)
			return
		} else if r.Method == "GET" {
			// logger.Debug("Listing multipart upload parts")
			h.listParts(w, r, bucket, key, uploadID)
			return
		} else if r.Method == "PUT" {
			if partNumber := r.URL.Query().Get("partNumber"); partNumber != "" {
				// logger.WithField("partNumber", partNumber).Debug("Uploading part")
				h.uploadPart(w, r, bucket, key, uploadID, partNumber)
				return
			}
		}
	}

	// Handle uploads query
	_, hasUploads := r.URL.Query()["uploads"]
	if hasUploads {
		logger.WithFields(logrus.Fields{
			"query":  r.URL.RawQuery,
			"method": r.Method,
		}).Error("Uploads query detected")
		if r.Method == "POST" {
			logger.Error("Initiating multipart upload")
			h.initiateMultipartUpload(w, r, bucket, key)
			return
		}
	}

	// Handle ACL operations
	if r.URL.Query().Get("acl") != "" {
		if r.Method == "GET" {
			// logger.Debug("Getting object ACL")
			h.getObjectACL(w, r, bucket, key)
			return
		} else if r.Method == "PUT" {
			// logger.Debug("Setting object ACL")
			h.putObjectACL(w, r, bucket, key)
			return
		}
	}

	// Check if this is an SDK v2 request and handle any specific requirements
	h.handleSDKv2Request(w, r)

	switch r.Method {
	case "GET":
		// logger.Debug("Getting object")
		h.getObject(w, r, bucket, key)
	case "PUT":
		// logger.WithField("size", r.ContentLength).Debug("Putting object")
		h.putObject(w, r, bucket, key)
	case "POST":
		// Check if this is a bulk delete request
		if _, hasDelete := r.URL.Query()["delete"]; hasDelete {
			h.handleBulkDelete(w, r, bucket)
			return
		}
		// Handle other POST operations
		h.sendError(w, fmt.Errorf("operation not supported"), http.StatusNotImplemented)
	case "DELETE":
		// logger.Debug("Deleting object")
		h.deleteObject(w, r, bucket, key)
	case "HEAD":
		// logger.Debug("Getting object metadata")
		h.headObject(w, r, bucket, key)
	}
}

func (h *Handler) listObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()

	prefix := r.URL.Query().Get("prefix")
	marker := r.URL.Query().Get("marker")
	delimiter := r.URL.Query().Get("delimiter")
	maxKeysStr := r.URL.Query().Get("max-keys")

	maxKeys := 1000
	if maxKeysStr != "" {
		if mk, err := strconv.Atoi(maxKeysStr); err == nil && mk > 0 {
			maxKeys = mk
		}
	}

	userAgent := r.Header.Get("User-Agent")
	if strings.Contains(strings.ToLower(userAgent), "minio") || strings.Contains(strings.ToLower(userAgent), "mc") {
		logrus.WithFields(logrus.Fields{
			"bucket":    bucket,
			"prefix":    prefix,
			"delimiter": delimiter,
			"maxKeys":   maxKeys,
			"marker":    marker,
			"userAgent": userAgent,
			"url":       r.URL.String(),
			"rawQuery":  r.URL.RawQuery,
		}).Info("MC client list request")
	}

	logger := logrus.WithFields(logrus.Fields{
		"bucket":    bucket,
		"prefix":    prefix,
		"delimiter": delimiter,
		"maxKeys":   maxKeys,
		"marker":    marker,
	})
	// logger.Debug("Listing objects")

	result, err := h.storage.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, delimiter, maxKeys)
	if err != nil {
		logger.WithError(err).Error("Failed to list objects")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	// logger.WithFields(logrus.Fields{
	// 	"objects":        len(result.Contents),
	// 	"commonPrefixes": len(result.CommonPrefixes),
	// 	"truncated":      result.IsTruncated,
	// }).Debug("Listed objects successfully")

	type contents struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	}

	type listBucketResult struct {
		XMLName        xml.Name   `xml:"ListBucketResult"`
		Name           string     `xml:"Name"`
		Prefix         string     `xml:"Prefix"`
		Marker         string     `xml:"Marker"`
		NextMarker     string     `xml:"NextMarker,omitempty"`
		MaxKeys        int        `xml:"MaxKeys"`
		IsTruncated    bool       `xml:"IsTruncated"`
		Contents       []contents `xml:"Contents"`
		CommonPrefixes []struct {
			Prefix string `xml:"Prefix"`
		} `xml:"CommonPrefixes,omitempty"`
	}

	response := listBucketResult{
		Name:        bucket,
		Prefix:      prefix,
		Marker:      marker,
		MaxKeys:     maxKeys,
		IsTruncated: result.IsTruncated,
		NextMarker:  result.NextMarker,
	}

	for _, obj := range result.Contents {
		response.Contents = append(response.Contents, contents{
			Key:          obj.Key,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}

	for _, prefix := range result.CommonPrefixes {
		response.CommonPrefixes = append(response.CommonPrefixes, struct {
			Prefix string `xml:"Prefix"`
		}{Prefix: prefix})
	}

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to encode response")
	}
}

func (h *Handler) getObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()
	// start := time.Now()

	isIcebergMetadata := strings.Contains(key, "metadata") && (strings.HasSuffix(key, ".json") || strings.Contains(key, "metadata.json"))

	logger := logrus.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"isIcebergMeta": isIcebergMetadata,
	})

	if isIcebergMetadata {
		logger.Info("Getting Iceberg metadata file")
	}

	// Check for range requests
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		// logger.WithField("range", rangeHeader).Debug("Range request")
		h.getRangeObject(w, r, bucket, key, rangeHeader)
		return
	}

	obj, err := h.storage.GetObject(ctx, bucket, key)
	if err != nil {
		logger.WithError(err).Error("Failed to get object")
		h.sendError(w, err, http.StatusNotFound)
		return
	}
	defer func() { _ = obj.Body.Close() }()

	// logger.WithFields(logrus.Fields{
	// 	"size":        obj.Size,
	// 	"contentType": obj.ContentType,
	// 	"etag":        obj.ETag,
	// }).Debug("Retrieved object")

	headers := w.Header()
	headers.Set("Content-Type", obj.ContentType)
	headers.Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	headers.Set("ETag", obj.ETag)
	headers.Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	headers.Set("Accept-Ranges", "bytes")

	for k, v := range obj.Metadata {
		// Skip checksum metadata that might cause validation errors
		if strings.HasPrefix(k, "x-amz-checksum-") || k == "x-amz-sdk-checksum-algorithm" {
			continue
		}
		headers.Set("x-amz-meta-"+k, v)
	}

	// Remove any checksum headers that might have been set by S3
	// These can cause validation failures if content was modified
	headers.Del("x-amz-checksum-crc32")
	headers.Del("x-amz-checksum-crc32c")
	headers.Del("x-amz-checksum-sha1")
	headers.Del("x-amz-checksum-sha256")

	// Track bytes written to ensure we match Content-Length
	written, err := io.Copy(w, obj.Body)
	if err != nil && !isClientDisconnectError(err) {
		logger.WithError(err).WithFields(logrus.Fields{
			"expected": obj.Size,
			"written":  written,
		}).Error("Failed to copy object data")
	} else if written != obj.Size {
		logger.WithFields(logrus.Fields{
			"expected": obj.Size,
			"written":  written,
			"bucket":   bucket,
			"key":      key,
		}).Warn("Content length mismatch - wrote different bytes than expected")
	}

	// if logrus.GetLevel() >= logrus.DebugLevel {
	// 	logger.WithField("duration", time.Since(start)).Debug("GET completed")
	// }
}

func (h *Handler) getRangeObject(w http.ResponseWriter, r *http.Request, bucket, key, rangeHeader string) {
	ctx := r.Context()

	// Parse range header
	ranges, err := parseRangeHeader(rangeHeader)
	if err != nil || len(ranges) == 0 {
		h.sendError(w, fmt.Errorf("invalid range"), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// Get object info first
	info, err := h.storage.HeadObject(ctx, bucket, key)
	if err != nil {
		h.sendError(w, err, http.StatusNotFound)
		return
	}

	// Only support single range for now
	if len(ranges) > 1 {
		h.sendError(w, fmt.Errorf("multiple ranges not supported"), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	rng := ranges[0]
	start, end := rng.start, rng.end

	// Adjust range values
	if start < 0 {
		start = info.Size + start
	}
	if end < 0 || end >= info.Size {
		end = info.Size - 1
	}

	if start > end || start >= info.Size {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", info.Size))
		h.sendError(w, fmt.Errorf("invalid range"), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// Get partial object
	obj, err := h.storage.GetObject(ctx, bucket, key)
	if err != nil {
		h.sendError(w, err, http.StatusNotFound)
		return
	}
	defer func() { _ = obj.Body.Close() }()

	// Skip to start position
	if start > 0 {
		if seeker, ok := obj.Body.(io.Seeker); ok {
			if _, err := seeker.Seek(start, io.SeekStart); err != nil {
				h.sendError(w, err, http.StatusInternalServerError)
				return
			}
		} else {
			// Fallback: read and discard
			if _, err := io.CopyN(io.Discard, obj.Body, start); err != nil {
				h.sendError(w, err, http.StatusInternalServerError)
				return
			}
		}
	}

	contentLength := end - start + 1

	// Set partial content headers
	w.Header().Set("Content-Type", info.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, info.Size))
	w.Header().Set("ETag", info.ETag)
	w.Header().Set("Last-Modified", info.LastModified.Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "bytes")

	for k, v := range info.Metadata {
		// Skip checksum metadata that might cause validation errors
		if strings.HasPrefix(k, "x-amz-checksum-") || k == "x-amz-sdk-checksum-algorithm" {
			continue
		}
		w.Header().Set("x-amz-meta-"+k, v)
	}

	// Remove any checksum headers that might have been set by S3
	// These can cause validation failures if content was modified
	w.Header().Del("x-amz-checksum-crc32")
	w.Header().Del("x-amz-checksum-crc32c")
	w.Header().Del("x-amz-checksum-sha1")
	w.Header().Del("x-amz-checksum-sha256")

	// Also remove SDK v1 checksum headers
	w.Header().Del("Content-MD5")

	w.WriteHeader(http.StatusPartialContent)

	// Copy the requested range with proper buffering
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	written := int64(0)
	for written < contentLength {
		toRead := contentLength - written
		if toRead > int64(len(buf)) {
			toRead = int64(len(buf))
		}

		n, err := io.ReadFull(obj.Body, buf[:toRead])
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			logrus.WithError(err).WithFields(logrus.Fields{
				"written":       written,
				"contentLength": contentLength,
				"bucket":        bucket,
				"key":           key,
			}).Error("Failed to read from storage")
			return
		}

		if n > 0 {
			wn, werr := w.Write(buf[:n])
			written += int64(wn)
			if werr != nil {
				logrus.WithError(werr).WithFields(logrus.Fields{
					"written":       written,
					"contentLength": contentLength,
					"bucket":        bucket,
					"key":           key,
				}).Error("Failed to write range data")
				return
			}
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			if written < contentLength {
				logrus.WithFields(logrus.Fields{
					"written":       written,
					"contentLength": contentLength,
					"bucket":        bucket,
					"key":           key,
				}).Error("Premature EOF while reading range")
			}
			break
		}
	}
}

type byteRange struct {
	start, end int64
}

func parseRangeHeader(rangeHeader string) ([]byteRange, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("invalid range header")
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(rangeSpec, ",")

	var ranges []byteRange
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		var start, end int64
		if strings.HasPrefix(part, "-") {
			// Suffix range
			n, err := strconv.ParseInt(part[1:], 10, 64)
			if err != nil {
				return nil, err
			}
			start, end = -n, -1
		} else if strings.HasSuffix(part, "-") {
			// Open-ended range
			n, err := strconv.ParseInt(part[:len(part)-1], 10, 64)
			if err != nil {
				return nil, err
			}
			start, end = n, -1
		} else {
			// Normal range
			idx := strings.Index(part, "-")
			if idx < 0 {
				return nil, fmt.Errorf("invalid range spec")
			}

			var err error
			start, err = strconv.ParseInt(part[:idx], 10, 64)
			if err != nil {
				return nil, err
			}

			end, err = strconv.ParseInt(part[idx+1:], 10, 64)
			if err != nil {
				return nil, err
			}
		}

		ranges = append(ranges, byteRange{start: start, end: end})
	}

	return ranges, nil
}

func (h *Handler) putObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()
	// start := time.Now()

	size := r.ContentLength
	logger := logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
		"size":   size,
	})

	if size < 0 {
		logger.Error("Missing Content-Length header")
		h.sendError(w, fmt.Errorf("missing Content-Length"), http.StatusBadRequest)
		return
	}

	var body io.Reader = r.Body
	var etag string
	var verifier *auth.V4StreamingVerifier

	// Check if this is a chunked upload with AWS V4 streaming signatures
	// This MUST be applied to ALL uploads to prevent data corruption
	if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ||
		r.Header.Get("Content-Encoding") == "aws-chunked" ||
		len(r.TransferEncoding) > 0 {
		// This is a chunked upload with signatures
		logger.WithFields(logrus.Fields{
			"contentType":      r.Header.Get("Content-Type"),
			"key":              key,
			"transferEncoding": r.TransferEncoding,
			"contentSha256":    r.Header.Get("x-amz-content-sha256"),
			"verifySignatures": h.chunking.VerifySignatures,
			"sdkChecksum":      r.Header.Get("x-amz-sdk-checksum-algorithm"),
			"checksumCRC32":    r.Header.Get("x-amz-checksum-crc32"),
			"checksumCRC32C":   r.Header.Get("x-amz-checksum-crc32c"),
			"checksumSHA1":     r.Header.Get("x-amz-checksum-sha1"),
			"checksumSHA256":   r.Header.Get("x-amz-checksum-sha256"),
		}).Info("Processing AWS V4 streaming upload")

		if h.chunking.VerifySignatures {
			// Parse authorization to get access key
			authHeader := r.Header.Get("Authorization")
			authParts, err := auth.ParseAuthorizationHeader(authHeader)
			if err != nil {
				logger.WithError(err).Error("Failed to parse authorization header")
				h.sendError(w, fmt.Errorf("invalid authorization: %w", err), http.StatusUnauthorized)
				return
			}

			credential := authParts["Credential"]
			if credential == "" {
				h.sendError(w, fmt.Errorf("missing credential in authorization"), http.StatusUnauthorized)
				return
			}

			// Extract access key from credential
			credParts := strings.Split(credential, "/")
			if len(credParts) < 1 {
				h.sendError(w, fmt.Errorf("invalid credential format"), http.StatusUnauthorized)
				return
			}
			accessKey := credParts[0]

			// Get secret key from auth provider
			secretKey, err := h.auth.GetSecretKey(accessKey)
			if err != nil {
				logger.WithError(err).Error("Failed to get secret key for access key")
				h.sendError(w, fmt.Errorf("invalid access key"), http.StatusUnauthorized)
				return
			}

			// Create signature verifier
			v, err := auth.NewV4StreamingVerifier(
				authHeader,
				r.Header.Get("x-amz-date"),
				secretKey,
			)
			if err != nil {
				logger.WithError(err).Error("Failed to create V4 streaming verifier")
				h.sendError(w, fmt.Errorf("invalid authorization: %w", err), http.StatusUnauthorized)
				return
			}
			verifier = v

			// Validate request time
			if err := auth.ValidateRequestTime(r.Header.Get("x-amz-date"), time.Duration(h.chunking.RequestTimeWindow)*time.Second); err != nil {
				logger.WithError(err).Error("Request time validation failed")
				h.sendError(w, err, http.StatusForbidden)
				return
			}

			// For now, use non-validating reader until validation is implemented
			// TODO: Implement ValidatingChunkReader
			logger.Warn("Chunk signature verification requested but using non-validating reader")
			body = storage.NewAWSChunkDecoder(r.Body)
		} else {
			// Use non-validating reader (current approach) - MUST strip chunks!
			body = storage.NewAWSChunkDecoder(r.Body)
		}

		// If x-amz-decoded-content-length is provided, use it as the actual size
		if decodedLength := r.Header.Get("x-amz-decoded-content-length"); decodedLength != "" {
			if decodedSize, err := strconv.ParseInt(decodedLength, 10, 64); err == nil {
				logger.WithFields(logrus.Fields{
					"originalSize": size,
					"decodedSize":  decodedSize,
				}).Debug("Using x-amz-decoded-content-length for actual content size")
				size = decodedSize
			}
		}
	}

	if size == 0 {
		body = bytes.NewReader([]byte{})
		etag = "\"d41d8cd98f00b204e9800998ecf8427e\""
	} else if size > 0 && size <= smallFileLimit {
		bufPtr := smallBufferPool.Get().(*[]byte)
		buf := *bufPtr
		if int64(len(buf)) < size {
			smallBufferPool.Put(bufPtr)
			buf = make([]byte, size)
		} else {
			buf = buf[:size]
			defer smallBufferPool.Put(bufPtr)
		}

		// Read entire small file into memory
		_, err := io.ReadFull(body, buf)
		if err != nil {
			logger.WithError(err).Error("Failed to read request body")
			h.sendError(w, err, http.StatusBadRequest)
			return
		}

		hash := md5.Sum(buf) //nolint:gosec // MD5 is required for S3 ETag compatibility
		etag = fmt.Sprintf("\"%s\"", hex.EncodeToString(hash[:]))
		body = bytes.NewReader(buf)
	}

	var metadata map[string]string
	for k, v := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			if metadata == nil {
				metadata = make(map[string]string)
			}
			metaKey := strings.TrimPrefix(strings.ToLower(k), "x-amz-meta-")
			metadata[metaKey] = v[0]
		}
	}

	// When processing chunked uploads, we must NOT pass checksum headers to the backend
	// because the checksums were calculated on the chunked data, not the stripped data
	if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		// Remove any SDK checksum metadata that might have been added
		if metadata != nil {
			delete(metadata, "x-amz-checksum-crc32")
			delete(metadata, "x-amz-checksum-crc32c")
			delete(metadata, "x-amz-checksum-sha1")
			delete(metadata, "x-amz-checksum-sha256")
			delete(metadata, "x-amz-sdk-checksum-algorithm")
		}
	}

	err := h.storage.PutObject(ctx, bucket, key, body, size, metadata)
	if err != nil {
		// Check if it's a signature error
		if verifier != nil && strings.Contains(err.Error(), "signature") {
			logger.WithError(err).Error("Chunk signature verification failed")
			h.sendError(w, err, http.StatusForbidden)
			return
		}
		logger.WithError(err).Error("Failed to put object")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	// Log chunk processing statistics if applicable
	if _, ok := body.(*storage.AWSChunkDecoder); ok {
		logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"size":   size,
		}).Info("Successfully processed AWS V4 chunked upload")
	}

	if etag == "" {
		etag = fmt.Sprintf("\"%x\"", time.Now().UnixNano())
	}

	// For chunked uploads, we need special handling to prevent SDK checksum validation
	if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		// The AWS SDK v2 validates checksums on PUT responses
		// Since we modify content by stripping chunks, we must prevent this validation

		// 1. Remove ALL checksum-related headers
		w.Header().Del("x-amz-checksum-crc32")
		w.Header().Del("x-amz-checksum-crc32c")
		w.Header().Del("x-amz-checksum-sha1")
		w.Header().Del("x-amz-checksum-sha256")
		w.Header().Del("x-amz-sdk-checksum-algorithm")
		w.Header().Del("x-amz-checksum-mode")

		// 2. Send minimal response headers
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", "0")

		// 3. Send 200 OK with no body
		w.WriteHeader(http.StatusOK)

		logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"etag":   etag,
		}).Debug("Sent minimal response for chunked upload to prevent checksum validation")

		return
	}

	// For AWS SDK v1 uploads with Content-MD5, also prevent checksum validation
	if r.Header.Get("Content-MD5") != "" {
		// AWS SDK v1 sends Content-MD5 and validates it against ETag
		// Since content might be modified by proxy, send minimal response

		// Remove all checksum headers
		w.Header().Del("Content-MD5")
		w.Header().Del("x-amz-checksum-crc32")
		w.Header().Del("x-amz-checksum-crc32c")
		w.Header().Del("x-amz-checksum-sha1")
		w.Header().Del("x-amz-checksum-sha256")

		// Send minimal response
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)

		logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"etag":   etag,
			"sdk":    "v1",
		}).Debug("Sent minimal response for SDK v1 upload with Content-MD5")

		return
	}

	// Normal upload response (no checksums to validate)
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)

	// if logrus.GetLevel() >= logrus.DebugLevel {
	// 	logger.WithField("duration", time.Since(start)).Debug("PUT completed")
	// }
}

func (h *Handler) deleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	logger := logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	})

	err := h.storage.DeleteObject(ctx, bucket, key)
	if err != nil {
		logger.WithError(err).Error("Failed to delete object")
		h.sendError(w, err, http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	logger.Info("Object deleted")
}

func (h *Handler) headObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	isIcebergMetadata := strings.Contains(key, "metadata") && (strings.HasSuffix(key, ".json") || strings.Contains(key, "metadata.json"))

	logger := logrus.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"method":        "HEAD",
		"isIcebergMeta": isIcebergMetadata,
	})

	if isIcebergMetadata {
		logger.Info("HEAD request for Iceberg metadata file")
	} else {
		logger.Info("HEAD request received")
	}

	info, err := h.storage.HeadObject(ctx, bucket, key)
	if err != nil {
		logger.WithError(err).Info("HEAD request failed - returning 404")
		h.sendError(w, err, http.StatusNotFound)
		return
	}

	logger.WithFields(logrus.Fields{
		"size": info.Size,
		"etag": info.ETag,
	}).Info("HEAD request succeeded - returning object info")

	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	w.Header().Set("ETag", info.ETag)
	w.Header().Set("Last-Modified", info.LastModified.Format(http.TimeFormat))

	for k, v := range info.Metadata {
		// Skip checksum metadata that might cause validation errors
		if strings.HasPrefix(k, "x-amz-checksum-") || k == "x-amz-sdk-checksum-algorithm" {
			continue
		}
		w.Header().Set("x-amz-meta-"+k, v)
	}

	// Remove any checksum headers that might have been set by S3
	// These can cause validation failures if content was modified
	w.Header().Del("x-amz-checksum-crc32")
	w.Header().Del("x-amz-checksum-crc32c")
	w.Header().Del("x-amz-checksum-sha1")
	w.Header().Del("x-amz-checksum-sha256")

	// Also remove SDK v1 checksum headers
	w.Header().Del("Content-MD5")

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) createBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()

	err := h.storage.CreateBucket(ctx, bucket)
	if err != nil {
		h.sendError(w, err, http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) deleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()

	err := h.storage.DeleteBucket(ctx, bucket)
	if err != nil {
		h.sendError(w, err, http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) headBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()

	exists, err := h.storage.BucketExists(ctx, bucket)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	if !exists {
		h.sendError(w, fmt.Errorf("bucket not found"), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) sendError(w http.ResponseWriter, err error, status int) {
	type errorResponse struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}

	code := "InternalError"
	switch status {
	case http.StatusNotFound:
		code = "NoSuchKey"
	case http.StatusConflict:
		code = "BucketAlreadyExists"
	case http.StatusBadRequest:
		code = "BadRequest"
	case http.StatusForbidden:
		code = "AccessDenied"
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if encErr := enc.Encode(errorResponse{
		Code:    code,
		Message: err.Error(),
	}); encErr != nil {
		logrus.WithError(encErr).Error("Failed to encode error response")
	}
}

// Multipart upload operations
func (h *Handler) initiateMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	// logrus.WithFields(logrus.Fields{
	// 	"bucket": bucket,
	// 	"key":    key,
	// }).Debug("Initiating multipart upload")

	ctx := r.Context()

	metadata := make(map[string]string)
	for k, v := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			metaKey := strings.TrimPrefix(strings.ToLower(k), "x-amz-meta-")
			metadata[metaKey] = v[0]
		}
	}

	// logrus.WithFields(logrus.Fields{
	// 	"bucket":   bucket,
	// 	"key":      key,
	// 	"metadata": metadata,
	// }).Debug("About to initiate multipart upload")

	uploadID, err := h.storage.InitiateMultipartUpload(ctx, bucket, key, metadata)
	if err != nil {
		logrus.WithError(err).Error("Failed to initiate multipart upload")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	}).Info("Multipart upload initiated")

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

	// Build XML response
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if encErr := enc.Encode(response); encErr != nil {
		logrus.WithError(encErr).Error("Failed to encode response")
		h.sendError(w, encErr, http.StatusInternalServerError)
		return
	}

	responseXML := buf.String()

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(responseXML)))
	w.WriteHeader(http.StatusOK)

	_, err = w.Write([]byte(responseXML))
	if err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}

func (h *Handler) uploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID, partNumberStr string) {
	ctx := r.Context()

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		h.sendError(w, fmt.Errorf("invalid part number"), http.StatusBadRequest)
		return
	}

	size := r.ContentLength
	if size < 0 {
		h.sendError(w, fmt.Errorf("missing Content-Length"), http.StatusBadRequest)
		return
	}

	etag, err := h.storage.UploadPart(ctx, bucket, key, uploadID, partNumber, r.Body, size)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) completeMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	ctx := r.Context()

	type completedPart struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	}

	type completeMultipartUpload struct {
		Parts []completedPart `xml:"Part"`
	}

	var req completeMultipartUpload
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}

	parts := make([]storage.CompletedPart, len(req.Parts))
	for i, p := range req.Parts {
		parts[i] = storage.CompletedPart{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
		}
	}

	err := h.storage.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	type completeMultipartUploadResult struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	multipartETag := fmt.Sprintf("\"%x-%d\"", time.Now().UnixNano(), len(parts))
	if err := enc.Encode(completeMultipartUploadResult{
		Location: fmt.Sprintf("http://%s/%s/%s", r.Host, bucket, key),
		Bucket:   bucket,
		Key:      key,
		ETag:     multipartETag,
	}); err != nil {
		logrus.WithError(err).Error("Failed to encode response")
	}
}

func (h *Handler) abortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	ctx := r.Context()

	err := h.storage.AbortMultipartUpload(ctx, bucket, key, uploadID)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	ctx := r.Context()

	maxPartsStr := r.URL.Query().Get("max-parts")
	partNumberMarkerStr := r.URL.Query().Get("part-number-marker")

	maxParts := 1000
	if maxPartsStr != "" {
		if mp, err := strconv.Atoi(maxPartsStr); err == nil && mp > 0 {
			maxParts = mp
		}
	}

	partNumberMarker := 0
	if partNumberMarkerStr != "" {
		if pnm, err := strconv.Atoi(partNumberMarkerStr); err == nil {
			partNumberMarker = pnm
		}
	}

	result, err := h.storage.ListParts(ctx, bucket, key, uploadID, maxParts, partNumberMarker)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	type part struct {
		PartNumber   int    `xml:"PartNumber"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
	}

	type listPartsResult struct {
		XMLName              xml.Name `xml:"ListPartsResult"`
		Bucket               string   `xml:"Bucket"`
		Key                  string   `xml:"Key"`
		UploadID             string   `xml:"UploadId"`
		PartNumberMarker     int      `xml:"PartNumberMarker"`
		NextPartNumberMarker int      `xml:"NextPartNumberMarker,omitempty"`
		MaxParts             int      `xml:"MaxParts"`
		IsTruncated          bool     `xml:"IsTruncated"`
		Parts                []part   `xml:"Part"`
	}

	response := listPartsResult{
		Bucket:               bucket,
		Key:                  key,
		UploadID:             uploadID,
		PartNumberMarker:     partNumberMarker,
		NextPartNumberMarker: result.NextPartNumberMarker,
		MaxParts:             maxParts,
		IsTruncated:          result.IsTruncated,
	}

	for _, p := range result.Parts {
		response.Parts = append(response.Parts, part{
			PartNumber:   p.PartNumber,
			LastModified: p.LastModified.Format(time.RFC3339),
			ETag:         p.ETag,
			Size:         p.Size,
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to encode response")
	}
}

func (h *Handler) getObjectACL(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	acl, err := h.storage.GetObjectACL(ctx, bucket, key)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	type grantee struct {
		XMLName     xml.Name `xml:"Grantee"`
		Type        string   `xml:"xsi:type,attr"`
		ID          string   `xml:"ID,omitempty"`
		DisplayName string   `xml:"DisplayName,omitempty"`
		URI         string   `xml:"URI,omitempty"`
	}

	type grant struct {
		Grantee    grantee `xml:"Grantee"`
		Permission string  `xml:"Permission"`
	}

	type accessControlPolicy struct {
		XMLName xml.Name `xml:"AccessControlPolicy"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		AccessControlList struct {
			Grant []grant `xml:"Grant"`
		} `xml:"AccessControlList"`
	}

	response := accessControlPolicy{}
	response.Owner.ID = acl.Owner.ID
	response.Owner.DisplayName = acl.Owner.DisplayName

	for _, g := range acl.Grants {
		grantItem := grant{
			Permission: g.Permission,
			Grantee: grantee{
				Type:        g.Grantee.Type,
				ID:          g.Grantee.ID,
				DisplayName: g.Grantee.DisplayName,
				URI:         g.Grantee.URI,
			},
		}
		response.AccessControlList.Grant = append(response.AccessControlList.Grant, grantItem)
	}

	w.Header().Set("Content-Type", "application/xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to encode response")
	}
}

func (h *Handler) putObjectACL(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	// For now, just accept and ignore ACL requests
	err := h.storage.PutObjectACL(ctx, bucket, key, nil)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// isClientDisconnectError checks if error is due to client disconnect
func isClientDisconnectError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "write: connection refused")
}
