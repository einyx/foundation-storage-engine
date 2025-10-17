package s3

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // MD5 is required for S3 compatibility
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/storage"
)

// handleObject handles object-level operations (GET, PUT, DELETE, HEAD, POST)
func (h *Handler) handleObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Validate bucket name and object key
	if err := ValidateBucketName(bucket); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}

	if err := ValidateObjectKey(key); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}

	// Log object operation
	logger := logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
		"remote": r.RemoteAddr,
		"query":  r.URL.RawQuery,
		"path":   r.URL.Path,
	})

	logger.WithFields(logrus.Fields{
		"rawPath": r.URL.Path,
		"bucket":  bucket,
		"key":     key,
	}).Debug("handleObject called")

	// Handle multipart upload operations
	if uploadID := r.URL.Query().Get("uploadId"); uploadID != "" {
		// Validate upload ID
		if err := ValidateUploadID(uploadID); err != nil {
			h.sendError(w, err, http.StatusBadRequest)
			return
		}

		logger = logger.WithField("uploadId", uploadID)
		if r.Method == "POST" {
			h.completeMultipartUpload(w, r, bucket, key, uploadID)
			return
		} else if r.Method == "DELETE" {
			h.abortMultipartUpload(w, r, bucket, key, uploadID)
			return
		} else if r.Method == "GET" {
			h.listParts(w, r, bucket, key, uploadID)
			return
		} else if r.Method == "PUT" {
			if partNumberStr := r.URL.Query().Get("partNumber"); partNumberStr != "" {
				// Validate part number
				if _, err := ValidatePartNumber(partNumberStr); err != nil {
					h.sendError(w, err, http.StatusBadRequest)
					return
				}
				h.uploadPart(w, r, bucket, key, uploadID, partNumberStr)
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
			"bucket": bucket,
			"key":    key,
		}).Info("Uploads query detected - multipart upload request")
		if r.Method == "POST" {
			logger.WithFields(logrus.Fields{
				"table":         extractTableName(key),
				"isIcebergFile": isIcebergMetadata(key) || isIcebergData(key),
			}).Info("Initiating multipart upload")
			h.initiateMultipartUpload(w, r, bucket, key)
			return
		}
	}

	// Handle ACL operations
	if r.URL.Query().Get("acl") != "" {
		if r.Method == "GET" {
			h.getObjectACL(w, r, bucket, key)
			return
		} else if r.Method == "PUT" {
			h.putObjectACL(w, r, bucket, key)
			return
		}
	}

	// Check if this is an SDK v2 request and handle any specific requirements
	h.handleSDKv2Request(w, r)

	// Check if this is actually a list operation disguised as an object request
	if r.Method == "GET" && h.isListOperation(r) {
		// This is a list operation, not an object get - delegate to list logic
		h.listObjects(w, r, bucket)
		return
	}

	switch r.Method {
	case "GET":
		// Check for range requests
		if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
			h.getRangeObject(w, r, bucket, key, rangeHeader)
		} else {
			h.getObject(w, r, bucket, key)
		}
	case "PUT":
		h.putObject(w, r, bucket, key)
	case "DELETE":
		h.deleteObject(w, r, bucket, key)
	case "HEAD":
		h.headObject(w, r, bucket, key)
	default:
		h.sendError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// getObject handles GET requests for objects
func (h *Handler) getObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	// Add panic recovery to prevent backend crashes
	defer func() {
		if rec := recover(); rec != nil {
			logrus.WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
				"panic":  fmt.Sprintf("%v", rec),
				"method": "GET",
			}).Error("Panic recovered in getObject")
			// Try to send error response if possible
			if !isResponseStarted(w) {
				h.sendError(w, fmt.Errorf("internal server error"), http.StatusInternalServerError)
			}
		}
	}()

	// Detect file types for optimization
	icebergMeta := isIcebergMetadata(key)
	avroFile := isAvroFile(key)
	icebergData := isIcebergData(key)

	logger := logrus.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"method":        "GET",
		"isIcebergMeta": icebergMeta,
		"isAvro":        avroFile,
		"isIcebergData": icebergData,
		"fileType":      filepath.Ext(key),
	})

	if icebergMeta {
		logger.WithFields(logrus.Fields{
			"table":         extractTableName(key),
			"isVersionFile": strings.Count(key, "metadata.json") > 1 || strings.Contains(key, "v"),
		}).Info("Getting Iceberg metadata file")
	} else if avroFile {
		logger.Info("Getting Avro data file")
	} else if icebergData {
		logger.WithField("table", extractTableName(key)).Info("Getting Iceberg data file")
	}

	obj, err := h.storage.GetObject(ctx, bucket, key)
	if err != nil {
		logger.WithError(err).Error("Failed to get object")
		h.sendError(w, err, http.StatusNotFound)
		return
	}
	defer func() { _ = obj.Body.Close() }()

	headers := w.Header()
	headers.Set("Content-Type", obj.ContentType)
	headers.Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	headers.Set("ETag", obj.ETag)
	headers.Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	headers.Set("Accept-Ranges", "bytes")

	// Add cache headers based on file type
	if cacheControl, hasCacheControl := getCacheHeaders(key); hasCacheControl {
		headers.Set("Cache-Control", cacheControl)
	}

	// Special handling for Java SDK clients (Trino, Hive, Hadoop)
	userAgent := r.Header.Get("User-Agent")
	if isJavaSDKClient(userAgent) {
		// Force connection close to prevent client hanging
		headers.Set("Connection", "close")
		// Set AWS S3 headers for compatibility
		headers.Set("Server", "AmazonS3")
		headers.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}

	// Copy object data to response
	if _, err := io.Copy(w, obj.Body); err != nil {
		if !isClientDisconnectError(err) {
			logger.WithError(err).Error("Failed to copy object data")
		} else {
			logger.WithError(err).Debug("Client disconnected during object transfer")
		}
	}
}

// getRangeObject handles range requests for objects
func (h *Handler) getRangeObject(w http.ResponseWriter, r *http.Request, bucket, key, rangeHeader string) {
	ctx := r.Context()

	logger := logrus.WithFields(logrus.Fields{
		"bucket":    bucket,
		"key":       key,
		"range":     rangeHeader,
		"method":    "GET",
		"userAgent": r.Header.Get("User-Agent"),
	})

	logger.Info("Processing range request")

	// Get object metadata first to validate range
	_, err := h.storage.HeadObject(ctx, bucket, key)
	if err != nil {
		logger.WithError(err).Error("Failed to get object info for range request")
		h.sendError(w, err, http.StatusNotFound)
		return
	}

	// For now, simple implementation - return full object with proper headers
	// TODO: Implement actual range parsing and partial content serving
	fullObj, err := h.storage.GetObject(ctx, bucket, key)
	if err != nil {
		logger.WithError(err).Error("Failed to get object for range request")
		h.sendError(w, err, http.StatusNotFound)
		return
	}
	defer fullObj.Body.Close()

	headers := w.Header()
	headers.Set("Content-Type", fullObj.ContentType)
	headers.Set("Content-Length", strconv.FormatInt(fullObj.Size, 10))
	headers.Set("ETag", fullObj.ETag)
	headers.Set("Last-Modified", fullObj.LastModified.Format(http.TimeFormat))
	headers.Set("Accept-Ranges", "bytes")

	// Add cache headers based on file type
	if cacheControl, hasCacheControl := getCacheHeaders(key); hasCacheControl {
		headers.Set("Cache-Control", cacheControl)
	}

	// For now, return 200 OK with full content instead of 206 Partial Content
	// This maintains compatibility while we implement proper range support
	w.WriteHeader(http.StatusOK)

	// Copy object data to response
	if _, err := io.Copy(w, fullObj.Body); err != nil {
		if !isClientDisconnectError(err) {
			logger.WithError(err).Error("Failed to copy range object data")
		} else {
			logger.WithError(err).Debug("Client disconnected during range transfer")
		}
	}

	logger.WithField("size", fullObj.Size).Info("Range request completed (full object served)")
}

// putObject handles PUT requests for objects
func (h *Handler) putObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	// Generate request tracking early for panic recovery
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Add panic recovery to prevent backend crashes
	defer func() {
		if rec := recover(); rec != nil {
			logrus.WithFields(logrus.Fields{
				"bucket":    bucket,
				"key":       key,
				"panic":     fmt.Sprintf("%v", rec),
				"requestID": requestID,
			}).Error("Panic recovered in putObject")
			// Try to send error response if possible
			if !isResponseStarted(w) {
				h.sendError(w, fmt.Errorf("internal server error"), http.StatusInternalServerError)
			}
		}
	}()

	// Check if this is a copy operation
	if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
		logrus.WithField("copySource", copySource).Info("Handling CopyObject request")
		h.handleCopyObject(w, r)
		return
	}

	// Detect file types and client types
	icebergMeta := isIcebergMetadata(key)
	icebergManifest := isIcebergManifest(key)
	icebergData := isIcebergData(key)
	userAgent := r.Header.Get("User-Agent")
	isJavaClient := isJavaSDKClient(userAgent)
	isAWSCLI := isAWSCLIClient(userAgent)

	// Initialize ETag variable
	var etag string

	// Calculate content length and detect chunked transfers
	size := r.ContentLength
	transferEncoding := r.Header.Get("Transfer-Encoding")
	contentSha256 := r.Header.Get("x-amz-content-sha256")
	chunkedWithoutSize := isChunkedWithoutSize(size, transferEncoding, contentSha256)

	logger := logrus.WithFields(logrus.Fields{
		"bucket":               bucket,
		"key":                  key,
		"size":                 size,
		"stage":                "start",
		"contentType":          r.Header.Get("Content-Type"),
		"transferEncoding":     transferEncoding,
		"method":               r.Method,
		"requestID":            requestID,
		"isChunkedWithoutSize": chunkedWithoutSize,
		"userAgent":            userAgent,
		"isJavaClient":         isJavaClient,
		"isAWSCLI":             isAWSCLI,
		"contentMD5":           r.Header.Get("Content-MD5"),
		"isIcebergMeta":        icebergMeta,
		"isIcebergData":        icebergData,
		"isSparkUpload":        isJavaClient || strings.Contains(userAgent, "Spark"),
		"checksumAlgorithm":    r.Header.Get("x-amz-sdk-checksum-algorithm"),
	})

	logger.Info("PUT handler started")

	if icebergMeta {
		logger.WithFields(logrus.Fields{
			"table":         extractTableName(key),
			"isVersionFile": strings.Count(key, "metadata.json") > 1 || strings.Contains(key, "v"),
		}).Info("Starting Iceberg metadata upload")
	} else if icebergManifest {
		logger.WithFields(logrus.Fields{
			"table": extractTableName(key),
		}).Info("Starting Iceberg manifest upload")
	} else if icebergData {
		logger.WithFields(logrus.Fields{
			"table": extractTableName(key),
		}).Info("Starting Iceberg data upload")
	}

	// CRITICAL: Ensure request body is closed
	defer r.Body.Close()

	// Handle request body with size-based optimization strategy
	var body io.Reader = r.Body

	// Handle empty files first
	if size == 0 {
		body = bytes.NewReader([]byte{})
		etag = "\"d41d8cd98f00b204e9800998ecf8427e\""
	} else if chunkedWithoutSize {
		// Handle chunked transfers without explicit size
		// For Trino, we should NOT buffer - it causes timeouts
		// Always buffer Iceberg metadata files regardless of client
		// Metadata files are small but critical - they must be written atomically
		if strings.Contains(userAgent, "Trino") && !icebergMeta {
			logger.WithFields(logrus.Fields{
				"key":       key,
				"userAgent": userAgent,
			}).Warn("Trino chunked upload without size - streaming directly to avoid timeout")

			// Use SmartChunkDecoder for Trino but don't buffer
			body = storage.NewSmartChunkDecoder(r.Body)
			size = -1
			etag = `"streaming-upload-etag"`
		} else {
			// For other clients, or for Iceberg metadata, buffer as before
			if icebergMeta {
				logger.Info("Buffering Iceberg metadata file for atomic write")
			} else {
				logger.Info("Buffering chunked upload without explicit size")
			}
			bufferStart := time.Now()

			var buf bytes.Buffer
			written, err := io.Copy(&buf, body)
			bufferDuration := time.Since(bufferStart)

			if err != nil {
				logger.WithError(err).WithField("duration", bufferDuration).Error("Failed to buffer chunked request body")
				h.sendError(w, fmt.Errorf("failed to buffer request body: %w", err), http.StatusBadRequest)
				return
			}

			logger.WithFields(logrus.Fields{
				"bufferedSize": written,
				"duration":     bufferDuration,
			}).Info("Successfully buffered chunked upload")

			data := buf.Bytes()
			// Don't calculate our own ETag for chunked uploads - it won't match client expectations
			// The client calculated MD5 on the original chunked data, not the decoded data
			etag = `"chunked-upload-etag"`
			body = bytes.NewReader(data)
			size = written
		}
	} else if size > 0 && size <= smallFileLimit {
		// Small file optimization with buffer pool and MD5 calculation
		actualSize := size

		bufPtr := smallBufferPool.Get().(*[]byte)
		buf := *bufPtr
		if int64(len(buf)) < actualSize {
			smallBufferPool.Put(bufPtr)
			buf = make([]byte, actualSize)
		} else {
			buf = buf[:actualSize]
			defer smallBufferPool.Put(bufPtr)
		}

		// Handle chunked decoding for small files
		isChunkedTransfer := r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ||
			r.Header.Get("Content-Encoding") == "aws-chunked"

		logger.WithFields(logrus.Fields{
			"contentSha256": r.Header.Get("x-amz-content-sha256"),
			"contentEncoding": r.Header.Get("Content-Encoding"), 
			"isChunkedTransfer": isChunkedTransfer,
			"isAWSCLI": isAWSCLI,
		}).Info("Chunked transfer detection")

		if isChunkedTransfer {
			if isAWSCLI {
				logger.WithField("userAgent", userAgent).Info("AWS CLI small file - using direct body reader")
				body = r.Body
			} else {
				body = storage.NewSmartChunkDecoder(r.Body)
				logger.Info("Using smart chunk decoder for small file")
			}
		}

		// Read entire small file into memory
		// For chunked transfers, use io.Copy instead of io.ReadFull to handle size variations
		logger.WithFields(logrus.Fields{
			"isChunkedTransfer": isChunkedTransfer,
			"isAWSCLI": isAWSCLI,
			"useChunkedPath": isChunkedTransfer && !isAWSCLI,
		}).Info("Deciding read strategy")
		
		if isChunkedTransfer && !isAWSCLI {
			logger.Info("Using chunked transfer read strategy")
			
			// For chunked transfers, read up to actualSize but don't require exact match
			limitedReader := io.LimitReader(body, actualSize)
			buffer := bytes.NewBuffer(nil)
			n, err := io.Copy(buffer, limitedReader)
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"expectedSize": actualSize,
					"actualRead":   n,
					"originalSize": size,
					"key":          key,
				}).Error("Failed to read chunked request body")
				h.sendError(w, err, http.StatusBadRequest)
				return
			}
			
			// Copy read data to buffer and adjust size
			copy(buf, buffer.Bytes())
			buf = buf[:n]
			actualSize = n
			
			logger.WithFields(logrus.Fields{
				"expectedSize": size,
				"actualRead": n,
			}).Info("Successfully read chunked transfer")
			
		} else {
			logger.Info("Using standard ReadFull strategy")
			// For non-chunked transfers, use ReadFull for exact size validation
			_, err := io.ReadFull(body, buf)
			if err != nil {
				logger.WithError(err).WithFields(logrus.Fields{
					"expectedSize": actualSize,
					"originalSize": size,
					"key":          key,
				}).Error("Failed to read request body")
				h.sendError(w, err, http.StatusBadRequest)
				return
			}
		}

		// Calculate MD5 hash for ETag
		hash := md5.Sum(buf) //nolint:gosec // MD5 is required for S3 ETag compatibility
		etag = fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))
		body = bytes.NewReader(buf)

		logger.WithFields(logrus.Fields{
			"actualSize":     actualSize,
			"etag":           etag,
			"bufferPoolUsed": true,
		}).Info("Small file processed with buffer pool and MD5 ETag")

	} else {
		// Large file handling - use streaming with smart decoder
		if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ||
			r.Header.Get("Content-Encoding") == "aws-chunked" {

			// For AWS CLI clients, bypass SmartChunkDecoder to avoid hanging issues
			if isAWSCLI {
				logger.WithField("userAgent", userAgent).Info("AWS CLI large file - using direct body reader")
				body = r.Body
			} else {
				// Use SmartChunkDecoder for other clients that might have chunked encoding issues
				body = storage.NewSmartChunkDecoder(r.Body)
				logger.Info("Using smart chunk decoder for large file upload")
			}

			// If x-amz-decoded-content-length is provided, use it as the actual size
			if decodedLen := r.Header.Get("x-amz-decoded-content-length"); decodedLen != "" {
				if parsedSize, err := strconv.ParseInt(decodedLen, 10, 64); err == nil {
					size = parsedSize
					logger.WithField("decodedSize", size).Info("Using decoded content length")
				}
			}
		} else {
			// For now, use non-validating reader until validation is implemented
			if r.Header.Get("x-amz-sdk-checksum-algorithm") != "" {
				logger.Warn("Chunk signature verification requested but using non-validating reader")
			}
			body = storage.NewSmartChunkDecoder(r.Body)
		}

		// For large files, use a generic ETag (storage backend should calculate if needed)
		etag = `"large-file-etag"`

		logger.WithFields(logrus.Fields{
			"size":            size,
			"streamingUpload": true,
		}).Info("Large file upload - using streaming mode")
	}

	// Validate size constraints
	if size < 0 && !chunkedWithoutSize {
		logger.Error("Missing Content-Length header")
		h.sendError(w, fmt.Errorf("missing Content-Length"), http.StatusBadRequest)
		return
	}

	// Prepare metadata
	metadata := make(map[string]string)
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		metadata["Content-Type"] = contentType
	}

	// Log chunk processing statistics if applicable
	logger.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"size":     size,
		"isAvro":   strings.HasSuffix(key, ".avro"),
		"bodyType": fmt.Sprintf("%T", body),
	}).Info("Processing upload request")

	// Store object
	err := h.storage.PutObject(ctx, bucket, key, body, size, metadata)
	if err != nil {
		logger.WithError(err).Error("Failed to put object")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	logger.WithFields(logrus.Fields{
		"stage":     "before_response",
		"userAgent": userAgent,
		"isAzure":   strings.Contains(strings.ToLower(userAgent), "azure"),
		"etag":      etag,
		"requestID": requestID,
		"bucket":    bucket,
		"key":       key,
	}).Info("Upload completed successfully, about to send response")

	// Special handling for Trino and Hive clients (which use Java AWS SDK)
	if isJavaSDKClient(userAgent) {

		// Remove all checksum headers that might cause validation issues
		w.Header().Del("x-amz-checksum-crc32")
		w.Header().Del("x-amz-checksum-crc32c")
		w.Header().Del("x-amz-checksum-sha1")
		w.Header().Del("x-amz-checksum-sha256")
		w.Header().Del("x-amz-sdk-checksum-algorithm")
		w.Header().Del("Content-MD5")

		// Set minimal AWS S3 PUT response headers (exactly like real S3)
		w.Header().Set("ETag", etag)
		w.Header().Set("x-amz-request-id", requestID)
		w.Header().Set("x-amz-id-2", fmt.Sprintf("S3/%s", requestID))
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))

		// CRITICAL: Set Content-Length to 0 for empty body
		w.Header().Set("Content-Length", "0")

		// Force connection close to prevent client hanging
		w.Header().Set("Connection", "close")

		// Send 200 OK
		w.WriteHeader(http.StatusOK)

		// Force flush immediately
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		logger.WithFields(logrus.Fields{
			"bucket":    bucket,
			"key":       key,
			"etag":      etag,
			"requestID": requestID,
			"client":    "java_sdk",
			"userAgent": userAgent,
			"stage":     "handler_complete",
		}).Info("Sent minimal S3 PUT response for Java SDK client")

		return
	}

	// Special handling for Azure clients
	if strings.Contains(strings.ToLower(userAgent), "azure") {
		// Azure SDK clients need specific response handling
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", "0")
		w.Header().Set("x-amz-request-id", requestID)
		w.Header().Set("x-amz-id-2", fmt.Sprintf("Azure/%s", requestID))
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))

		// Write status and flush immediately
		w.WriteHeader(http.StatusOK)

		// Force immediate flush for Azure clients
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		logger.WithFields(logrus.Fields{
			"bucket":    bucket,
			"key":       key,
			"client":    "azure_sdk",
			"stage":     "handler_complete",
			"etag":      etag,
			"requestID": requestID,
		}).Info("Sent Azure-compatible PUT response")

		return
	}

	// Standard response for other clients
	w.Header().Set("ETag", etag)
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("Content-Length", "0") // Explicitly set Content-Length for all responses
	w.WriteHeader(http.StatusOK)

	// Final log to confirm handler completed
	logger.WithFields(logrus.Fields{
		"stage":           "handler_complete",
		"etag":            etag,
		"requestID":       requestID,
		"bucket":          bucket,
		"key":             key,
		"responseHeaders": w.Header(),
	}).Info("PUT object handler completed successfully")
}

// deleteObject handles DELETE requests for objects
func (h *Handler) deleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	// Add panic recovery to prevent backend crashes
	defer func() {
		if rec := recover(); rec != nil {
			logrus.WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
				"panic":  fmt.Sprintf("%v", rec),
				"method": "DELETE",
			}).Error("Panic recovered in deleteObject")
			// Try to send error response if possible
			if !isResponseStarted(w) {
				h.sendError(w, fmt.Errorf("internal server error"), http.StatusInternalServerError)
			}
		}
	}()

	err := h.storage.DeleteObject(ctx, bucket, key)
	if err != nil {
		logrus.WithError(err).Error("Failed to delete object")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// headObject handles HEAD requests for objects
func (h *Handler) headObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	// Add panic recovery to prevent backend crashes
	defer func() {
		if rec := recover(); rec != nil {
			logrus.WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
				"panic":  fmt.Sprintf("%v", rec),
				"method": "HEAD",
			}).Error("Panic recovered in headObject")
			// Try to send error response if possible
			if !isResponseStarted(w) {
				h.sendError(w, fmt.Errorf("internal server error"), http.StatusInternalServerError)
			}
		}
	}()

	// Detect file types for optimization
	icebergMeta := isIcebergMetadata(key)
	userAgent := r.Header.Get("User-Agent")

	logger := logrus.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"method":        "HEAD",
		"isIcebergMeta": icebergMeta,
		"userAgent":     userAgent,
	})

	if icebergMeta {
		logger.WithField("table", extractTableName(key)).Info("HEAD request for Iceberg metadata file")
	} else {
		logger.Debug("HEAD request received")
	}

	start := time.Now()
	obj, err := h.storage.HeadObject(ctx, bucket, key)
	if err != nil {
		logger.WithError(err).Error("Failed to get object info")
		h.sendError(w, err, http.StatusNotFound)
		return
	}
	duration := time.Since(start)

	headers := w.Header()
	headers.Set("Content-Type", obj.ContentType)
	headers.Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	headers.Set("ETag", obj.ETag)
	headers.Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	headers.Set("Accept-Ranges", "bytes")

	// Add cache headers based on file type
	if cacheControl, hasCacheControl := getCacheHeaders(key); hasCacheControl {
		headers.Set("Cache-Control", cacheControl)
	}

	// Remove any checksum headers that might cause issues
	w.Header().Del("x-amz-checksum-crc32")
	w.Header().Del("x-amz-checksum-crc32c")
	w.Header().Del("x-amz-checksum-sha1")
	w.Header().Del("x-amz-checksum-sha256")
	w.Header().Del("Content-MD5")

	// Special handling for Java SDK clients (Trino, Hive, Hadoop)
	if isJavaSDKClient(userAgent) {
		// Force connection close to prevent client hanging
		w.Header().Set("Connection", "close")

		// Set AWS S3 headers for compatibility
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))

		logger.WithFields(logrus.Fields{
			"userAgent": userAgent,
			"bucket":    bucket,
			"key":       key,
			"duration":  duration,
		}).Info("Applied Java SDK optimizations for HEAD request")
	}

	// For Trino/Iceberg, ensure proper response headers
	if strings.Contains(userAgent, "Trino") || icebergMeta {
		w.Header().Set("Connection", "close") // Force connection close
		logger.WithFields(logrus.Fields{
			"table":       extractTableName(key),
			"icebergMeta": icebergMeta,
		}).Debug("Setting Connection: close for Trino/Iceberg client")
	}

	w.WriteHeader(http.StatusOK)

	// Force immediate flush for HEAD responses to prevent client hangs
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	logger.WithFields(logrus.Fields{
		"size":     obj.Size,
		"duration": duration,
		"etag":     obj.ETag,
	}).Debug("HEAD request completed")
}

// ScanContentResult holds virus scan results
type ScanContentResult struct {
	Body   io.Reader
	Result interface{}
}

// scanContent scans content for viruses using VirusTotal
func (h *Handler) scanContent(ctx context.Context, body io.Reader, key string, size int64, logger *logrus.Entry, w http.ResponseWriter) (*ScanContentResult, error) {
	// For now, just return clean result
	// TODO: Implement actual VirusTotal scanning
	return &ScanContentResult{
		Body:   body,
		Result: nil, // No scan result available without real scanner
	}, nil
}
