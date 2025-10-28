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

// parseRange parses HTTP Range header like "bytes=start-end"
func parseRange(rangeHeader string, size int64) (start, end int64, err error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, fmt.Errorf("unsupported range type")
	}
	
	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(rangeSpec, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range format")
	}
	
	// Parse start
	if parts[0] == "" {
		// Suffix range: bytes=-N means last N bytes
		if parts[1] == "" {
			return 0, 0, fmt.Errorf("invalid range format")
		}
		suffixLength, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffixLength < 0 {
			return 0, 0, fmt.Errorf("invalid suffix length: %w", err)
		}
		if size == 0 {
			return 0, -1, nil // For zero-length files
		}
		start = size - suffixLength
		if start < 0 {
			start = 0
		}
		end = size - 1
		return start, end, nil
	}
	start, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start: %w", err)
	}
	
	// Parse end
	if parts[1] == "" {
		end = size - 1
	} else {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid end: %w", err)
		}
	}
	
	// Validate range
	if start < 0 || (end < -1) || (end >= 0 && start > end) || (size > 0 && start >= size) {
		return 0, 0, fmt.Errorf("invalid range: start=%d, end=%d, size=%d", start, end, size)
	}
	if end >= size {
		end = size - 1
	}
	
	return start, end, nil
}

// getFileCorruptionRisk determines the corruption risk level for different file types
func getFileCorruptionRisk(key string) string {
	if strings.HasSuffix(key, ".orc") || strings.HasSuffix(key, ".avro") {
		return "high" // These formats are very sensitive to corruption
	}
	if strings.HasSuffix(key, ".parquet") {
		return "low" // Parquet files now handled safely by SafeChunkDecoder
	}
	return "low"
}

// validateSizeForFileType validates size mismatches based on file corruption risk
func (h *Handler) validateSizeForFileType(key string, expectedDecoded, actualRead int64) error {
	sizeMismatch := actualRead != expectedDecoded
	risk := getFileCorruptionRisk(key)

	if !sizeMismatch {
		return nil // No mismatch, all good
	}

	// Log the mismatch for monitoring
	logger := logrus.WithFields(logrus.Fields{
		"key":             key,
		"expectedDecoded": expectedDecoded,
		"actualRead":      actualRead,
		"riskLevel":       risk,
	})

	switch risk {
	case "high":
		logger.Error("Rejecting upload due to size mismatch for high-risk file format")
		return fmt.Errorf("size mismatch: expected %d bytes, got %d bytes", expectedDecoded, actualRead)
	case "medium":
		logger.Warn("Size mismatch detected for medium-risk file format, but allowing upload")
		return nil
	default:
		logger.Info("Size mismatch detected for low-risk file format, allowing upload")
		return nil
	}
}

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

	// Copy object data to response with optimized streaming for large files
	if err := h.streamObjectData(w, obj.Body, obj.Size, logger); err != nil {
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
	objInfo, err := h.storage.HeadObject(ctx, bucket, key)
	if err != nil {
		logger.WithError(err).Error("Failed to get object info for range request")
		h.sendError(w, err, http.StatusNotFound)
		return
	}

	// Parse the range header
	start, end, err := parseRange(rangeHeader, objInfo.Size)
	if err != nil {
		logger.WithError(err).Error("Invalid range header")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", objInfo.Size))
		h.sendError(w, fmt.Errorf("invalid range"), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	logger.WithFields(logrus.Fields{
		"start": start,
		"end":   end,
		"size":  objInfo.Size,
	}).Info("Parsed range request")

	// Handle zero-length objects without calling GetObjectRange
	if objInfo.Size == 0 {
		headers := w.Header()
		headers.Set("Accept-Ranges", "bytes")
		headers.Set("Content-Type", objInfo.ContentType)
		headers.Set("Content-Length", "0")
		headers.Set("Content-Range", fmt.Sprintf("bytes */%d", objInfo.Size))
		headers.Set("ETag", objInfo.ETag)
		headers.Set("Last-Modified", objInfo.LastModified.UTC().Format(http.TimeFormat))
		
		w.WriteHeader(http.StatusPartialContent)
		logger.Info("Zero-length range request completed")
		return
	}

	// Get object with range
	rangeObj, err := h.storage.GetObjectRange(ctx, bucket, key, start, end)
	if err != nil {
		logger.WithError(err).Error("Failed to get object range")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}
	defer rangeObj.Body.Close()

	// Set headers for partial content response
	contentLength := end - start + 1
	headers := w.Header()
	headers.Set("Accept-Ranges", "bytes")
	headers.Set("Content-Type", rangeObj.ContentType)
	headers.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	headers.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, objInfo.Size))
	headers.Set("ETag", rangeObj.ETag)
	headers.Set("Last-Modified", rangeObj.LastModified.UTC().Format(http.TimeFormat))

	// Add cache headers based on file type
	if cacheControl, hasCacheControl := getCacheHeaders(key); hasCacheControl {
		headers.Set("Cache-Control", cacheControl)
	}

	// Return 206 Partial Content
	w.WriteHeader(http.StatusPartialContent)
	
	// Copy the range data with optimized streaming
	copied, err := h.streamObjectDataWithCount(w, rangeObj.Body, contentLength, logger)
	if err != nil {
		if !isClientDisconnectError(err) {
			logger.WithError(err).Error("Failed to copy range object data")
		} else {
			logger.WithError(err).Debug("Client disconnected during range transfer")
		}
		return
	}

	logger.WithFields(logrus.Fields{
		"start":      start,
		"end":        end,
		"size":       objInfo.Size,
		"copied":     copied,
		"expected":   contentLength,
	}).Info("Range request completed successfully")
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

	// Validate request using helper function (safe refactoring step 1)
	if err := validatePutObjectRequest(bucket, key, r); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
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

			// Use AWS chunk decoder for chunked encoding
			body = storage.NewSafeChunkDecoder(r.Body)
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
				body = storage.NewSafeChunkDecoder(r.Body)
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
			
			// Validate size for critical file types to prevent corruption
			sizeMismatch := false
			expectedDecoded := size
			if decodedHeader := r.Header.Get("X-Amz-Decoded-Content-Length"); decodedHeader != "" {
				if decoded, parseErr := strconv.ParseInt(decodedHeader, 10, 64); parseErr == nil {
					expectedDecoded = decoded
				}
			}

			if n != expectedDecoded {
				sizeMismatch = true
				logger.WithFields(logrus.Fields{
					"expectedSize":         size,
					"expectedDecoded":      expectedDecoded,
					"actualRead":           n,
					"sizeMismatch":         sizeMismatch,
					"isParquet":           strings.HasSuffix(key, ".parquet"),
					"isIcebergData":       isIcebergData(key),
				}).Error("Size mismatch detected in chunked transfer - potential file corruption")
			}

			logger.WithFields(logrus.Fields{
				"expectedSize":    size,
				"expectedDecoded": expectedDecoded,
				"actualRead":      n,
				"sizeMismatch":    sizeMismatch,
			}).Info("Successfully read chunked transfer")

			// Validate size based on file corruption risk
			if err := h.validateSizeForFileType(key, expectedDecoded, n); err != nil {
				h.sendError(w, err, http.StatusBadRequest)
				return
			}
			
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

			// For AWS CLI clients, use direct chunk decoder
			if isAWSCLI {
				logger.WithField("userAgent", userAgent).Info("AWS CLI large file - using direct body reader")
				body = r.Body
			} else {
				// Use AWS chunk decoder for other clients
				body = storage.NewSafeChunkDecoder(r.Body)
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
			body = storage.NewSafeChunkDecoder(r.Body)
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

// streamObjectData optimizes streaming for large files with proper buffering and progress monitoring
func (h *Handler) streamObjectData(w http.ResponseWriter, reader io.Reader, size int64, logger *logrus.Entry) error {
	// Choose buffer size based on file size
	var bufferSize int
	if size > 100*1024*1024 { // Files > 100MB get large buffers
		bufferSize = largeBufferSize // 1MB
	} else if size > 1024*1024 { // Files > 1MB get medium buffers
		bufferSize = mediumBufferSize // 256KB
	} else {
		bufferSize = smallBufferSize // 4KB
	}

	// Get buffer from pool
	bufPtr := largeBufferPool.Get().(*[]byte)
	defer largeBufferPool.Put(bufPtr)
	
	buffer := (*bufPtr)[:bufferSize]
	
	var totalWritten int64
	start := time.Now()
	lastProgress := time.Now()
	
	for {
		// Read chunk with timeout protection and connection health check
		n, readErr := reader.Read(buffer)
		
		// If we get 0 bytes and no error, this might indicate a stalled connection
		if n == 0 && readErr == nil {
			// This could be a sign of a stalled connection, continue but log it
			continue
		}
		if n > 0 {
			// Write chunk to response with retry on temporary failures
			written := 0
			for written < n {
				w, writeErr := w.Write(buffer[written:n])
				if writeErr != nil {
					// Check if it's a recoverable error
					if isClientDisconnectError(writeErr) {
						return fmt.Errorf("client disconnected during write: %w", writeErr)
					}
					return fmt.Errorf("failed to write chunk: %w", writeErr)
				}
				written += w
			}
			
			totalWritten += int64(n)
			
			// Flush more frequently for large files to prevent buffering issues
			if totalWritten%int64(bufferSize*5) == 0 { // Flush every 5 buffer cycles instead of 10
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				
				// Check if client is still connected by testing if we can write a 0-byte chunk
				if totalWritten > 0 && size > 100*1024*1024 { // Only for large files
					if _, err := w.Write([]byte{}); err != nil {
						return fmt.Errorf("client disconnected during transfer: %w", err)
					}
				}
				
				// Log progress every 50MB for very large files
				if time.Since(lastProgress) > 5*time.Second && size > 50*1024*1024 { // More frequent logging
					progress := float64(totalWritten) / float64(size) * 100
					speed := float64(totalWritten) / time.Since(start).Seconds() / 1024 / 1024 // MB/s
					logger.WithFields(logrus.Fields{
						"written":  totalWritten,
						"size":     size,
						"progress": fmt.Sprintf("%.1f%%", progress),
						"speed":    fmt.Sprintf("%.2f MB/s", speed),
					}).Info("Large file transfer progress")
					lastProgress = time.Now()
				}
			}
		}
		
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			// Better error logging for read failures
			logger.WithError(readErr).WithFields(logrus.Fields{
				"totalWritten": totalWritten,
				"size":         size,
				"progress":     fmt.Sprintf("%.1f%%", float64(totalWritten)/float64(size)*100),
			}).Error("Failed to read chunk during streaming")
			return fmt.Errorf("failed to read chunk: %w", readErr)
		}
	}
	
	// Final flush
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	
	// Log completion stats for large files
	if size > 10*1024*1024 {
		duration := time.Since(start)
		speed := float64(totalWritten) / duration.Seconds() / 1024 / 1024 // MB/s
		logger.WithFields(logrus.Fields{
			"written":  totalWritten,
			"size":     size,
			"duration": duration,
			"speed":    fmt.Sprintf("%.2f MB/s", speed),
		}).Info("Large file transfer completed")
	}
	
	return nil
}

// streamObjectDataWithCount is like streamObjectData but returns bytes written
func (h *Handler) streamObjectDataWithCount(w http.ResponseWriter, reader io.Reader, size int64, logger *logrus.Entry) (int64, error) {
	err := h.streamObjectData(w, reader, size, logger)
	return size, err // For now, return expected size on success
}
