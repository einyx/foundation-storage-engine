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
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/auth"
	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/storage"
	"github.com/einyx/foundation-storage-engine/internal/virustotal"
)

const (
	smallBufferSize  = 4 * 1024     // 4KB
	mediumBufferSize = 256 * 1024   // 256KB - increased for better large file handling
	largeBufferSize  = 1024 * 1024  // 1MB - for very large files
	smallFileLimit   = 100 * 1024   // 100KB
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
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, largeBufferSize)
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
	scanner  *virustotal.Scanner
}

func NewHandler(storage storage.Backend, auth auth.Provider, cfg config.S3Config, chunking config.ChunkingConfig) *Handler {
	h := &Handler{
		storage:  storage,
		auth:     auth,
		config:   cfg,
		router:   mux.NewRouter(),
		chunking: chunking,
		scanner:  nil, // Scanner is optional, set with SetScanner
	}

	h.setupRoutes()
	return h
}

// SetScanner sets the VirusTotal scanner for the handler
func (h *Handler) SetScanner(scanner *virustotal.Scanner) {
	h.scanner = scanner
}

// isListOperation checks if a GET request should be treated as a list operation
// based on query parameters that indicate a bucket listing rather than object retrieval
func (h *Handler) isListOperation(r *http.Request) bool {
	query := r.URL.Query()
	
	// Check for list-type query parameters that indicate this is a list operation
	listParams := []string{
		"list-type",     // S3 v2 list API
		"delimiter",     // Directory-style listing
		"prefix",        // Prefix filtering
		"marker",        // S3 v1 list continuation
		"max-keys",      // Limit number of results
		"continuation-token", // S3 v2 list continuation
	}
	
	for _, param := range listParams {
		if query.Get(param) != "" {
			return true
		}
	}
	
	return false
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
	// Log every request to debug hanging
	start := time.Now()
	
	// Wrap response writer to capture status
	wrapped := &responseWriter{
		ResponseWriter: w,
		statusCode:    200,
		written:       false,
	}
	
	logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
		"query":  r.URL.RawQuery,
		"userAgent": r.Header.Get("User-Agent"),
	}).Info("Incoming S3 request")
	
	h.router.ServeHTTP(wrapped, r)
	
	// Log response
	duration := time.Since(start)
	logrus.WithFields(logrus.Fields{
		"method":   r.Method,
		"path":     r.URL.Path,
		"status":   wrapped.statusCode,
		"duration": duration,
	}).Info("S3 request completed")
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (w *responseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// isResponseStarted checks if response has already been written
func isResponseStarted(w http.ResponseWriter) bool {
	if rw, ok := w.(*responseWriter); ok {
		return rw.written
	}
	return false
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
	
	// Debug logging for download issues
	logger.WithFields(logrus.Fields{
		"rawPath": r.URL.Path,
		"bucket": bucket,
		"key": key,
	}).Debug("handleObject called")

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

	// Check if this is actually a list operation disguised as an object request
	if r.Method == "GET" && h.isListOperation(r) {
		// This is a list operation, not an object get - delegate to list logic
		h.listObjects(w, r, bucket)
		return
	}

	switch r.Method {
	case "GET":
		// logger.Debug("Getting object")
		h.getObject(w, r, bucket, key)
	case "PUT":
		// Check if this is a copy operation
		if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
			logger.WithField("copySource", copySource).Info("Handling CopyObject request")
			h.handleCopyObject(w, r)
			return
		}
		// logger.WithField("size", r.ContentLength).Debug("Putting object")
		h.putObject(w, r, bucket, key)
	case "POST":
		// Check if this is a bulk delete request
		if _, hasDelete := r.URL.Query()["delete"]; hasDelete {
			h.handleBulkDelete(w, r, bucket)
			return
		}
		// Check if this is a restore request
		if _, hasRestore := r.URL.Query()["restore"]; hasRestore {
			// Get version ID from query parameter
			versionID := r.URL.Query().Get("versionId")
			
			// Call restore method
			err := h.storage.RestoreObject(r.Context(), bucket, key, versionID)
			if err != nil {
				logger.WithError(err).Error("Failed to restore object")
				h.sendError(w, err, http.StatusInternalServerError)
				return
			}
			
			// Return success response
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<RestoreObjectResult>
  <Restored>true</Restored>
</RestoreObjectResult>`)
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

	// Check if this is a V2 list request
	listType := r.URL.Query().Get("list-type")
	isV2 := listType == "2"
	
	prefix := r.URL.Query().Get("prefix")
	marker := r.URL.Query().Get("marker")
	delimiter := r.URL.Query().Get("delimiter")
	maxKeysStr := r.URL.Query().Get("max-keys")
	includeDeleted := r.URL.Query().Get("deleted") == "true"
	
	// For V2 requests, use continuation-token instead of marker
	if isV2 {
		continuationToken := r.URL.Query().Get("continuation-token")
		if continuationToken != "" {
			marker = continuationToken
		}
	}

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
		"includeDeleted": includeDeleted,
	})
	// logger.Debug("Listing objects")

	// Handle soft delete listing
	var result *storage.ListObjectsResult
	var err error
	
	if includeDeleted {
		// List deleted objects (no delimiter support for deleted objects)
		result, err = h.storage.ListDeletedObjects(ctx, bucket, prefix, marker, maxKeys)
	} else {
		// Normal listing
		result, err = h.storage.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, delimiter, maxKeys)
	}
	if err != nil {
		logger.WithError(err).Error("Failed to list objects")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}
	
	// Special handling for deleted objects listing
	if includeDeleted {
		// Create a custom response format that includes metadata
		type metadataItem struct {
			DeletedTime string `xml:"DeletedTime,omitempty"`
			VersionID   string `xml:"VersionID,omitempty"`
			IsDeleted   string `xml:"IsDeleted,omitempty"`
		}
		
		type deletedContents struct {
			Key          string       `xml:"Key"`
			LastModified string       `xml:"LastModified"`
			ETag         string       `xml:"ETag"`
			Size         int64        `xml:"Size"`
			StorageClass string       `xml:"StorageClass"`
			Metadata     metadataItem `xml:"Metadata"`
		}
		
		type deletedListResult struct {
			XMLName        xml.Name          `xml:"ListBucketResult"`
			Name           string            `xml:"Name"`
			Prefix         string            `xml:"Prefix"`
			Marker         string            `xml:"Marker"`
			NextMarker     string            `xml:"NextMarker,omitempty"`
			MaxKeys        int               `xml:"MaxKeys"`
			IsTruncated    bool              `xml:"IsTruncated"`
			Contents       []deletedContents `xml:"Contents"`
		}
		
		response := deletedListResult{
			Name:        bucket,
			Prefix:      prefix,
			Marker:      marker,
			MaxKeys:     maxKeys,
			IsTruncated: result.IsTruncated,
			NextMarker:  result.NextMarker,
		}
		
		for _, obj := range result.Contents {
			metadata := metadataItem{}
			if obj.Metadata != nil {
				metadata.DeletedTime = obj.Metadata["DeletedTime"]
				metadata.VersionID = obj.Metadata["VersionID"]
				metadata.IsDeleted = obj.Metadata["IsDeleted"]
			}
			
			response.Contents = append(response.Contents, deletedContents{
				Key:          obj.Key,
				LastModified: obj.LastModified.Format(time.RFC3339),
				ETag:         obj.ETag,
				Size:         obj.Size,
				StorageClass: "STANDARD",
				Metadata:     metadata,
			})
		}
		
		logrus.WithFields(logrus.Fields{
			"deletedCount": len(response.Contents),
			"bucket": bucket,
		}).Info("Returning deleted objects XML response")
		
		// Log first few items for debugging
		if len(response.Contents) > 0 {
			logrus.WithFields(logrus.Fields{
				"firstKey": response.Contents[0].Key,
				"firstSize": response.Contents[0].Size,
			}).Debug("First deleted object details")
		}
		
		w.Header().Set("Content-Type", "application/xml")
		enc := xml.NewEncoder(w)
		enc.Indent("", "  ")
		if err := enc.Encode(response); err != nil {
			logrus.WithError(err).Error("Failed to encode deleted objects response")
		}
		return
	}
	
	// Debug logging for pagination issues
	if isV2 && result.IsTruncated {
		logger.WithFields(logrus.Fields{
			"marker": marker,
			"nextMarker": result.NextMarker,
			"resultCount": len(result.Contents),
			"isTruncated": result.IsTruncated,
		}).Debug("V2 list pagination state")
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
	
	type listBucketResultV2 struct {
		XMLName               xml.Name   `xml:"ListBucketResult"`
		Name                  string     `xml:"Name"`
		Prefix                string     `xml:"Prefix"`
		MaxKeys               int        `xml:"MaxKeys"`
		IsTruncated           bool       `xml:"IsTruncated"`
		Contents              []contents `xml:"Contents"`
		CommonPrefixes        []struct {
			Prefix string `xml:"Prefix"`
		} `xml:"CommonPrefixes,omitempty"`
		ContinuationToken     string `xml:"ContinuationToken,omitempty"`
		NextContinuationToken string `xml:"NextContinuationToken,omitempty"`
		KeyCount              int    `xml:"KeyCount"`
	}

	// Safety check: Never return IsTruncated=true with empty Contents
	// This prevents XML parsing errors in clients
	if len(result.Contents) == 0 && result.IsTruncated {
		logrus.WithFields(logrus.Fields{
			"bucket":       bucket,
			"prefix":       prefix,
			"isTruncated":  result.IsTruncated,
			"nextMarker":   result.NextMarker,
		}).Warn("Correcting IsTruncated=true with empty Contents")
		result.IsTruncated = false
		result.NextMarker = ""
	}

	// Handle V2 format if requested
	if isV2 {
		// Safety check: Prevent infinite loops by detecting when NextMarker equals current marker
		// Handle URL encoding differences
		decodedMarker, _ := url.QueryUnescape(marker)
		if result.IsTruncated && result.NextMarker != "" && 
			(result.NextMarker == marker || result.NextMarker == decodedMarker) {
			logrus.WithFields(logrus.Fields{
				"bucket":       bucket,
				"prefix":       prefix,
				"marker":       marker,
				"decodedMarker": decodedMarker,
				"nextMarker":   result.NextMarker,
			}).Warn("Detected same continuation token, breaking potential infinite loop")
			result.IsTruncated = false
			result.NextMarker = ""
		}
		
		responseV2 := listBucketResultV2{
			Name:        bucket,
			Prefix:      prefix,
			MaxKeys:     maxKeys,
			IsTruncated: result.IsTruncated,
			KeyCount:    len(result.Contents),
		}
		
		// Use continuation tokens for V2
		if marker != "" {
			responseV2.ContinuationToken = marker
		}
		if result.NextMarker != "" {
			responseV2.NextContinuationToken = result.NextMarker
		}

		for _, obj := range result.Contents {
			responseV2.Contents = append(responseV2.Contents, contents{
				Key:          obj.Key,
				LastModified: obj.LastModified.Format(time.RFC3339),
				ETag:         obj.ETag,
				Size:         obj.Size,
				StorageClass: "STANDARD",
			})
		}

		for _, prefix := range result.CommonPrefixes {
			responseV2.CommonPrefixes = append(responseV2.CommonPrefixes, struct {
				Prefix string `xml:"Prefix"`
			}{Prefix: prefix})
		}

		w.Header().Set("Content-Type", "application/xml")
		enc := xml.NewEncoder(w)
		enc.Indent("", "  ")
		if err := enc.Encode(responseV2); err != nil {
			logrus.WithError(err).Error("Failed to encode response")
		}
		return
	}
	
	// V1 format (default)
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
	isAvroFile := strings.HasSuffix(key, ".avro")

	logger := logrus.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"isIcebergMeta": isIcebergMetadata,
		"isAvro":        isAvroFile,
		"fileType":      filepath.Ext(key),
	})

	if isIcebergMetadata {
		logger.Info("Getting Iceberg metadata file")
	} else if isAvroFile {
		logger.Info("Getting Avro data file")
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
	
	// Add cache headers to reduce repeated requests
	// Iceberg metadata files change frequently, so use short cache
	if isIcebergMetadata {
		headers.Set("Cache-Control", "private, max-age=5")
	} else {
		// Data files are immutable once written
		headers.Set("Cache-Control", "private, max-age=3600")
	}

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
	} else {
		// Log successful retrieval
		logger.WithFields(logrus.Fields{
			"size": written,
			"completed": true,
		}).Info("Successfully retrieved object")
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

// extractTableName tries to extract the table name from an Iceberg path
func extractTableName(key string) string {
	parts := strings.Split(key, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "_") && i > 0 {
			// This looks like an Iceberg table name
			return part
		}
	}
	return ""
}

func (h *Handler) putObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	// handlerStart := time.Now()
	
	// Generate request ID for tracking
	requestID := r.Header.Get("X-Amz-Request-Id")
	if requestID == "" {
		requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	
	// Log timing checkpoint
	logrus.WithFields(logrus.Fields{
		"stage": "handler_entry",
		"bucket": bucket,
		"key": key,
		"requestID": requestID,
		"contentLength": r.ContentLength,
		"remoteAddr": r.RemoteAddr,
	}).Info("PUT handler started")
	
	// CRITICAL: Ensure request body is closed
	defer r.Body.Close()
	
	// Add panic recovery to prevent backend crashes
	defer func() {
		if r := recover(); r != nil {
			logrus.WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
				"panic":  fmt.Sprintf("%v", r),
				"requestID": requestID,
			}).Error("Panic recovered in putObject")
			// Try to send error response if possible
			if !isResponseStarted(w) {
				h.sendError(w, fmt.Errorf("internal server error"), http.StatusInternalServerError)
			}
		}
	}()
	
	ctx := r.Context()
	// start := time.Now()

	size := r.ContentLength
	
	// AWS CLI with chunked transfer doesn't send Content-Length, 
	// but sends X-Amz-Decoded-Content-Length instead
	if size < 0 && r.Header.Get("X-Amz-Decoded-Content-Length") != "" {
		decodedLength, err := strconv.ParseInt(r.Header.Get("X-Amz-Decoded-Content-Length"), 10, 64)
		if err == nil {
			size = decodedLength
		}
	}
	
	// For chunked transfers without explicit size, we'll have to buffer the data
	isChunkedWithoutSize := size < 0 && (r.Header.Get("Transfer-Encoding") == "chunked" || 
		r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	
	// Detect SDK version and client type
	userAgent := r.Header.Get("User-Agent")
	isSDKv1 := strings.Contains(userAgent, "aws-sdk-java/1") || 
		strings.Contains(userAgent, "aws-cli/1") ||
		r.Header.Get("Content-MD5") != ""
	
	// Detect Java-based clients (including Spark)
	isJavaClient := strings.Contains(userAgent, "aws-sdk-java") ||
		strings.Contains(userAgent, "Java/") ||
		strings.Contains(userAgent, "Apache-Spark") ||
		strings.Contains(userAgent, "Hadoop")
	
	logger := logrus.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
		"size":   size,
		"contentLengthHeader": r.Header.Get("Content-Length"),
		"decodedContentLength": r.Header.Get("X-Amz-Decoded-Content-Length"),
		"transferEncoding": r.Header.Get("Transfer-Encoding"),
		"method": r.Method,
		"requestID": requestID,
		"isChunkedWithoutSize": isChunkedWithoutSize,
		"userAgent": userAgent,
		"isSDKv1": isSDKv1,
		"isJavaClient": isJavaClient,
		"contentMD5": r.Header.Get("Content-MD5"),
	})

	if size < 0 && !isChunkedWithoutSize {
		logger.Error("Missing Content-Length header")
		h.sendError(w, fmt.Errorf("missing Content-Length"), http.StatusBadRequest)
		return
	}

	// Special logging for Iceberg-related files
	if strings.HasSuffix(key, ".avro") {
		logger.WithFields(logrus.Fields{
			"stage": "start",
			"contentType": r.Header.Get("Content-Type"),
			"contentEncoding": r.Header.Get("Content-Encoding"),
			"transferEncoding": r.TransferEncoding,
		}).Info("Starting Avro file upload")
	} else if strings.HasSuffix(key, ".parquet") {
		logger.WithFields(logrus.Fields{
			"stage": "start",
			"contentType": r.Header.Get("Content-Type"),
			"isIcebergData": strings.Contains(key, "/data/"),
			"table": extractTableName(key),
			"isSparkUpload": isJavaClient || strings.Contains(userAgent, "Spark"),
			"checksumAlgorithm": r.Header.Get("x-amz-sdk-checksum-algorithm"),
			"contentMD5": r.Header.Get("Content-MD5"),
		}).Info("Starting Parquet file upload")
	} else if strings.Contains(key, "metadata.json") {
		logger.WithFields(logrus.Fields{
			"stage": "start",
			"isIcebergMetadata": true,
			"table": extractTableName(key),
			"isVersionFile": strings.Count(key, "metadata.json") > 1 || strings.Contains(key, "v"),
		}).Info("Starting Iceberg metadata upload")
	} else if strings.Contains(key, "manifest") || strings.Contains(key, "snap-") {
		logger.WithFields(logrus.Fields{
			"stage": "start",
			"isIcebergManifest": true,
			"table": extractTableName(key),
		}).Info("Starting Iceberg manifest upload")
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
			body = storage.NewSmartChunkDecoder(r.Body)
		} else {
			// Use smart decoder that can handle both chunked and raw data
			body = storage.NewSmartChunkDecoder(r.Body)
		}

		// If x-amz-decoded-content-length is provided, use it as the actual size
		if decodedLength := r.Header.Get("x-amz-decoded-content-length"); decodedLength != "" {
			if decodedSize, err := strconv.ParseInt(decodedLength, 10, 64); err == nil {
				logger.WithFields(logrus.Fields{
					"originalSize": size,
					"decodedSize":  decodedSize,
				}).Debug("Using x-amz-decoded-content-length for actual content size")
				size = decodedSize
				
				// Update logger with corrected size
				logger = logrus.WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    key,
					"size":   size,
					"contentLengthHeader": r.Header.Get("Content-Length"),
					"decodedContentLength": r.Header.Get("X-Amz-Decoded-Content-Length"),
					"transferEncoding": r.Header.Get("Transfer-Encoding"),
					"method": r.Method,
					"requestID": requestID,
					"isChunkedWithoutSize": isChunkedWithoutSize,
					"userAgent": userAgent,
					"isSDKv1": isSDKv1,
					"isJavaClient": isJavaClient,
					"contentMD5": r.Header.Get("Content-MD5"),
				})
			}
		}
	}

	if size == 0 {
		body = bytes.NewReader([]byte{})
		etag = "\"d41d8cd98f00b204e9800998ecf8427e\""
	} else if isChunkedWithoutSize {
		// For Trino, we should NOT buffer - it causes timeouts
		// Always buffer Iceberg metadata files regardless of client  
		// Metadata files are small but critical - they must be written atomically
		isIcebergMetadata := strings.Contains(key, "metadata") && strings.HasSuffix(key, ".json")
		
		if strings.Contains(userAgent, "Trino") && !isIcebergMetadata {
			logger.WithFields(logrus.Fields{
				"key": key,
				"userAgent": userAgent,
			}).Warn("Trino chunked upload without size - streaming directly to avoid timeout")
			// Leave body as-is (SmartChunkDecoder) and size as -1
			// The storage backend will handle it
			size = -1
		} else {
			// For other clients, or for Iceberg metadata, buffer as before
			if isIcebergMetadata {
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
				h.sendError(w, err, http.StatusBadRequest)
				return
			}
			size = written
			logger.WithFields(logrus.Fields{
				"bufferedSize": size,
				"duration": bufferDuration,
				"bytesPerSec": float64(size) / bufferDuration.Seconds(),
				"isIcebergMetadata": isIcebergMetadata,
			}).Info("Buffered chunked upload successfully")
			
			data := buf.Bytes()
			// Don't calculate our own ETag for chunked uploads - it won't match client expectations
			// The client calculated MD5 on the original chunked data, not the decoded data
			// hash := md5.Sum(data) //nolint:gosec // MD5 is required for S3 ETag compatibility
			// etag = fmt.Sprintf("\"%s\"", hex.EncodeToString(hash[:]))
			body = bytes.NewReader(data)
		}
	} else if size > 0 && size <= smallFileLimit {
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

		// Read entire small file into memory
		_, err := io.ReadFull(body, buf)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"expectedSize": actualSize,
				"originalSize": size,
				"key": key,
			}).Error("Failed to read request body")
			h.sendError(w, err, http.StatusBadRequest)
			return
		}

		hash := md5.Sum(buf) //nolint:gosec // MD5 is required for S3 ETag compatibility
		etag = fmt.Sprintf("\"%s\"", hex.EncodeToString(hash[:]))
		body = bytes.NewReader(buf)
		
		// Update size to match actual content size  
		oldSize := size
		size = actualSize
		
		// Update logger with corrected size for accurate response logging
		if actualSize != oldSize {
			logger = logrus.WithFields(logrus.Fields{
				"bucket": bucket,
				"key": key,
				"size": actualSize,
				"originalSize": oldSize,
				"contentLengthHeader": r.Header.Get("Content-Length"),
				"decodedContentLength": r.Header.Get("X-Amz-Decoded-Content-Length"),
				"transferEncoding": r.Header.Get("Transfer-Encoding"),
				"method": r.Method,
				"requestID": requestID,
				"isChunkedWithoutSize": isChunkedWithoutSize,
				"userAgent": userAgent,
				"isSDKv1": isSDKv1,
				"isJavaClient": isJavaClient,
				"contentMD5": r.Header.Get("Content-MD5"),
			})
		}
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

	// Scan file with VirusTotal if enabled (only for reasonably sized files)
	var scanResult *virustotal.ScanResult
	if h.scanner != nil && h.scanner.IsEnabled() && size > 0 && size <= 32*1024*1024 {
		// For small files, buffer and scan
		var buf bytes.Buffer
		teeReader := io.TeeReader(body, &buf)
		
		// Scan the file
		result, err := h.scanner.ScanReader(ctx, teeReader, key, size)
		if err != nil {
			logger.WithError(err).Warn("VirusTotal scan failed, continuing with upload")
		} else if result != nil {
			scanResult = result
			logger.WithFields(logrus.Fields{
				"verdict":    scanResult.Verdict,
				"malicious":  scanResult.Malicious,
				"suspicious": scanResult.Suspicious,
				"harmless":   scanResult.Harmless,
				"permalink":  scanResult.Permalink,
			}).Info("VirusTotal scan completed")
			
			// Check if we should block the upload
			if h.scanner.ShouldBlockUpload(scanResult) {
				logger.WithFields(logrus.Fields{
					"threat_level": scanResult.GetThreatLevel(),
					"permalink":    scanResult.Permalink,
				}).Error("Upload blocked due to threat detection")
				
				// Add scan info to response headers
				w.Header().Set("X-VirusTotal-Verdict", scanResult.Verdict)
				w.Header().Set("X-VirusTotal-ThreatLevel", scanResult.GetThreatLevel())
				w.Header().Set("X-VirusTotal-Permalink", scanResult.Permalink)
				
				h.sendError(w, fmt.Errorf("upload blocked: %s", scanResult.GetThreatLevel()), http.StatusForbidden)
				return
			}
			
			// Add scan info to metadata
			if metadata == nil {
				metadata = make(map[string]string)
			}
			metadata["x-virustotal-verdict"] = scanResult.Verdict
			metadata["x-virustotal-scan-date"] = scanResult.ScanDate.Format(time.RFC3339)
			metadata["x-virustotal-permalink"] = scanResult.Permalink
		}
		
		// Use the buffered content for storage
		body = &buf
	}

	// Add debugging for critical file types
	if strings.HasSuffix(key, ".avro") || strings.HasSuffix(key, ".json") {
		logger.WithFields(logrus.Fields{
			"key": key,
			"size": size,
			"hasDecoder": body != r.Body,
			"contentSha256": r.Header.Get("x-amz-content-sha256"),
			"fileType": filepath.Ext(key),
		}).Info("Processing data file upload")
		
		// For chunked files, ensure we track the actual decoded size
		if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
			// Size should already be set to decoded content length
			logger.WithFields(logrus.Fields{
				"decodedSize": size,
				"originalContentLength": r.ContentLength,
			}).Info("Using decoded size for chunked file")
		}
	}
	
	// Add timeout monitoring for Iceberg operations
	putStart := time.Now()
	if strings.Contains(key, "_expectations") || strings.Contains(key, "_validations") {
		logger.Info("Starting PUT for Iceberg expectations/validations table")
	}
	
	// Log before storage operation
	logger.WithField("stage", "before_storage").Debug("About to call storage.PutObject")
	
	err := h.storage.PutObject(ctx, bucket, key, body, size, metadata)
	
	putDuration := time.Since(putStart)
	if putDuration > 5*time.Second {
		logger.WithFields(logrus.Fields{
			"duration": putDuration,
			"key": key,
			"size": size,
		}).Warn("Slow PUT operation detected - storage backend took too long")
	}
	
	if err != nil {
		// Check if it's a signature error
		if verifier != nil && strings.Contains(err.Error(), "signature") {
			logger.WithError(err).Error("Chunk signature verification failed")
			h.sendError(w, err, http.StatusForbidden)
			return
		}
		
		// Special error handling for Avro files
		if strings.HasSuffix(key, ".avro") {
			logger.WithError(err).WithFields(logrus.Fields{
				"stage": "storage_error",
				"decodedSize": size,
			}).Error("Failed to store Avro file")
		}
		
		logger.WithError(err).Error("Failed to put object")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	// Log chunk processing statistics if applicable
	if smartDecoder, ok := body.(*storage.SmartChunkDecoder); ok {
		logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"size":   size,
			"isAvro": strings.HasSuffix(key, ".avro"),
			"decoderType": "SmartChunkDecoder",
			"rawFallback": smartDecoder.IsRawFallback(),
		}).Info("Successfully processed chunked upload")
	} else if _, ok := body.(*storage.AWSChunkDecoder); ok {
		logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"size":   size,
			"isAvro": strings.HasSuffix(key, ".avro"),
			"decoderType": "AWSChunkDecoder",
		}).Info("Successfully processed AWS V4 chunked upload")
	}
	
	// For chunked uploads, ALWAYS generate a multipart-style ETag to prevent client validation errors
	// This is critical because we modify the content by stripping chunk headers
	if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ||
		r.Header.Get("Content-Encoding") == "aws-chunked" ||
		len(r.TransferEncoding) > 0 {
		// Use multipart-style ETag format (hash-partcount) to signal modified content
		// This prevents AWS SDK from trying to validate MD5 checksums
		etag = fmt.Sprintf("\"%x-1\"", time.Now().UnixNano())
		logger.WithFields(logrus.Fields{
			"generatedETag": etag,
			"reason": "chunked upload content modified",
		}).Debug("Generated multipart-style ETag for chunked upload")
	} else if etag == "" {
		// For non-chunked uploads without ETag, generate a simple one
		etag = fmt.Sprintf("\"%x\"", time.Now().UnixNano())
	}
	
	// Log successful completion
	logger.WithFields(logrus.Fields{
		"etag": etag,
		"completed": true,
		"stage": "before_response",
		"userAgent": userAgent,
		"isAzure": strings.Contains(strings.ToLower(userAgent), "azure"),
	}).Info("Upload completed successfully, about to send response")
	
	// Special handling for Trino and Hive clients (which use Java AWS SDK)
	if strings.Contains(strings.ToLower(userAgent), "trino") || 
	   (strings.Contains(strings.ToLower(userAgent), "java") && strings.Contains(userAgent, "app/Trino")) ||
	   strings.Contains(strings.ToLower(userAgent), "hive") ||
	   strings.Contains(strings.ToLower(userAgent), "hadoop") ||
	   strings.Contains(strings.ToLower(userAgent), "s3a") {
		
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
			"bucket": bucket,
			"key": key,
			"etag": etag,
			"requestID": requestID,
			"client": "java_sdk",
			"userAgent": userAgent,
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
			"bucket": bucket,
			"key": key,
			"etag": etag,
			"requestID": requestID,
			"client": "azure",
		}).Info("Sent Azure-optimized response")
		
		return
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
		
		// Add VirusTotal scan info to response headers if available
		if scanResult != nil {
			w.Header().Set("X-VirusTotal-Verdict", scanResult.Verdict)
			w.Header().Set("X-VirusTotal-Permalink", scanResult.Permalink)
			w.Header().Set("X-VirusTotal-ScanDate", scanResult.ScanDate.Format(time.RFC3339))
			w.Header().Set("X-VirusTotal-ThreatLevel", scanResult.GetThreatLevel())
		}

		// 3. Send 200 OK with no body
		w.WriteHeader(http.StatusOK)
		
		// Force flush the response
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"etag":   etag,
			"flushed": true,
		}).Debug("Sent minimal response for chunked upload to prevent checksum validation")

		return
	}

	// For AWS SDK v1 uploads with Content-MD5, also prevent checksum validation
	// Also handle Java clients (including Spark) which may validate checksums
	if r.Header.Get("Content-MD5") != "" || isJavaClient {
		// AWS SDK v1 sends Content-MD5 and validates it against ETag
		// Java clients (Spark) also validate checksums
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
		
		// Add VirusTotal scan info to response headers if available
		if scanResult != nil {
			w.Header().Set("X-VirusTotal-Verdict", scanResult.Verdict)
			w.Header().Set("X-VirusTotal-Permalink", scanResult.Permalink)
			w.Header().Set("X-VirusTotal-ScanDate", scanResult.ScanDate.Format(time.RFC3339))
			w.Header().Set("X-VirusTotal-ThreatLevel", scanResult.GetThreatLevel())
		}
		
		w.WriteHeader(http.StatusOK)
		
		// Force immediate flush for Java clients (including Trino)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"etag":   etag,
			"sdk":    "v1/java",
			"isJavaClient": isJavaClient,
		}).Debug("Sent minimal response for SDK v1/Java upload with checksum validation")

		return
	}

	// Normal upload response (no checksums to validate)
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", "0") // Explicitly set Content-Length for all responses
	
	// Add VirusTotal scan info to response headers if available
	if scanResult != nil {
		w.Header().Set("X-VirusTotal-Verdict", scanResult.Verdict)
		w.Header().Set("X-VirusTotal-Permalink", scanResult.Permalink)
		w.Header().Set("X-VirusTotal-ScanDate", scanResult.ScanDate.Format(time.RFC3339))
		w.Header().Set("X-VirusTotal-ThreatLevel", scanResult.GetThreatLevel())
	}
	
	// SDK v1 might expect specific headers
	if isSDKv1 {
		w.Header().Set("x-amz-id-2", fmt.Sprintf("LriYPLdmOdAiIfgSm/%s", requestID))
		w.Header().Set("x-amz-request-id", requestID)
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		logger.Debug("Adding SDK v1 compatible response headers")
	}
	
	// Write ETag header before status (removing duplicate)
	w.Header().Set("x-amz-version-id", "") // Some clients expect this
	
	// For Trino/Iceberg, ensure proper response headers
	if strings.Contains(userAgent, "Trino") || strings.Contains(key, "metadata.json") {
		w.Header().Set("Connection", "close") // Force connection close
		logger.Debug("Setting Connection: close for Trino client")
	}
	
	// CRITICAL: Write status code
	w.WriteHeader(http.StatusOK)
	
	// CRITICAL: No body for PUT responses per S3 spec
	// Don't write empty byte slice as it can cause issues
	
	// Force flush the response to ensure client receives it immediately
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
		logger.Debug("Flushed response immediately")
	}
	
	// Final log to confirm handler completed
	logger.WithFields(logrus.Fields{
		"stage": "handler_complete",
		"etag": etag,
		"requestID": requestID,
		"bucket": bucket,
		"key": key,
	}).Info("PUT handler completed - response sent and flushed")

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

	start := time.Now()
	info, err := h.storage.HeadObject(ctx, bucket, key)
	duration := time.Since(start)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"duration": duration,
		}).WithError(err).Info("HEAD request failed - returning 404")
		h.sendError(w, err, http.StatusNotFound)
		return
	}

	logger.WithFields(logrus.Fields{
		"size": info.Size,
		"etag": info.ETag,
		"lastModified": info.LastModified,
		"contentType": info.ContentType,
		"duration": duration,
	}).Info("HEAD request succeeded - returning object info")

	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	w.Header().Set("ETag", info.ETag)
	w.Header().Set("Last-Modified", info.LastModified.Format(http.TimeFormat))
	
	// Add cache headers to reduce repeated requests
	// Iceberg metadata files change frequently, so use short cache
	if isIcebergMetadata {
		w.Header().Set("Cache-Control", "private, max-age=5")
	} else {
		// Data files are immutable once written
		w.Header().Set("Cache-Control", "private, max-age=3600")
	}

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

	// Special handling for Java SDK clients (Trino, Hive, Hadoop)
	userAgent := r.Header.Get("User-Agent")
	if strings.Contains(strings.ToLower(userAgent), "trino") || 
	   (strings.Contains(strings.ToLower(userAgent), "java") && strings.Contains(userAgent, "app/Trino")) ||
	   strings.Contains(strings.ToLower(userAgent), "hive") ||
	   strings.Contains(strings.ToLower(userAgent), "hadoop") ||
	   strings.Contains(strings.ToLower(userAgent), "s3a") {
		
		// Force connection close to prevent client hanging
		w.Header().Set("Connection", "close")
		
		// Set AWS S3 headers for compatibility
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		
		logger.WithFields(logrus.Fields{
			"userAgent": userAgent,
			"bucket": bucket,
			"key": key,
		}).Info("Applied Java SDK optimizations for HEAD request")
	}

	w.WriteHeader(http.StatusOK)
	
	// Force immediate flush for HEAD responses to prevent client hangs
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (h *Handler) createBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()
	
	// Check if user is admin
	isAdmin, _ := ctx.Value("is_admin").(bool)
	if !isAdmin {
		logrus.WithFields(logrus.Fields{
			"user_sub": ctx.Value("user_sub"),
			"bucket":   bucket,
			"operation": "CreateBucket",
		}).Warn("Non-admin user attempted to create bucket")
		h.sendError(w, fmt.Errorf("access denied: admin privileges required"), http.StatusForbidden)
		return
	}

	err := h.storage.CreateBucket(ctx, bucket)
	if err != nil {
		h.sendError(w, err, http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) deleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()
	
	// Check if user is admin
	isAdmin, _ := ctx.Value("is_admin").(bool)
	if !isAdmin {
		logrus.WithFields(logrus.Fields{
			"user_sub": ctx.Value("user_sub"),
			"bucket":   bucket,
			"operation": "DeleteBucket",
		}).Warn("Non-admin user attempted to delete bucket")
		h.sendError(w, fmt.Errorf("access denied: admin privileges required"), http.StatusForbidden)
		return
	}

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
		"userAgent": r.Header.Get("User-Agent"),
	}).Info("Multipart upload initiated - TRACKING FOR LOCK ISSUES")

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
	start := time.Now()

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		h.sendError(w, fmt.Errorf("invalid part number"), http.StatusBadRequest)
		return
	}

	size := r.ContentLength
	
	// AWS CLI with chunked transfer doesn't send Content-Length, 
	// but sends X-Amz-Decoded-Content-Length instead
	if size < 0 && r.Header.Get("X-Amz-Decoded-Content-Length") != "" {
		decodedLength, err := strconv.ParseInt(r.Header.Get("X-Amz-Decoded-Content-Length"), 10, 64)
		if err == nil {
			size = decodedLength
		}
	}
	
	if size < 0 {
		h.sendError(w, fmt.Errorf("missing Content-Length"), http.StatusBadRequest)
		return
	}

	logger := logrus.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"size":       size,
		"method":     "uploadPart",
	})

	logger.Info("Starting part upload")

	// Handle AWS chunked encoding if present
	var body io.Reader = r.Body
	if r.Header.Get("x-amz-content-sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ||
		r.Header.Get("Content-Encoding") == "aws-chunked" {
		// Use SmartChunkDecoder which can handle both chunked and raw data
		body = storage.NewSmartChunkDecoder(r.Body)
		// For chunked uploads, the size is the decoded content length
		if decodedSize := r.Header.Get("x-amz-decoded-content-length"); decodedSize != "" {
			if ds, err := strconv.ParseInt(decodedSize, 10, 64); err == nil {
				size = ds
			}
		}
		logger.Info("Using smart chunk decoder for part upload")
	}

	uploadStart := time.Now()
	
	// For very large parts, add progress logging
	if size > 50*1024*1024 { // > 50MB
		logger.WithFields(logrus.Fields{
			"size": size,
			"sizeMB": size / 1024 / 1024,
		}).Warn("Large part upload - adding extended timeout and progress tracking")
		
		// Use extended timeout for large parts
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
	}
	
	etag, err := h.storage.UploadPart(ctx, bucket, key, uploadID, partNumber, body, size)
	uploadDuration := time.Since(uploadStart)

	if err != nil {
		logger.WithError(err).WithField("uploadDuration", uploadDuration).Error("Part upload failed")
		
		// Check if it's a timeout
		if ctx.Err() == context.DeadlineExceeded || strings.Contains(err.Error(), "timeout") {
			logger.Error("Part upload timed out - S3 backend is too slow")
		}
		
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
	
	logger.WithFields(logrus.Fields{
		"etag":          etag,
		"uploadDuration": uploadDuration,
		"totalDuration": time.Since(start),
	}).Info("Part upload completed successfully")
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

	userAgent := r.Header.Get("User-Agent")
	logrus.WithFields(logrus.Fields{
		"bucket":    bucket,
		"key":       key,
		"uploadID":  uploadID,
		"parts":     len(parts),
		"userAgent": userAgent,
		"isTrino":   strings.Contains(userAgent, "Trino"),
		"headers":   r.Header,
	}).Info("Completing multipart upload")

	err := h.storage.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to complete multipart upload")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}
	
	// For Trino, verify the object exists before returning success
	// This ensures S3 backend has fully processed the multipart upload
	if strings.Contains(userAgent, "Trino") {
		logrus.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Debug("Verifying object exists for Trino before returning success")
		
		// Small retry loop to handle eventual consistency
		var verifyErr error
		for i := 0; i < 3; i++ {
			_, verifyErr = h.storage.HeadObject(ctx, bucket, key)
			if verifyErr == nil {
				break
			}
			if i < 2 {
				time.Sleep(100 * time.Millisecond)
			}
		}
		
		if verifyErr != nil {
			logrus.WithError(verifyErr).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
			}).Warn("Object not immediately available after multipart complete")
		}
	}
	
	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	}).Info("Multipart upload completed successfully - LOCK SHOULD BE RELEASED")
	
	// Add AWS-compatible headers
	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("x-amz-id-2", fmt.Sprintf("uS8Fg/%s", requestID))
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("Server", "AmazonS3")

	type completeMultipartUploadResult struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}

	w.Header().Set("Content-Type", "application/xml")
	
	// Write status code BEFORE encoding
	w.WriteHeader(http.StatusOK)
	
	// CRITICAL: Flush headers immediately for Trino
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	
	// Add XML declaration
	w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
	
	// Generate proper multipart ETag
	// For multipart uploads, AWS S3 generates an ETag in the format: {md5_of_md5s}-{number_of_parts}
	hasher := md5.New()
	for _, part := range parts {
		// Remove quotes from ETag if present
		etag := strings.Trim(part.ETag, "\"")
		// Decode hex string to bytes
		if partMD5, err := hex.DecodeString(etag); err == nil {
			hasher.Write(partMD5)
		}
	}
	multipartMD5 := hasher.Sum(nil)
	multipartETag := fmt.Sprintf("\"%s-%d\"", hex.EncodeToString(multipartMD5), len(parts))
	
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(completeMultipartUploadResult{
		Location: fmt.Sprintf("http://%s/%s/%s", r.Host, bucket, key),
		Bucket:   bucket,
		Key:      key,
		ETag:     multipartETag,
	}); err != nil {
		logrus.WithError(err).Error("Failed to encode response")
	}
	
	// CRITICAL: Flush the response body to ensure Trino receives it
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
		logrus.WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Debug("Flushed CompleteMultipartUpload response")
	}
}

func (h *Handler) abortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	ctx := r.Context()

	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	}).Info("Aborting multipart upload - RELEASING LOCK")

	err := h.storage.AbortMultipartUpload(ctx, bucket, key, uploadID)
	if err != nil {
		logrus.WithError(err).Error("Failed to abort multipart upload")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	logrus.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
	}).Info("Multipart upload aborted successfully")

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
