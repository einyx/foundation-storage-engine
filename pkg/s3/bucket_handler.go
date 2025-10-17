package s3

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// listBuckets handles GET / - lists all buckets for the authenticated user
func (h *Handler) listBuckets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Add S3-compatible headers to identify this as an S3 service
	w.Header().Set("Server", "AmazonS3")
	w.Header().Set("x-amz-request-id", fmt.Sprintf("%d", time.Now().UnixNano()))
	w.Header().Set("x-amz-id-2", "S3/ListBuckets")
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))

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

// handleBucket handles bucket-level operations (GET for listing, HEAD, POST for bulk operations)
func (h *Handler) handleBucket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// Validate bucket name
	if err := ValidateBucketName(bucket); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}

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

	switch r.Method {
	case "GET":
		h.listObjects(w, r, bucket)
	case "POST":
		// Check if this is a bulk delete request
		if _, hasDelete := r.URL.Query()["delete"]; hasDelete {
			h.handleBulkDelete(w, r, bucket)
			return
		}
		// Handle other POST operations
		h.sendError(w, fmt.Errorf("operation not supported"), http.StatusNotImplemented)
	case "HEAD":
		h.headBucket(w, r, bucket)
	default:
		h.sendError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// handleBucketAdmin handles administrative bucket operations (CREATE, DELETE)
func (h *Handler) handleBucketAdmin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// Validate bucket name
	if err := ValidateBucketName(bucket); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "PUT":
		h.createBucket(w, r, bucket)
	case "DELETE":
		h.deleteBucket(w, r, bucket)
	default:
		h.sendError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

// createBucket creates a new bucket (admin operation)
func (h *Handler) createBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()

	// Check if user is admin
	isAdmin, _ := ctx.Value("is_admin").(bool)
	if !isAdmin {
		logrus.WithFields(logrus.Fields{
			"user_sub":  ctx.Value("user_sub"),
			"bucket":    bucket,
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

// deleteBucket deletes an existing bucket (admin operation)
func (h *Handler) deleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()

	// Check if user is admin
	isAdmin, _ := ctx.Value("is_admin").(bool)
	if !isAdmin {
		logrus.WithFields(logrus.Fields{
			"user_sub":  ctx.Value("user_sub"),
			"bucket":    bucket,
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

// headBucket checks if a bucket exists
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

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
}
