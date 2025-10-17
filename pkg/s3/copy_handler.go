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

// copyObjectResponse represents the XML response for a successful copy operation
type copyObjectResponse struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// handleCopyObject handles S3 CopyObject requests
func (h *Handler) handleCopyObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	destBucket := vars["bucket"]
	destKey := vars["key"]
	
	// Validate destination bucket and key
	if err := ValidateBucketName(destBucket); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}
	if err := ValidateObjectKey(destKey); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}
	
	// Get and validate the copy source
	copySource := r.Header.Get("x-amz-copy-source")
	if copySource == "" {
		h.sendError(w, fmt.Errorf("missing x-amz-copy-source header"), http.StatusBadRequest)
		return
	}
	
	// Validate and parse copy source
	sourceBucket, sourceKey, err := ValidateCopySource(copySource)
	if err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}
	
	logger := logrus.WithFields(logrus.Fields{
		"sourceBucket": sourceBucket,
		"sourceKey":    sourceKey,
		"destBucket":   destBucket,
		"destKey":      destKey,
		"copySource":   copySource,
	})
	
	logger.Info("Processing CopyObject request")
	
	ctx := r.Context()
	
	// Get the source object
	sourceObj, err := h.storage.GetObject(ctx, sourceBucket, sourceKey)
	if err != nil {
		logger.WithError(err).Error("Failed to get source object for copy")
		h.sendError(w, fmt.Errorf("failed to get source object: %w", err), http.StatusNotFound)
		return
	}
	defer sourceObj.Body.Close()
	
	// Extract metadata from headers for the destination object
	metadata := make(map[string]string)
	
	// Copy metadata directive
	metadataDirective := r.Header.Get("x-amz-metadata-directive")
	if metadataDirective == "" || metadataDirective == "COPY" {
		// Copy metadata from source
		metadata = sourceObj.Metadata
	}
	
	// Override with any new metadata from request
	newMetadata := make(map[string]string)
	for k, v := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			metaKey := strings.TrimPrefix(strings.ToLower(k), "x-amz-meta-")
			newMetadata[metaKey] = v[0]
		}
	}
	
	// Validate new metadata
	if err := ValidateMetadata(newMetadata); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}
	
	// Apply new metadata to existing metadata
	for k, v := range newMetadata {
		metadata[k] = v
	}
	
	// Put the object to the destination
	err = h.storage.PutObject(ctx, destBucket, destKey, sourceObj.Body, sourceObj.Size, metadata)
	if err != nil {
		logger.WithError(err).Error("Failed to put destination object for copy")
		h.sendError(w, fmt.Errorf("failed to copy object: %w", err), http.StatusInternalServerError)
		return
	}
	
	// Get the destination object info for the response
	destInfo, err := h.storage.HeadObject(ctx, destBucket, destKey)
	if err != nil {
		// If we can't get the info, create a synthetic response
		logger.WithError(err).Warn("Failed to get destination object info after copy, using synthetic response")
		etag := fmt.Sprintf("\"%x\"", time.Now().UnixNano())
		lastModified := time.Now().UTC().Format(time.RFC3339)
		
		response := copyObjectResponse{
			LastModified: lastModified,
			ETag:         etag,
		}
		
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		enc := xml.NewEncoder(w)
		enc.Indent("", "  ")
		if err := enc.Encode(response); err != nil {
			logger.WithError(err).Error("Failed to encode copy response")
		}
		return
	}
	
	// Create the response
	response := copyObjectResponse{
		LastModified: destInfo.LastModified.Format(time.RFC3339),
		ETag:         destInfo.ETag,
	}
	
	logger.WithFields(logrus.Fields{
		"etag":         response.ETag,
		"lastModified": response.LastModified,
	}).Info("CopyObject completed successfully")
	
	// Write the XML response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	
	// Add XML declaration
	w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
	
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		logger.WithError(err).Error("Failed to encode copy response")
	}
}