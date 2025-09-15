package s3

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

// DeleteObjectsRequest represents the XML request for multi-object delete
type DeleteObjectsRequest struct {
	XMLName xml.Name `xml:"Delete"`
	Quiet   bool     `xml:"Quiet"`
	Objects []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId,omitempty"`
	} `xml:"Object"`
}

// DeleteObjectsResponse represents the XML response for multi-object delete
type DeleteObjectsResponse struct {
	XMLName xml.Name        `xml:"DeleteResult"`
	Deleted []DeletedObject `xml:"Deleted,omitempty"`
	Errors  []DeleteError   `xml:"Error,omitempty"`
}

// DeletedObject represents a successfully deleted object
type DeletedObject struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId,omitempty"`
}

// DeleteError represents a failed deletion
type DeleteError struct {
	Key       string `xml:"Key"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
	VersionID string `xml:"VersionId,omitempty"`
}

// handleBulkDelete handles POST /?delete requests
func (h *Handler) handleBulkDelete(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()

	logger := logrus.WithFields(logrus.Fields{
		"bucket":    bucket,
		"operation": "bulkDelete",
	})

	// Parse XML body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		h.sendError(w, err, http.StatusBadRequest)
		return
	}

	var req DeleteObjectsRequest
	if unmarshalErr := xml.Unmarshal(body, &req); unmarshalErr != nil {
		logger.WithError(unmarshalErr).Error("Failed to parse XML")
		h.sendError(w, fmt.Errorf("malformed XML"), http.StatusBadRequest)
		return
	}

	logger.WithField("objectCount", len(req.Objects)).Info("Processing bulk delete request")

	// Process deletions
	var response DeleteObjectsResponse

	for _, obj := range req.Objects {
		// Delete each object individually
		deleteErr := h.storage.DeleteObject(ctx, bucket, obj.Key)

		if deleteErr != nil {
			// Add to errors
			response.Errors = append(response.Errors, DeleteError{
				Key:     obj.Key,
				Code:    "InternalError",
				Message: deleteErr.Error(),
			})
			logger.WithError(deleteErr).WithField("key", obj.Key).Warn("Failed to delete object")
		} else {
			// Add to deleted list (unless quiet mode)
			if !req.Quiet {
				response.Deleted = append(response.Deleted, DeletedObject{
					Key: obj.Key,
				})
			}
			logger.WithField("key", obj.Key).Debug("Deleted object")
		}
	}

	// Return XML response
	responseXML, err := xml.Marshal(response)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal response")
		h.sendError(w, err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(responseXML)

	logger.WithFields(logrus.Fields{
		"deleted": len(response.Deleted),
		"errors":  len(response.Errors),
	}).Info("Bulk delete completed")
}
