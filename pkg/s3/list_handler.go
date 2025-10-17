package s3

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/storage"
)

// List operation result structures
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
	XMLName        xml.Name   `xml:"ListBucketResult"`
	Name           string     `xml:"Name"`
	Prefix         string     `xml:"Prefix"`
	MaxKeys        int        `xml:"MaxKeys"`
	IsTruncated    bool       `xml:"IsTruncated"`
	Contents       []contents `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes,omitempty"`
	ContinuationToken     string `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string `xml:"NextContinuationToken,omitempty"`
	KeyCount              int    `xml:"KeyCount"`
}

// Deleted objects listing structures
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
	XMLName     xml.Name          `xml:"ListBucketResult"`
	Name        string            `xml:"Name"`
	Prefix      string            `xml:"Prefix"`
	Marker      string            `xml:"Marker"`
	NextMarker  string            `xml:"NextMarker,omitempty"`
	MaxKeys     int               `xml:"MaxKeys"`
	IsTruncated bool              `xml:"IsTruncated"`
	Contents    []deletedContents `xml:"Contents"`
}

// listObjects handles bucket listing operations
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

	// Validate query parameters
	if err := ValidateQueryParameter("prefix", prefix); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}
	if err := ValidateQueryParameter("delimiter", delimiter); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}
	if err := ValidateQueryParameter("marker", marker); err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
	}

	// For V2 requests, use continuation-token instead of marker
	if isV2 {
		continuationToken := r.URL.Query().Get("continuation-token")
		if continuationToken != "" {
			if err := ValidateContinuationToken(continuationToken); err != nil {
				h.sendError(w, err, http.StatusBadRequest)
				return
			}
			marker = continuationToken
		}
	}

	// Validate and set max-keys
	maxKeys, err := ValidateMaxKeys(maxKeysStr)
	if err != nil {
		h.sendError(w, err, http.StatusBadRequest)
		return
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
		"bucket":         bucket,
		"prefix":         prefix,
		"delimiter":      delimiter,
		"maxKeys":        maxKeys,
		"marker":         marker,
		"includeDeleted": includeDeleted,
	})

	// Handle soft delete listing
	var result *storage.ListObjectsResult

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
			"bucket":       bucket,
		}).Info("Returning deleted objects XML response")

		if len(response.Contents) > 0 {
			logrus.WithFields(logrus.Fields{
				"firstKey":  response.Contents[0].Key,
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

	if isV2 && result.IsTruncated {
		logger.WithFields(logrus.Fields{
			"marker":      marker,
			"nextMarker":  result.NextMarker,
			"resultCount": len(result.Contents),
			"isTruncated": result.IsTruncated,
		}).Debug("V2 list pagination state")
	}

	// Safety check: Never return IsTruncated=true with empty Contents
	// This prevents XML parsing errors in clients
	if len(result.Contents) == 0 && result.IsTruncated {
		logrus.WithFields(logrus.Fields{
			"bucket":      bucket,
			"prefix":      prefix,
			"isTruncated": result.IsTruncated,
			"nextMarker":  result.NextMarker,
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
				"bucket":        bucket,
				"prefix":        prefix,
				"marker":        marker,
				"decodedMarker": decodedMarker,
				"nextMarker":    result.NextMarker,
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
