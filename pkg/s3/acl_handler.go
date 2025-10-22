// Package s3 provides S3-compatible API handlers for the proxy server.
package s3

import (
	"encoding/xml"
	"net/http"

	"github.com/sirupsen/logrus"
)

// grantee represents an ACL grantee
type grantee struct {
	XMLName     xml.Name `xml:"Grantee"`
	Type        string   `xml:"xsi:type,attr"`
	ID          string   `xml:"ID,omitempty"`
	DisplayName string   `xml:"DisplayName,omitempty"`
	URI         string   `xml:"URI,omitempty"`
}

// grant represents an ACL grant
type grant struct {
	Grantee    grantee `xml:"Grantee"`
	Permission string  `xml:"Permission"`
}

// accessControlPolicy represents the ACL response structure
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

// getObjectACL handles GET requests for object ACLs
func (h *Handler) getObjectACL(w http.ResponseWriter, r *http.Request, bucket, key string) {
	ctx := r.Context()

	acl, err := h.storage.GetObjectACL(ctx, bucket, key)
	if err != nil {
		h.sendError(w, err, http.StatusInternalServerError)
		return
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

// putObjectACL handles PUT requests for object ACLs
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
