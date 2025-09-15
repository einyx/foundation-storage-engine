package s3

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// handleSDKv2Request checks if this is an SDK v2 request and performs any necessary transformations
// The 'w' parameter is included to maintain consistency with other handler methods, even though it's currently unused
func (h *Handler) handleSDKv2Request(_ http.ResponseWriter, r *http.Request) bool {
	// Check for SDK v2 specific headers
	sdkRequest := r.Header.Get("x-amz-sdk-request")
	checksumAlgorithm := r.Header.Get("x-amz-checksum-algorithm")

	// Log SDK version detection
	if sdkRequest != "" {
		logrus.WithFields(logrus.Fields{
			"sdk_request": sdkRequest,
			"method":      r.Method,
			"path":        r.URL.Path,
		}).Debug("SDK v2 request detected")
	}

	// Handle SDK v2 checksum headers
	if checksumAlgorithm != "" {
		logrus.WithField("algorithm", checksumAlgorithm).Debug("SDK v2 checksum algorithm requested")

		// For uploads, we'll accept the checksum but not validate it (s3proxy will calculate its own)
		if r.Method == "PUT" || r.Method == "POST" {
			// Map SDK v2 checksum headers to standard headers
			if sha256 := r.Header.Get("x-amz-checksum-sha256"); sha256 != "" {
				r.Header.Set("x-amz-content-sha256", sha256)
			}

			if crc32 := r.Header.Get("x-amz-checksum-crc32"); crc32 != "" {
				logrus.WithField("crc32", crc32).Debug("CRC32 checksum present (not validated)")
			}

			if crc32c := r.Header.Get("x-amz-checksum-crc32c"); crc32c != "" {
				logrus.WithField("crc32c", crc32c).Debug("CRC32C checksum present (not validated)")
			}
		}
	}

	// Handle SDK v2 specific query parameters
	if r.URL.Query().Get("x-id") != "" {
		logrus.WithField("x-id", r.URL.Query().Get("x-id")).Debug("SDK v2 x-id parameter present")
	}

	// Return true if this is definitely an SDK v2 request
	return sdkRequest != "" || checksumAlgorithm != ""
}
