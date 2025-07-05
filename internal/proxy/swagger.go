package proxy

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed swagger-ui/*
var swaggerUI embed.FS

// SwaggerHandler serves the Swagger UI and OpenAPI specification
type SwaggerHandler struct {
	specPath string
	specData []byte
}

// NewSwaggerHandler creates a new Swagger UI handler
func NewSwaggerHandler(specPath string) (*SwaggerHandler, error) {
	// Read the OpenAPI spec file
	specData, err := fs.ReadFile(swaggerUI, specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenAPI spec: %w", err)
	}

	return &SwaggerHandler{
		specPath: specPath,
		specData: specData,
	}, nil
}

// ServeHTTP serves the Swagger UI
func (h *SwaggerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api-docs")
	if path == "" || path == "/" {
		path = "/index.html"
	}

	// Serve the OpenAPI spec
	if path == "/openapi.yaml" || path == "/openapi.json" {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(h.specData)
		return
	}

	// Serve Swagger UI static files
	if strings.HasPrefix(path, "/") {
		path = "swagger-ui" + path
	}

	data, err := swaggerUI.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Set content type based on file extension
	contentType := "text/plain"
	switch {
	case strings.HasSuffix(path, ".html"):
		contentType = "text/html"
		// Inject the OpenAPI spec URL
		dataStr := string(data)
		dataStr = strings.ReplaceAll(dataStr, "https://petstore.swagger.io/v2/swagger.json", "/api-docs/openapi.yaml")
		data = []byte(dataStr)
	case strings.HasSuffix(path, ".css"):
		contentType = "text/css"
	case strings.HasSuffix(path, ".js"):
		contentType = "application/javascript"
	case strings.HasSuffix(path, ".json"):
		contentType = "application/json"
	}

	w.Header().Set("Content-Type", contentType)
	w.Write(data)
}

// ServeSwaggerUI returns an HTTP handler for Swagger UI without embedded files
func ServeSwaggerUI(openAPISpec []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/docs")
		
		// Serve the OpenAPI spec
		if path == "/openapi.yaml" || path == "/openapi.json" || path == "/spec" {
			w.Header().Set("Content-Type", "application/yaml")
			w.Write(openAPISpec)
			return
		}

		// Serve a simple HTML page that loads Swagger UI from CDN
		if path == "" || path == "/" || path == "/index.html" {
			html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Foundation Storage Engine - API Documentation</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.10.3/swagger-ui.css">
    <style>
        body {
            margin: 0;
            padding: 0;
        }
        .swagger-ui .topbar {
            display: none;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.10.3/swagger-ui-bundle.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.10.3/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "/docs/openapi.yaml",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>`
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(html))
			return
		}

		http.NotFound(w, r)
	}
}