# Build stage
FROM golang:1.24.3-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o foundation-storage-engine ./cmd/foundation-storage-engine

# Final stage
FROM alpine:latest

# Install wget for health checks
RUN apk --no-cache add wget ca-certificates

COPY --from=builder /app/foundation-storage-engine /foundation-storage-engine

# Copy web UI files
COPY web /web

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/foundation-storage-engine"]
