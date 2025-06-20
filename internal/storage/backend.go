// Package storage provides storage backend interfaces and implementations.
package storage

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/einyx/s3proxy-go/internal/config"
)

type Backend interface {
	ListBuckets(ctx context.Context) ([]BucketInfo, error)
	CreateBucket(ctx context.Context, bucket string) error
	DeleteBucket(ctx context.Context, bucket string) error
	BucketExists(ctx context.Context, bucket string) (bool, error)

	ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error)
	ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error)
	GetObject(ctx context.Context, bucket, key string) (*Object, error)
	PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error
	DeleteObject(ctx context.Context, bucket, key string) error
	HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error)

	GetObjectACL(ctx context.Context, bucket, key string) (*ACL, error)
	PutObjectACL(ctx context.Context, bucket, key string, acl *ACL) error

	InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error)
	UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error)
	CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error
	AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error
	ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error)
}

type BucketInfo struct {
	Name         string
	CreationDate time.Time
}

type ListObjectsResult struct {
	IsTruncated    bool
	Contents       []ObjectInfo
	NextMarker     string
	CommonPrefixes []string
}

type Object struct {
	Body         io.ReadCloser
	ContentType  string
	Size         int64
	ETag         string
	Metadata     map[string]string
	LastModified time.Time
}

type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
	StorageClass string
	ContentType  string
	Metadata     map[string]string
}

type ACL struct {
	Owner  Owner
	Grants []Grant
}

type Owner struct {
	ID          string
	DisplayName string
}

type Grant struct {
	Grantee    Grantee
	Permission string
}

type Grantee struct {
	Type        string
	ID          string
	DisplayName string
	URI         string
}

type CompletedPart struct {
	PartNumber int
	ETag       string
}

type ListPartsResult struct {
	Bucket               string
	Key                  string
	UploadID             string
	PartNumberMarker     int
	NextPartNumberMarker int
	MaxParts             int
	IsTruncated          bool
	Parts                []Part
}

type Part struct {
	PartNumber   int
	ETag         string
	Size         int64
	LastModified time.Time
}

func NewBackend(cfg config.StorageConfig) (Backend, error) {
	switch cfg.Provider {
	case "azure", "azureblob":
		return NewAzureBackend(cfg.Azure)
	case "s3":
		return NewS3Backend(cfg.S3)
	case "filesystem":
		if cfg.FileSystem == nil {
			return nil, fmt.Errorf("filesystem configuration required")
		}
		return NewFileSystemBackend(cfg.FileSystem)
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", cfg.Provider)
	}
}
