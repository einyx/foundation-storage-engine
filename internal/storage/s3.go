package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"

	"github.com/meshxdata/foundation-storage-engine/internal/config"
)

const (
	multipartThreshold = 5 * 1024 * 1024 // 5MB
	partSize           = 5 * 1024 * 1024 // 5MB
)

type chunkedDecodingReader struct {
	reader   io.ReadCloser
	buffer   []byte
	chunkBuf []byte
	inChunk  bool
	done     bool
}

func newChunkedDecodingReader(r io.ReadCloser) io.ReadCloser {
	return &chunkedDecodingReader{
		reader:   r,
		buffer:   make([]byte, 0),
		chunkBuf: make([]byte, 8192),
	}
}

func (c *chunkedDecodingReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}

	// If we have buffered data, return it first
	if len(c.buffer) > 0 {
		n := copy(p, c.buffer)
		c.buffer = c.buffer[n:]
		return n, nil
	}

	// Read more data
	n, err := c.reader.Read(c.chunkBuf)
	if n > 0 {
		data := c.chunkBuf[:n]

		// Check if this looks like chunked encoding
		if !c.inChunk && len(data) > 0 {
			// Look for chunk signature pattern (hex size followed by ;chunk-signature=)
			if idx := bytes.Index(data, []byte(";chunk-signature=")); idx > 0 && idx < 20 {
				// Skip the chunk header line
				if endIdx := bytes.IndexByte(data, '\n'); endIdx > idx {
					data = data[endIdx+1:]
					c.inChunk = true
				}
			}
		}

		// Remove any trailing chunk markers (0\r\n\r\n at the end)
		if bytes.HasSuffix(data, []byte("0\r\n\r\n")) {
			data = data[:len(data)-5]
			c.done = true
		}

		// Copy what we can to the output buffer
		copied := copy(p, data)
		// Save any remaining data for next read
		if copied < len(data) {
			c.buffer = append(c.buffer, data[copied:]...)
		}

		return copied, nil
	}

	return 0, err
}

func (c *chunkedDecodingReader) Close() error {
	return c.reader.Close()
}

type S3Backend struct {
	defaultClient   *s3.S3                          // Default S3 client
	clients         map[string]*s3.S3               // Per-region S3 clients
	sessions        map[string]*session.Session     // Per-region sessions
	config          *config.S3StorageConfig         // Keep reference to config
	bucketMapping   map[string]string               // Simple virtual to real bucket mapping
	bucketConfigs   map[string]*config.BucketConfig // Per-bucket configuration
	bufferPool      sync.Pool
	largeBufferPool sync.Pool
	metadataCache   *MetadataCache
	mu              sync.RWMutex // Protect client creation
}

type MetadataCache struct {
	mu    sync.RWMutex
	cache map[string]*cachedMetadata
	ttl   time.Duration
}

type cachedMetadata struct {
	info   *ObjectInfo
	expiry time.Time
}

func (m *MetadataCache) Get(key string) (*ObjectInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if entry, ok := m.cache[key]; ok && time.Now().Before(entry.expiry) {
		return entry.info, true
	}
	return nil, false
}

func (m *MetadataCache) Set(key string, info *ObjectInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache[key] = &cachedMetadata{
		info:   info,
		expiry: time.Now().Add(m.ttl),
	}
}

func (m *MetadataCache) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cache, key)
}

func (s *S3Backend) mapBucket(virtualBucket string) string {
	if s.bucketConfigs != nil {
		if cfg, ok := s.bucketConfigs[virtualBucket]; ok && cfg.RealName != "" {
			// logrus.WithFields(logrus.Fields{
			// 	"virtual": virtualBucket,
			// 	"real":    cfg.RealName,
			// }).Debug("Mapping bucket name from bucket config")
			return cfg.RealName
		}
	}

	if s.bucketMapping != nil {
		if realBucket, ok := s.bucketMapping[virtualBucket]; ok {
			// logrus.WithFields(logrus.Fields{
			// 	"virtual": virtualBucket,
			// 	"real":    realBucket,
			// }).Debug("Mapping bucket name from simple mapping")
			return realBucket
		}
	}

	return virtualBucket
}

func (s *S3Backend) getPrefixForBucket(virtualBucket string) string {
	// logrus.WithFields(logrus.Fields{
	// 	"virtualBucket": virtualBucket,
	// 	"hasConfigs":    s.bucketConfigs != nil,
	// 	"configCount":   len(s.bucketConfigs),
	// }).Debug("getPrefixForBucket called")

	if s.bucketConfigs != nil {
		if cfg, ok := s.bucketConfigs[virtualBucket]; ok {
			logrus.WithFields(logrus.Fields{
				"virtualBucket": virtualBucket,
				"realName":      cfg.RealName,
				"prefix":        cfg.Prefix,
				"region":        cfg.Region,
				"hasPrefix":     cfg.Prefix != "",
			}).Info("Found bucket config")

			if cfg.Prefix != "" {
				prefix := cfg.Prefix
				if !strings.HasSuffix(prefix, "/") {
					prefix += "/"
				}
				logrus.WithFields(logrus.Fields{
					"virtualBucket": virtualBucket,
					"prefix":        prefix,
				}).Info("Using bucket prefix")
				return prefix
			}
		}
	}

	// logrus.WithField("virtualBucket", virtualBucket).Debug("No prefix found for bucket")
	return ""
}

func (s *S3Backend) addPrefixToKey(virtualBucket, key string) string {
	prefix := s.getPrefixForBucket(virtualBucket)
	if prefix == "" {
		return key
	}
	if strings.HasPrefix(key, "/") {
		return prefix + key[1:]
	}
	return prefix + key
}

func (s *S3Backend) removePrefixFromKey(virtualBucket, key string) string {
	prefix := s.getPrefixForBucket(virtualBucket)
	if prefix == "" {
		return key
	}
	return strings.TrimPrefix(key, prefix)
}

// GetBucketConfig returns the configuration for a specific bucket
func (s *S3Backend) GetBucketConfig(bucket string) *config.BucketConfig {
	if s.bucketConfigs != nil {
		if cfg, ok := s.bucketConfigs[bucket]; ok {
			return cfg
		}
	}
	return nil
}

func (s *S3Backend) getClientForBucket(bucket string) (*s3.S3, error) {
	if s.bucketConfigs != nil {
		if cfg, ok := s.bucketConfigs[bucket]; ok {
			// logrus.WithFields(logrus.Fields{
			// 	"virtualBucket": bucket,
			// 	"realBucket":    cfg.RealName,
			// 	"region":        cfg.Region,
			// }).Debug("Using bucket-specific configuration")
			return s.getOrCreateClient(cfg)
		}

		for _, cfg := range s.bucketConfigs {
			if cfg.RealName == bucket {
				// logrus.WithFields(logrus.Fields{
				// 	"realBucket":    bucket,
				// 	"virtualBucket": virtualBucket,
				// 	"region":        cfg.Region,
				// }).Debug("Using configuration from virtual bucket mapping")
				return s.getOrCreateClient(cfg)
			}
		}
	}

	// logrus.WithField("bucket", bucket).Debug("Using default client for bucket")
	// Use default client
	return s.defaultClient, nil
}

func (s *S3Backend) getOrCreateClient(bucketCfg *config.BucketConfig) (*s3.S3, error) {
	clientKey := bucketCfg.Region
	if bucketCfg.Endpoint != "" {
		clientKey = bucketCfg.Endpoint + "_" + bucketCfg.Region // pragma: allowlist secret
	}

	s.mu.RLock()
	if client, ok := s.clients[clientKey]; ok {
		s.mu.RUnlock()
		return client, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if client, ok := s.clients[clientKey]; ok {
		return client, nil
	}

	awsConfig := &aws.Config{
		Region:           aws.String(bucketCfg.Region),
		S3ForcePathStyle: aws.Bool(s.config.UsePathStyle),
		MaxRetries:       aws.Int(3),
	}

	if bucketCfg.Endpoint != "" {
		awsConfig.Endpoint = aws.String(bucketCfg.Endpoint)
	} else if s.config.Endpoint != "" && bucketCfg.Endpoint == "" {
		awsConfig.Endpoint = aws.String(s.config.Endpoint)
	}

	if s.config.DisableSSL {
		awsConfig.DisableSSL = aws.Bool(true)
	}

	if bucketCfg.AccessKey != "" && bucketCfg.SecretKey != "" {
		awsConfig.Credentials = credentials.NewStaticCredentials(bucketCfg.AccessKey, bucketCfg.SecretKey, "")
	} else if s.config.AccessKey != "" && s.config.SecretKey != "" {
		awsConfig.Credentials = credentials.NewStaticCredentials(s.config.AccessKey, s.config.SecretKey, "")
	}

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session for region %s: %w", bucketCfg.Region, err)
	}

	client := s3.New(sess)

	s.clients[clientKey] = client
	s.sessions[clientKey] = sess

	logrus.WithFields(logrus.Fields{
		"region":   bucketCfg.Region,
		"endpoint": bucketCfg.Endpoint,
		"key":      clientKey,
	}).Info("Created new S3 client for bucket")

	return client, nil
}

func NewS3Backend(cfg *config.S3StorageConfig) (*S3Backend, error) {
	awsConfig := &aws.Config{
		Region:                        aws.String(cfg.Region),
		S3ForcePathStyle:              aws.Bool(cfg.UsePathStyle),
		MaxRetries:                    aws.Int(3),
		S3UseAccelerate:               aws.Bool(false),
		S3DisableContentMD5Validation: aws.Bool(false),
	}

	if cfg.Endpoint != "" {
		awsConfig.Endpoint = aws.String(cfg.Endpoint)
		logrus.WithField("endpoint", cfg.Endpoint).Info("Using custom S3 endpoint")
	}

	if cfg.DisableSSL {
		awsConfig.DisableSSL = aws.Bool(true)
	}

	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		awsConfig.Credentials = credentials.NewStaticCredentials(cfg.AccessKey, cfg.SecretKey, "")
		logrus.Info("Using static AWS credentials")
	} else {
		logrus.Info("Using AWS default credential chain (env vars, IAM role, etc.)")
	}

	var sess *session.Session
	var err error

	if cfg.Profile != "" {
		sess, err = session.NewSessionWithOptions(session.Options{
			Config:            *awsConfig,
			Profile:           cfg.Profile,
			SharedConfigState: session.SharedConfigEnable,
		})
		logrus.WithField("profile", cfg.Profile).Info("Using AWS profile")
	} else {
		sess, err = session.NewSession(awsConfig)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	s3Client := s3.New(sess)

	if sess.Config.Credentials != nil {
		creds, err := sess.Config.Credentials.Get()
		if err != nil {
			logrus.WithError(err).Warn("Failed to get AWS credentials for logging")
		} else {
			logrus.WithFields(logrus.Fields{
				"provider":     creds.ProviderName,
				"hasAccessKey": creds.AccessKeyID != "",
			}).Info("AWS credentials resolved")
		}
	}

	if len(cfg.BucketMapping) > 0 {
		logrus.WithField("bucketMapping", cfg.BucketMapping).Info("Bucket mapping configured")
	}

	if len(cfg.BucketConfigs) > 0 {
		sanitizedConfigs := make(map[string]interface{})
		for name, config := range cfg.BucketConfigs {
			sanitizedConfigs[name] = map[string]interface{}{
				"RealName": config.RealName,
				"Prefix":   config.Prefix,
				"Region":   config.Region,
				"Endpoint": config.Endpoint,
			}
		}
		logrus.WithField("bucketConfigs", sanitizedConfigs).Info("Bucket configs configured")
	}

	logrus.WithFields(logrus.Fields{
		"endpoint":     cfg.Endpoint,
		"region":       cfg.Region,
		"usePathStyle": cfg.UsePathStyle,
	}).Info("S3 backend created")

	return &S3Backend{
		defaultClient: s3Client,
		clients:       make(map[string]*s3.S3),
		sessions:      make(map[string]*session.Session),
		config:        cfg,
		bucketMapping: cfg.BucketMapping,
		bucketConfigs: cfg.BucketConfigs,
		bufferPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 32*1024) // 32KB buffers
				return &buf
			},
		},
		largeBufferPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 1024*1024) // 1MB buffers
				return &buf
			},
		},
		metadataCache: &MetadataCache{
			cache: make(map[string]*cachedMetadata),
			ttl:   30 * time.Second,
		},
	}, nil
}

func (s *S3Backend) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	result, err := s.defaultClient.ListBucketsWithContext(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	realBuckets := make(map[string]BucketInfo)
	for _, b := range result.Buckets {
		realBuckets[aws.StringValue(b.Name)] = BucketInfo{
			Name:         aws.StringValue(b.Name),
			CreationDate: aws.TimeValue(b.CreationDate),
		}
	}

	buckets := make([]BucketInfo, 0, len(s.bucketConfigs))

	for virtualName, config := range s.bucketConfigs {
		creationDate := time.Now()
		if realBucket, exists := realBuckets[config.RealName]; exists {
			creationDate = realBucket.CreationDate
		}

		buckets = append(buckets, BucketInfo{
			Name:         virtualName,
			CreationDate: creationDate,
		})
	}

	return buckets, nil
}

func (s *S3Backend) CreateBucket(ctx context.Context, bucket string) error {
	realBucket := s.mapBucket(bucket)
	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return fmt.Errorf("failed to get client for bucket: %w", err)
	}

	_, err = client.CreateBucketWithContext(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(realBucket),
	})
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}
	return nil
}

func (s *S3Backend) DeleteBucket(ctx context.Context, bucket string) error {
	realBucket := s.mapBucket(bucket)
	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return fmt.Errorf("failed to get client for bucket: %w", err)
	}

	_, err = client.DeleteBucketWithContext(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(realBucket),
	})
	if err != nil {
		return fmt.Errorf("failed to delete bucket: %w", err)
	}
	return nil
}

func (s *S3Backend) BucketExists(ctx context.Context, bucket string) (bool, error) {
	if s.bucketConfigs != nil {
		if _, ok := s.bucketConfigs[bucket]; ok {
			return true, nil
		}
	}

	realBucket := s.mapBucket(bucket)
	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return false, fmt.Errorf("failed to get client for bucket: %w", err)
	}

	_, err = client.HeadBucketWithContext(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(realBucket),
	})
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *S3Backend) ListObjects(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListObjectsResult, error) {
	return s.ListObjectsWithDelimiter(ctx, bucket, prefix, marker, "", maxKeys)
}

func (s *S3Backend) ListObjectsWithDelimiter(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	realBucket := s.mapBucket(bucket)
	bucketPrefix := s.getPrefixForBucket(bucket)

	actualPrefix := bucketPrefix + prefix

	logrus.WithFields(logrus.Fields{
		"bucket":       bucket,
		"realBucket":   realBucket,
		"bucketPrefix": bucketPrefix,
		"prefix":       prefix,
		"actualPrefix": actualPrefix,
		"delimiter":    delimiter,
	}).Info("S3 ListObjectsWithDelimiter called")

	input := &s3.ListObjectsInput{
		Bucket:  aws.String(realBucket),
		MaxKeys: aws.Int64(int64(maxKeys)),
	}

	if actualPrefix != "" {
		input.Prefix = aws.String(actualPrefix)
	}
	if marker != "" {
		input.Marker = aws.String(s.addPrefixToKey(bucket, marker))
	}
	if delimiter != "" {
		input.Delimiter = aws.String(delimiter)
	}

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for bucket: %w", err)
	}

	resp, err := client.ListObjectsWithContext(ctx, input)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"bucket": bucket,
			"error":  err.Error(),
		}).Error("S3 ListObjects failed")
		return nil, fmt.Errorf("failed to list objects: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"bucket":       bucket,
		"objectCount":  len(resp.Contents),
		"prefixCount":  len(resp.CommonPrefixes),
		"actualPrefix": actualPrefix,
		"bucketPrefix": bucketPrefix,
	}).Info("S3 ListObjects response received")

	// for i, obj := range resp.Contents {
	// 	if i < 5 {
	// 		logrus.WithFields(logrus.Fields{
	// 			"bucket":    bucket,
	// 			"rawKey":    aws.StringValue(obj.Key),
	// 			"objectNum": i + 1,
	// 		}).Debug("Raw object from S3")
	// 	}
	// }

	result := &ListObjectsResult{
		IsTruncated: aws.BoolValue(resp.IsTruncated),
		Contents:    make([]ObjectInfo, 0, len(resp.Contents)),
	}

	for _, obj := range resp.Contents {
		key := aws.StringValue(obj.Key)
		size := aws.Int64Value(obj.Size)

		if bucketPrefix != "" && !strings.HasPrefix(key, bucketPrefix) {
			// logrus.WithFields(logrus.Fields{
			// 	"key":          key,
			// 	"bucketPrefix": bucketPrefix,
			// 	"bucket":       bucket,
			// }).Debug("Filtering out object not in bucket prefix")
			continue
		}

		virtualKey := s.removePrefixFromKey(bucket, key)

		if delimiter == "/" && strings.HasSuffix(virtualKey, "/") {
			continue
		}

		result.Contents = append(result.Contents, ObjectInfo{
			Key:          virtualKey,
			Size:         size,
			ETag:         aws.StringValue(obj.ETag),
			LastModified: aws.TimeValue(obj.LastModified),
			StorageClass: aws.StringValue(obj.StorageClass),
		})
	}

	if resp.NextMarker != nil {
		result.NextMarker = s.removePrefixFromKey(bucket, aws.StringValue(resp.NextMarker))
	}

	for _, prefix := range resp.CommonPrefixes {
		prefixStr := aws.StringValue(prefix.Prefix)

		if bucketPrefix != "" && !strings.HasPrefix(prefixStr, bucketPrefix) {
			// logrus.WithFields(logrus.Fields{
			// 	"prefix":       prefixStr,
			// 	"bucketPrefix": bucketPrefix,
			// 	"bucket":       bucket,
			// }).Debug("Filtering out prefix not in bucket prefix")
			continue
		}

		virtualPrefix := s.removePrefixFromKey(bucket, prefixStr)
		result.CommonPrefixes = append(result.CommonPrefixes, virtualPrefix)
	}

	return result, nil
}

func (s *S3Backend) GetObject(ctx context.Context, bucket, key string) (*Object, error) {
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	input := &s3.GetObjectInput{
		Bucket: aws.String(realBucket),
		Key:    aws.String(realKey),
	}

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for bucket: %w", err)
	}

	resp, err := client.GetObjectWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	metadata := make(map[string]string)
	for k, v := range resp.Metadata {
		if v != nil {
			metadata[k] = *v
		}
	}

	// Add KMS encryption metadata if present
	if resp.ServerSideEncryption != nil && *resp.ServerSideEncryption == "aws:kms" {
		metadata["x-amz-server-side-encryption"] = "aws:kms"
		if resp.SSEKMSKeyId != nil {
			metadata["x-amz-server-side-encryption-aws-kms-key-id"] = *resp.SSEKMSKeyId
		}
	}

	// IMPORTANT: For Iceberg metadata files and other JSON content, we should NOT
	// use the chunked decoding reader as it can corrupt the data.
	var body = resp.Body

	contentLength := aws.Int64Value(resp.ContentLength)
	contentType := aws.StringValue(resp.ContentType)

	// For chunked responses without content length, use chunked decoder
	if resp.ContentLength == nil || contentLength == -1 {
		// Response might be chunked, use chunked decoder
		logrus.WithFields(logrus.Fields{
			"key":         realKey,
			"contentType": contentType,
		}).Debug("Using chunked decoding reader")
		body = newChunkedDecodingReader(resp.Body)
	}

	return &Object{
		Body:         body,
		ContentType:  aws.StringValue(resp.ContentType),
		Size:         aws.Int64Value(resp.ContentLength),
		ETag:         aws.StringValue(resp.ETag),
		LastModified: aws.TimeValue(resp.LastModified),
		Metadata:     metadata,
	}, nil
}

func (s *S3Backend) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, metadata map[string]string) error {
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	var body io.ReadSeeker
	if rs, ok := reader.(io.ReadSeeker); ok {
		body = rs
	} else {
		if size > 0 && size <= multipartThreshold {
			data, err := io.ReadAll(reader)
			if err != nil {
				return fmt.Errorf("failed to read data: %w", err)
			}
			body = bytes.NewReader(data)
		} else {
			return s.putObjectMultipart(ctx, bucket, realBucket, key, reader, metadata)
		}
	}

	input := &s3.PutObjectInput{
		Bucket:        aws.String(realBucket),
		Key:           aws.String(realKey),
		Body:          body,
		ContentLength: aws.Int64(size),
		// Disable automatic checksum calculation by the SDK
		// This prevents checksum validation errors when we modify content
		ChecksumAlgorithm: nil,
	}

	// Handle KMS encryption headers
	kmsHeaders := make(map[string]string)
	if len(metadata) > 0 {
		input.Metadata = make(map[string]*string)
		for k, v := range metadata {
			// Extract KMS headers from metadata
			if strings.HasPrefix(k, "x-amz-server-side-encryption") {
				kmsHeaders[k] = v
			} else {
				input.Metadata[k] = aws.String(v)
			}
		}
	}

	// Apply KMS encryption settings
	if encryption, ok := kmsHeaders["x-amz-server-side-encryption"]; ok && encryption == "aws:kms" {
		input.ServerSideEncryption = aws.String("aws:kms")
		if keyID, ok := kmsHeaders["x-amz-server-side-encryption-aws-kms-key-id"]; ok {
			input.SSEKMSKeyId = aws.String(keyID)
		}
		// Note: Encryption context would be handled via a different field if needed
	}

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return fmt.Errorf("failed to get client for bucket: %w", err)
	}

	_, err = client.PutObjectWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put object: %w", err)
	}

	s.metadataCache.Delete(fmt.Sprintf("%s/%s", bucket, key))

	return nil
}

func (s *S3Backend) DeleteObject(ctx context.Context, bucket, key string) error {
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return fmt.Errorf("failed to get client for bucket: %w", err)
	}

	_, err = client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(realBucket),
		Key:    aws.String(realKey),
	})
	if err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}

	s.metadataCache.Delete(fmt.Sprintf("%s/%s", bucket, key))

	return nil
}

func (s *S3Backend) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	cacheKey := fmt.Sprintf("%s/%s", bucket, key)
	if cached, found := s.metadataCache.Get(cacheKey); found {
		return cached, nil
	}

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for bucket: %w", err)
	}

	resp, err := client.HeadObjectWithContext(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(realBucket),
		Key:    aws.String(realKey),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to head object: %w", err)
	}

	metadata := make(map[string]string)
	for k, v := range resp.Metadata {
		if v != nil {
			metadata[k] = *v
		}
	}

	info := &ObjectInfo{
		Key:          key,
		Size:         aws.Int64Value(resp.ContentLength),
		ETag:         aws.StringValue(resp.ETag),
		LastModified: aws.TimeValue(resp.LastModified),
		StorageClass: aws.StringValue(resp.StorageClass),
		Metadata:     metadata,
	}

	s.metadataCache.Set(cacheKey, info)

	return info, nil
}

func (s *S3Backend) GetObjectACL(ctx context.Context, bucket, key string) (*ACL, error) {
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for bucket: %w", err)
	}

	resp, err := client.GetObjectAclWithContext(ctx, &s3.GetObjectAclInput{
		Bucket: aws.String(realBucket),
		Key:    aws.String(realKey),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object ACL: %w", err)
	}

	acl := &ACL{
		Owner: Owner{
			ID:          aws.StringValue(resp.Owner.ID),
			DisplayName: aws.StringValue(resp.Owner.DisplayName),
		},
		Grants: make([]Grant, 0, len(resp.Grants)),
	}

	for _, g := range resp.Grants {
		grant := Grant{
			Permission: aws.StringValue(g.Permission),
		}

		if g.Grantee != nil {
			grant.Grantee = Grantee{
				Type:        aws.StringValue(g.Grantee.Type),
				ID:          aws.StringValue(g.Grantee.ID),
				DisplayName: aws.StringValue(g.Grantee.DisplayName),
				URI:         aws.StringValue(g.Grantee.URI),
			}
		}

		acl.Grants = append(acl.Grants, grant)
	}

	return acl, nil
}

func (s *S3Backend) PutObjectACL(ctx context.Context, bucket, key string, acl *ACL) error {
	// For simplicity, we'll just acknowledge the request
	// A full implementation would convert the ACL to S3 format
	return nil
}

func (s *S3Backend) InitiateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	// logrus.WithFields(logrus.Fields{
	// 	"bucket":   bucket,
	// 	"key":      key,
	// 	"metadata": metadata,
	// }).Debug("Initiating multipart upload")

	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(realBucket),
		Key:    aws.String(realKey),
	}

	if len(metadata) > 0 {
		input.Metadata = make(map[string]*string)
		for k, v := range metadata {
			input.Metadata[k] = aws.String(v)
		}
	}

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return "", fmt.Errorf("failed to get client for bucket: %w", err)
	}

	resp, err := client.CreateMultipartUploadWithContext(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to initiate multipart upload: %w", err)
	}

	uploadID := aws.StringValue(resp.UploadId)

	return uploadID, nil
}

func (s *S3Backend) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, reader io.Reader, size int64) (string, error) {
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read part data: %w", err)
	}

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return "", fmt.Errorf("failed to get client for bucket: %w", err)
	}

	resp, err := client.UploadPartWithContext(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(realBucket),
		Key:           aws.String(realKey),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int64(int64(partNumber)),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload part: %w", err)
	}

	return aws.StringValue(resp.ETag), nil
}

func (s *S3Backend) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart) error {
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	completedParts := make([]*s3.CompletedPart, len(parts))
	for i, p := range parts {
		completedParts[i] = &s3.CompletedPart{
			PartNumber: aws.Int64(int64(p.PartNumber)),
			ETag:       aws.String(p.ETag),
		}
	}

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return fmt.Errorf("failed to get client for bucket: %w", err)
	}

	_, err = client.CompleteMultipartUploadWithContext(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(realBucket),
		Key:      aws.String(realKey),
		UploadId: aws.String(uploadID),
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	return nil
}

func (s *S3Backend) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return fmt.Errorf("failed to get client for bucket: %w", err)
	}

	_, err = client.AbortMultipartUploadWithContext(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(realBucket),
		Key:      aws.String(realKey),
		UploadId: aws.String(uploadID),
	})
	if err != nil {
		return fmt.Errorf("failed to abort multipart upload: %w", err)
	}
	return nil
}

func (s *S3Backend) ListParts(ctx context.Context, bucket, key, uploadID string, maxParts int, partNumberMarker int) (*ListPartsResult, error) {
	virtualBucket := bucket // Keep track of the virtual bucket name
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)

	input := &s3.ListPartsInput{
		Bucket:   aws.String(realBucket),
		Key:      aws.String(realKey),
		UploadId: aws.String(uploadID),
		MaxParts: aws.Int64(int64(maxParts)),
	}

	if partNumberMarker > 0 {
		input.PartNumberMarker = aws.Int64(int64(partNumberMarker))
	}

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for bucket: %w", err)
	}

	resp, err := client.ListPartsWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list parts: %w", err)
	}

	result := &ListPartsResult{
		Bucket:      virtualBucket, // Return the virtual bucket name to the client
		Key:         key,
		UploadID:    uploadID,
		IsTruncated: aws.BoolValue(resp.IsTruncated),
		Parts:       make([]Part, 0, len(resp.Parts)),
	}

	for _, p := range resp.Parts {
		result.Parts = append(result.Parts, Part{
			PartNumber:   int(aws.Int64Value(p.PartNumber)),
			ETag:         aws.StringValue(p.ETag),
			Size:         aws.Int64Value(p.Size),
			LastModified: aws.TimeValue(p.LastModified),
		})
	}

	if resp.NextPartNumberMarker != nil {
		result.NextPartNumberMarker = int(aws.Int64Value(resp.NextPartNumberMarker))
	}

	return result, nil
}

func (s *S3Backend) putObjectMultipart(ctx context.Context, virtualBucket, realBucket, key string, reader io.Reader, metadata map[string]string) error {
	client, err := s.getClientForBucket(virtualBucket)
	if err != nil {
		return fmt.Errorf("failed to get client for bucket: %w", err)
	}

	realKey := s.addPrefixToKey(virtualBucket, key)

	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(realBucket),
		Key:    aws.String(realKey),
	}

	// Handle KMS encryption headers
	kmsHeaders := make(map[string]string)
	if len(metadata) > 0 {
		input.Metadata = make(map[string]*string)
		for k, v := range metadata {
			// Extract KMS headers from metadata
			if strings.HasPrefix(k, "x-amz-server-side-encryption") {
				kmsHeaders[k] = v
			} else {
				input.Metadata[k] = aws.String(v)
			}
		}
	}

	// Apply KMS encryption settings
	if encryption, ok := kmsHeaders["x-amz-server-side-encryption"]; ok && encryption == "aws:kms" {
		input.ServerSideEncryption = aws.String("aws:kms")
		if keyID, ok := kmsHeaders["x-amz-server-side-encryption-aws-kms-key-id"]; ok {
			input.SSEKMSKeyId = aws.String(keyID)
		}
	}

	resp, err := client.CreateMultipartUploadWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to initiate multipart upload: %w", err)
	}

	uploadID := resp.UploadId

	multipartPartSize := int64(partSize)

	var parts []*s3.CompletedPart
	partNumber := int64(1)

	buf := make([]byte, multipartPartSize)
	for {
		n, readErr := io.ReadFull(reader, buf)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			_, _ = client.AbortMultipartUploadWithContext(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(realBucket),
				Key:      aws.String(realKey),
				UploadId: uploadID,
			})
			return fmt.Errorf("failed to read part: %w", readErr)
		}

		if n == 0 {
			break
		}

		partInput := &s3.UploadPartInput{
			Bucket:     aws.String(realBucket),
			Key:        aws.String(realKey),
			UploadId:   uploadID,
			PartNumber: aws.Int64(partNumber),
			Body:       bytes.NewReader(buf[:n]),
		}

		partResp, uploadErr := client.UploadPartWithContext(ctx, partInput)
		if uploadErr != nil {
			_, _ = client.AbortMultipartUploadWithContext(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(realBucket),
				Key:      aws.String(realKey),
				UploadId: uploadID,
			})
			return fmt.Errorf("failed to upload part %d: %w", partNumber, uploadErr)
		}

		parts = append(parts, &s3.CompletedPart{
			ETag:       partResp.ETag,
			PartNumber: aws.Int64(partNumber),
		})

		partNumber++

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(realBucket),
		Key:      aws.String(realKey),
		UploadId: uploadID,
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: parts,
		},
	}

	_, err = client.CompleteMultipartUploadWithContext(ctx, completeInput)
	if err != nil {
		return fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	// Invalidate cache
	s.metadataCache.Delete(fmt.Sprintf("%s/%s", virtualBucket, key))

	return nil
}
