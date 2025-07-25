package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

const (
	multipartThreshold = 10 * 1024 * 1024  // 10MB - use multipart early to avoid large single uploads
	partSize           = 5 * 1024 * 1024   // 5MB - smaller parts to avoid timeouts
	maxPartSize        = 10 * 1024 * 1024  // 10MB - keep parts small for reliability
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
	// Track problematic servers for resilient upload
	problematicServers map[string]*serverStatus
	serverMu          sync.RWMutex
}

type serverStatus struct {
	endpoint        string
	failureCount    int
	lastFailure     time.Time
	useResilient    bool
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

	logrus.WithFields(logrus.Fields{
		"clientKey": clientKey,
		"region":    bucketCfg.Region,
		"endpoint":  bucketCfg.Endpoint,
	}).Debug("Getting or creating S3 client")

	s.mu.RLock()
	if client, ok := s.clients[clientKey]; ok {
		s.mu.RUnlock()
		// Skip validation if we've validated recently
		// This prevents excessive validation calls
		return client, nil
	} else {
		s.mu.RUnlock()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if client, ok := s.clients[clientKey]; ok {
		// Client already exists, return it
		return client, nil
	}

	// Use faster timeouts for better responsiveness
	dialTimeout := 5 * time.Second
	if bucketCfg.Region == "me-central-1" {
		dialTimeout = 10 * time.Second // Slightly longer for ME region
	}

	// Reduce retries and timeout for better responsiveness
	maxRetries := 2
	httpTimeout := 30 * time.Second
	if bucketCfg.Region == "me-central-1" {
		maxRetries = 3 // Slightly more for problematic region
		httpTimeout = 60 * time.Second
	}
	
	awsConfig := &aws.Config{
		Region:           aws.String(bucketCfg.Region),
		S3ForcePathStyle: aws.Bool(s.config.UsePathStyle),
		MaxRetries:       aws.Int(maxRetries),
		HTTPClient: &http.Client{
			Timeout: httpTimeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   dialTimeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          100,   // Increase for better performance
				MaxIdleConnsPerHost:   10,    // Allow more connections per host
				MaxConnsPerHost:       20,    // Allow more concurrent operations
				IdleConnTimeout:       90 * time.Second,
				DisableKeepAlives:     false,
				TLSHandshakeTimeout:   10 * time.Second, // Reduce for faster failure
				ExpectContinueTimeout: 2 * time.Second,  // Reduce for faster failure
				ForceAttemptHTTP2:     false, // Disable HTTP/2 for better compatibility
				WriteBufferSize:       256 * 1024,  // 256KB - larger buffers for multipart uploads
				ReadBufferSize:        256 * 1024,  // 256KB - better throughput for large transfers
			},
		},
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

	var sess *session.Session
	var err error

	if s.config.Profile != "" {
		sess, err = session.NewSessionWithOptions(session.Options{
			Config:            *awsConfig,
			Profile:           s.config.Profile,
			SharedConfigState: session.SharedConfigEnable,
		})
	} else {
		sess, err = session.NewSession(awsConfig)
	}
	
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
		HTTPClient: &http.Client{
			Timeout: 300 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:          100,   // Increase for better performance
				MaxIdleConnsPerHost:   10,    // Allow more connections per host
				MaxConnsPerHost:       20,    // Allow more concurrent operations
				IdleConnTimeout:       90 * time.Second,
				DisableKeepAlives:     false,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ForceAttemptHTTP2:     false, // Disable HTTP/2 for better compatibility
				WriteBufferSize:       256 * 1024,  // 256KB - larger buffers for multipart uploads
				ReadBufferSize:        256 * 1024,  // 256KB - better throughput for large transfers
			},
		},
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
				buf := make([]byte, 64*1024) // 64KB buffers for better performance
				return &buf
			},
		},
		largeBufferPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, partSize) // 16MB buffers to match part size
				return &buf
			},
		},
		metadataCache: &MetadataCache{
			cache: make(map[string]*cachedMetadata),
			ttl:   30 * time.Second,
		},
		problematicServers: make(map[string]*serverStatus),
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
	
	// For critical Iceberg metadata files, use a shorter timeout
	if strings.Contains(key, "metadata.json") || strings.Contains(key, "_expectations") {
		// Create a context with timeout for metadata operations
		timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		ctx = timeoutCtx
		
		logrus.WithFields(logrus.Fields{
			"key": key,
			"timeout": "10s",
		}).Debug("Using short timeout for metadata operation")
	}

	var body io.ReadSeeker
	if rs, ok := reader.(io.ReadSeeker); ok {
		body = rs
	} else {
		// Handle different size scenarios
		if size < 0 {
			// Size unknown - use multipart upload for streaming
			logrus.WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
			}).Info("Size unknown, using multipart upload for streaming")
			return s.putObjectMultipart(ctx, bucket, realBucket, key, reader, metadata)
		} else if size <= multipartThreshold {
			// Small file - buffer and use regular PUT
			logrus.WithFields(logrus.Fields{
				"key": key,
				"size": size,
				"threshold": multipartThreshold,
			}).Debug("Using regular PUT for small file")
			
			data, err := io.ReadAll(reader)
			if err != nil {
				return fmt.Errorf("failed to read data: %w", err)
			}
			body = bytes.NewReader(data)
		} else {
			// Large file - use multipart
			// Check if we should use resilient uploader
			if s.shouldUseResilientUpload(bucket) {
				client, err := s.getClientForBucket(bucket)
				if err != nil {
					return fmt.Errorf("failed to get client for bucket: %w", err)
				}
				logrus.WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    key,
					"size":   size,
				}).Info("Using resilient uploader for problematic server")
				return s.putObjectMultipartResilient(ctx, bucket, key, reader, size, client)
			}
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

	// Debug: Log what we're about to do
	logrus.WithFields(logrus.Fields{
		"bucket": realBucket,
		"key": realKey,
		"size": size,
		"hasBody": input.Body != nil,
		"metadata": input.Metadata,
	}).Info("About to call S3 PutObject")
	
	// Time the actual S3 PUT operation
	s3Start := time.Now()
	
	output, err := client.PutObjectWithContext(ctx, input)
	
	s3Duration := time.Since(s3Start)
	
	logrus.WithFields(logrus.Fields{
		"duration": s3Duration,
		"bucket": realBucket,
		"key": realKey,
		"size": size,
		"error": err,
		"etag": output.ETag,
	}).Info("S3 PutObject completed")
	
	if s3Duration > 5*time.Second {
		logrus.WithFields(logrus.Fields{
			"duration": s3Duration,
			"bucket": realBucket,
			"key": realKey,
			"size": size,
		}).Warn("S3 PutObject took too long")
	}
	
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

	client, err := s.getClientForBucket(bucket)
	if err != nil {
		return "", fmt.Errorf("failed to get client for bucket: %w", err)
	}

	// Log upload start
	logrus.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"partNumber": partNumber,
		"size":       size,
	}).Debug("Starting part upload to S3")

	// AWS SDK requires io.ReadSeeker for uploads
	// For streaming uploads, we need to implement a buffered approach
	var body io.ReadSeeker
	
	if rs, ok := reader.(io.ReadSeeker); ok {
		body = rs
	} else {
		// For non-seekable readers, we need to provide a seekable interface
		limitedReader := io.LimitReader(reader, size)
		
		// For small parts (<= 10MB), buffer in memory for best performance
		if size <= 10*1024*1024 {
			data, err := io.ReadAll(limitedReader)
			if err != nil {
				return "", fmt.Errorf("failed to read part data: %w", err)
			}
			body = bytes.NewReader(data)
		} else {
			// For larger parts, use buffered seeker that can handle retries
			logrus.WithFields(logrus.Fields{
				"size":       size,
				"sizeMB":     size / 1024 / 1024,
				"partNumber": partNumber,
			}).Info("Large part detected - using buffered seeker")
			
			// For very large parts from slow clients, we need special handling
			logrus.WithFields(logrus.Fields{
				"size":       size,
				"sizeMB":     size / 1024 / 1024,
				"partNumber": partNumber,
			}).Warn("Large part upload detected - using minimal buffering approach")
			
			// Don't use BufferedSeeker for huge parts - it still tries to buffer too much
			// Instead, fail fast if AWS SDK needs to retry
			// This is better than timing out after 60 seconds
			data, err := io.ReadAll(limitedReader)
			if err != nil {
				return "", fmt.Errorf("failed to read large part data: %w", err)
			}
			body = bytes.NewReader(data)
		}
	}
	
	// Upload with proper timeout handling
	uploadCtx := ctx
	if size > 1024*1024 { // For parts > 1MB, ensure reasonable timeout
		var cancel context.CancelFunc
		uploadCtx, cancel = context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
	}
	
	startTime := time.Now()
	resp, err := client.UploadPartWithContext(uploadCtx, &s3.UploadPartInput{
		Bucket:        aws.String(realBucket),
		Key:           aws.String(realKey),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int64(int64(partNumber)),
		Body:          body,
		ContentLength: aws.Int64(size),
	})
	
	uploadDuration := time.Since(startTime)
	
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"duration":   uploadDuration,
			"partNumber": partNumber,
			"size":       size,
		}).Error("Failed to upload part to S3")
		return "", fmt.Errorf("failed to upload part: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"duration":   uploadDuration,
		"partNumber": partNumber,
		"size":       size,
		"etag":       aws.StringValue(resp.ETag),
	}).Debug("Successfully uploaded part to S3")

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

// putObjectMultipartStreaming handles streaming uploads with small parts
func (s *S3Backend) putObjectMultipartStreaming(ctx context.Context, virtualBucket, realBucket, key string, reader io.Reader, metadata map[string]string) error {
	realKey := s.addPrefixToKey(virtualBucket, key)
	
	client, err := s.getClientForBucket(virtualBucket)
	if err != nil {
		return fmt.Errorf("failed to get client for bucket: %w", err)
	}
	
	// Initiate multipart upload
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
	
	resp, err := client.CreateMultipartUploadWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to initiate multipart upload: %w", err)
	}
	
	uploadID := aws.StringValue(resp.UploadId)
	
	// Use streaming handler with small parts
	handler := NewStreamingMultipartHandler(client, realBucket, realKey, uploadID)
	parts, err := handler.HandleStreamingUpload(ctx, reader)
	
	if err != nil {
		// Abort the upload on error
		abortErr := s.AbortMultipartUpload(ctx, virtualBucket, key, uploadID)
		if abortErr != nil {
			logrus.WithError(abortErr).Error("Failed to abort multipart upload after error")
		}
		return fmt.Errorf("streaming upload failed: %w", err)
	}
	
	// Complete the upload
	completedParts := make([]*s3.CompletedPart, len(parts))
	for i, p := range parts {
		completedParts[i] = &s3.CompletedPart{
			PartNumber: aws.Int64(int64(p.PartNumber)),
			ETag:       aws.String(p.ETag),
		}
	}
	
	_, completeErr := client.CompleteMultipartUploadWithContext(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(realBucket),
		Key:      aws.String(realKey),
		UploadId: aws.String(uploadID),
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	
	if completeErr != nil {
		// Try to abort if completion fails
		abortErr := s.AbortMultipartUpload(ctx, virtualBucket, key, uploadID)
		if abortErr != nil {
			logrus.WithError(abortErr).Error("Failed to abort after completion error")
		}
		return fmt.Errorf("failed to complete streaming upload: %w", completeErr)
	}
	
	return nil
}

func (s *S3Backend) putObjectMultipart(ctx context.Context, virtualBucket, realBucket, key string, reader io.Reader, metadata map[string]string) error {
	// Check if we're dealing with a streaming upload (size unknown)
	if _, ok := reader.(*SmartChunkDecoder); ok {
		logrus.WithFields(logrus.Fields{
			"bucket": virtualBucket,
			"key":    key,
		}).Warn("Detected streaming upload - using small parts to avoid timeouts")
		
		// For streaming uploads, use the streaming handler with small parts
		return s.putObjectMultipartStreaming(ctx, virtualBucket, realBucket, key, reader, metadata)
	}
	
	// Use concurrent uploads with a worker pool
	const maxConcurrentUploads = 8 // Increased for better throughput
	
	// For now use default part size since we might not know total size
	// TODO: In the future, we could implement dynamic part sizing based on file size
	actualPartSize := partSize
	type partData struct {
		partNumber int64
		data       []byte
		bufPtr     *[]byte // Store buffer pointer for cleanup
	}
	
	type uploadResult struct {
		partNumber int64
		etag       string
		err        error
	}
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

	partChan := make(chan partData, maxConcurrentUploads)
	resultChan := make(chan uploadResult, maxConcurrentUploads*2)
	
	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrentUploads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for part := range partChan {
				partInput := &s3.UploadPartInput{
					Bucket:        aws.String(realBucket),
					Key:           aws.String(realKey),
					UploadId:      uploadID,
					PartNumber:    aws.Int64(part.partNumber),
					Body:          bytes.NewReader(part.data),
					ContentLength: aws.Int64(int64(len(part.data))),
				}
				
				resp, err := client.UploadPartWithContext(ctx, partInput)
				
				// Return buffer to pool after upload
				if part.bufPtr != nil {
					if len(*part.bufPtr) <= 64*1024 {
						s.bufferPool.Put(part.bufPtr)
					} else {
						s.largeBufferPool.Put(part.bufPtr)
					}
				}
				
				if err != nil {
					resultChan <- uploadResult{partNumber: part.partNumber, err: err}
					return
				}
				
				resultChan <- uploadResult{
					partNumber: part.partNumber,
					etag:       aws.StringValue(resp.ETag),
					err:        nil,
				}
			}
		}()
	}

	// Result collector goroutine
	parts := make(map[int64]*s3.CompletedPart)
	var uploadErr error
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Reader goroutine
	go func() {
		defer close(partChan)
		
		partNumber := int64(1)
		bufSize := actualPartSize
		
		logrus.WithFields(logrus.Fields{
			"partSize": bufSize,
			"bucket":   virtualBucket,
			"key":      key,
		}).Info("Starting multipart reader goroutine")
		
		// Use appropriate buffer pool based on part size
		var bufPtr *[]byte
		var buf []byte
		if bufSize <= 5*1024*1024 {
			bufPtr = s.largeBufferPool.Get().(*[]byte)
			defer s.largeBufferPool.Put(bufPtr)
			buf = (*bufPtr)[:bufSize]
		} else {
			// For very large parts, allocate directly
			buf = make([]byte, bufSize)
		}
		
		totalBytesRead := int64(0)
		
		for {
			// Dynamic buffer sizing for small files
			readSize := int(bufSize)
			if len(buf) < readSize {
				readSize = len(buf)
			}
			
			readStart := time.Now()
			logrus.WithFields(logrus.Fields{
				"partNumber": partNumber,
				"readSize":   readSize,
			}).Debug("Attempting to read part data")
			
			// Use io.ReadAtLeast instead of io.ReadFull to handle partial reads better
			n, readErr := io.ReadAtLeast(reader, buf[:readSize], 1)
			readDuration := time.Since(readStart)
			
			logrus.WithFields(logrus.Fields{
				"partNumber": partNumber,
				"bytesRead":  n,
				"duration":   readDuration,
				"error":      readErr,
			}).Debug("Part data read completed")
			
			if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
				logrus.WithError(readErr).Error("Failed to read part data")
				uploadErr = fmt.Errorf("failed to read part: %w", readErr)
				return
			}
			
			if n == 0 {
				break
			}
			
			totalBytesRead += int64(n)
			
			// Copy data to avoid race conditions
			// Use buffer pool for part data
			var data []byte
			var dataPtr *[]byte
			if n <= 64*1024 { // 64KB - use small buffer pool
				dataPtr = s.bufferPool.Get().(*[]byte)
				data = (*dataPtr)[:n]
				copy(data, buf[:n])
			} else if n <= partSize { // Use large buffer pool for parts up to part size
				dataPtr = s.largeBufferPool.Get().(*[]byte)
				data = (*dataPtr)[:n]
				copy(data, buf[:n])
			} else {
				data = make([]byte, n)
				copy(data, buf[:n])
			}
			
			logrus.WithFields(logrus.Fields{
				"partNumber":     partNumber,
				"partSize":       n,
				"totalBytesRead": totalBytesRead,
			}).Debug("Sending part to upload queue")
			
			select {
			case partChan <- partData{partNumber: partNumber, data: data, bufPtr: dataPtr}:
				partNumber++
			case <-ctx.Done():
				logrus.WithError(ctx.Err()).Error("Context cancelled while sending part")
				uploadErr = ctx.Err()
				return
			}
			
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				logrus.WithField("totalBytesRead", totalBytesRead).Info("Finished reading all data")
				break
			}
		}
	}()

	// Collect results
	for result := range resultChan {
		if result.err != nil {
			uploadErr = result.err
			break
		}
		parts[result.partNumber] = &s3.CompletedPart{
			ETag:       aws.String(result.etag),
			PartNumber: aws.Int64(result.partNumber),
		}
	}

	// Handle errors
	if uploadErr != nil {
		_, _ = client.AbortMultipartUploadWithContext(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(realBucket),
			Key:      aws.String(realKey),
			UploadId: uploadID,
		})
		// Mark server as problematic on upload errors
		s.markServerProblematic(virtualBucket, uploadErr)
		return uploadErr
	}

	// Sort parts by part number
	var sortedParts []*s3.CompletedPart
	for i := int64(1); i <= int64(len(parts)); i++ {
		if part, ok := parts[i]; ok {
			sortedParts = append(sortedParts, part)
		}
	}

	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(realBucket),
		Key:      aws.String(realKey),
		UploadId: uploadID,
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: sortedParts,
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

// getServerEndpoint gets the endpoint for a bucket
func (s *S3Backend) getServerEndpoint(bucket string) string {
	if s.bucketConfigs != nil {
		if cfg, ok := s.bucketConfigs[bucket]; ok && cfg.Endpoint != "" {
			return cfg.Endpoint
		}
	}
	if s.config.Endpoint != "" {
		return s.config.Endpoint
	}
	return "default"
}

// markServerProblematic marks a server as problematic
func (s *S3Backend) markServerProblematic(bucket string, err error) {
	endpoint := s.getServerEndpoint(bucket)
	
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	
	status, exists := s.problematicServers[endpoint]
	if !exists {
		status = &serverStatus{
			endpoint: endpoint,
		}
		s.problematicServers[endpoint] = status
	}
	
	status.failureCount++
	status.lastFailure = time.Now()
	
	// After 3 failures, mark for resilient upload
	if status.failureCount >= 3 {
		status.useResilient = true
		logrus.WithFields(logrus.Fields{
			"endpoint": endpoint,
			"failures": status.failureCount,
		}).Warn("Server marked for resilient upload due to repeated failures")
	}
}

// shouldUseResilientUpload checks if we should use resilient uploader
func (s *S3Backend) shouldUseResilientUpload(bucket string) bool {
	endpoint := s.getServerEndpoint(bucket)
	
	s.serverMu.RLock()
	defer s.serverMu.RUnlock()
	
	if status, exists := s.problematicServers[endpoint]; exists {
		// Reset after 1 hour of no failures
		if time.Since(status.lastFailure) > time.Hour {
			return false
		}
		return status.useResilient
	}
	
	return false
}

// putObjectMultipartResilient uses the resilient uploader for problematic servers
func (s *S3Backend) putObjectMultipartResilient(ctx context.Context, bucket, key string, reader io.Reader, size int64, client *s3.S3) error {
	// Note: When size is 0 or unknown, we'll read until EOF
	// The resilient uploader handles this by reading parts dynamically
	realBucket := s.mapBucket(bucket)
	realKey := s.addPrefixToKey(bucket, key)
	
	uploader := NewResilientUploader(client)
	uploader.config.ProgressCallback = func(uploaded, total int64) {
		percent := float64(uploaded) / float64(total) * 100
		logrus.WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploaded": uploaded,
			"total":    total,
			"percent":  percent,
		}).Debug("Resilient upload progress")
	}
	
	err := uploader.UploadWithRetry(ctx, realBucket, realKey, reader, size)
	if err != nil {
		s.markServerProblematic(bucket, err)
		return err
	}
	
	// Invalidate cache
	s.metadataCache.Delete(fmt.Sprintf("%s/%s", bucket, key))
	
	return nil
}
