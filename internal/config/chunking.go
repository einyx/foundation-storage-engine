package config

// ChunkingConfig holds configuration for AWS V4 streaming chunk handling
type ChunkingConfig struct {
	// Security options
	VerifySignatures     bool  `yaml:"verify_signatures" default:"false"`
	RequireChunkedUpload bool  `yaml:"require_chunked_upload" default:"false"`
	MaxChunkSize         int64 `yaml:"max_chunk_size" default:"1048576"`  // 1MB
	RequestTimeWindow    int   `yaml:"request_time_window" default:"300"` // 5 minutes

	// Verification modes
	LogOnlyMode bool `yaml:"log_only_mode" default:"true"` // Log errors but don't reject

	// Storage options
	StoreChunkedFormat bool `yaml:"store_chunked_format" default:"false"`

	// Response options
	PreserveChunkedResponse bool `yaml:"preserve_chunked_response" default:"false"`
	ChunkResponseSize       int  `yaml:"chunk_response_size" default:"65536"` // 64KB
}
