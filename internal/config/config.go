// Package config provides configuration structures and loading functionality for the S3 proxy
package config

import (
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/spf13/viper"
)

// Config represents the main configuration structure for the S3 proxy
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	S3         S3Config         `mapstructure:"s3"`
	Storage    StorageConfig    `mapstructure:"storage"`
	Auth       AuthConfig       `mapstructure:"auth"`
	Encryption EncryptionConfig `mapstructure:"encryption"`
	Chunking   ChunkingConfig   `mapstructure:"chunking"`
}

// ServerConfig contains HTTP server configuration settings
type ServerConfig struct {
	Listen       string        `mapstructure:"listen" envconfig:"SERVER_LISTEN" default:":8080"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" envconfig:"SERVER_READ_TIMEOUT" default:"60s"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" envconfig:"SERVER_WRITE_TIMEOUT" default:"60s"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout" envconfig:"SERVER_IDLE_TIMEOUT" default:"120s"`
	MaxBodySize  int64         `mapstructure:"max_body_size" envconfig:"SERVER_MAX_BODY_SIZE" default:"5368709120"` // 5GB
}

// S3Config contains S3-specific configuration settings
type S3Config struct {
	Region               string `mapstructure:"region" envconfig:"S3_REGION" default:"us-east-1"`
	VirtualHost          bool   `mapstructure:"virtual_host" envconfig:"S3_VIRTUAL_HOST" default:"false"`
	PathStyle            bool   `mapstructure:"path_style" envconfig:"S3_PATH_STYLE" default:"true"`
	ServicePath          string `mapstructure:"service_path" envconfig:"S3_SERVICE_PATH" default:""`
	IgnoreUnknownHeaders bool   `mapstructure:"ignore_unknown_headers" envconfig:"S3_IGNORE_UNKNOWN_HEADERS" default:"true"`
}

// StorageConfig specifies the storage backend configuration
type StorageConfig struct {
	Provider   string              `mapstructure:"provider" envconfig:"STORAGE_PROVIDER" required:"true"`
	Azure      *AzureStorageConfig `mapstructure:"azure"`
	S3         *S3StorageConfig    `mapstructure:"s3"`
	FileSystem *FileSystemConfig   `mapstructure:"filesystem"`
}

// AzureStorageConfig contains Azure Blob Storage specific settings
type AzureStorageConfig struct {
	AccountName   string `mapstructure:"account_name" envconfig:"AZURE_ACCOUNT_NAME"`
	AccountKey    string `mapstructure:"account_key" envconfig:"AZURE_ACCOUNT_KEY"`
	ContainerName string `mapstructure:"container_name" envconfig:"AZURE_CONTAINER_NAME"`
	Endpoint      string `mapstructure:"endpoint" envconfig:"AZURE_ENDPOINT"`
	UseSAS        bool   `mapstructure:"use_sas" envconfig:"AZURE_USE_SAS" default:"false"`
	SASToken      string `mapstructure:"sas_token" envconfig:"AZURE_SAS_TOKEN"`
}

// S3StorageConfig contains S3 storage backend specific settings
type S3StorageConfig struct {
	Endpoint      string                   `mapstructure:"endpoint" envconfig:"S3_ENDPOINT"`
	Region        string                   `mapstructure:"region" envconfig:"S3_REGION" default:"us-east-1"`
	AccessKey     string                   `mapstructure:"access_key" envconfig:"S3_ACCESS_KEY"`
	SecretKey     string                   `mapstructure:"secret_key" envconfig:"S3_SECRET_KEY"`
	Profile       string                   `mapstructure:"profile" envconfig:"AWS_PROFILE"`
	UsePathStyle  bool                     `mapstructure:"use_path_style" envconfig:"S3_USE_PATH_STYLE" default:"true"`
	DisableSSL    bool                     `mapstructure:"disable_ssl" envconfig:"S3_DISABLE_SSL" default:"false"`
	BucketMapping map[string]string        `mapstructure:"bucket_mapping"` // Map virtual bucket names to real bucket names
	BucketConfigs map[string]*BucketConfig `mapstructure:"bucket_configs"` // Per-bucket configuration
}

// BucketConfig contains per-bucket configuration settings
type BucketConfig struct {
	RealName             string            `mapstructure:"real_name"`              // Real bucket name in S3
	Prefix               string            `mapstructure:"prefix"`                 // Optional prefix (subdirectory) within the bucket
	Region               string            `mapstructure:"region"`                 // AWS region for this bucket
	Endpoint             string            `mapstructure:"endpoint"`               // Optional custom endpoint for this bucket
	AccessKey            string            `mapstructure:"access_key"`             // Optional per-bucket access key
	SecretKey            string            `mapstructure:"secret_key"`             // Optional per-bucket secret key
	KMSKeyID             string            `mapstructure:"kms_key_id"`             // Optional KMS key for this bucket
	KMSEncryptionContext map[string]string `mapstructure:"kms_encryption_context"` // Optional encryption context
}

// FileSystemConfig contains filesystem storage backend settings
type FileSystemConfig struct {
	BaseDir string `mapstructure:"base_dir" envconfig:"FS_BASE_DIR" default:"/data"`
}

// AuthConfig specifies authentication configuration
type AuthConfig struct {
	Type       string `mapstructure:"type" envconfig:"AUTH_TYPE" default:"none"` // none, basic, awsv2, awsv4
	Identity   string `mapstructure:"identity" envconfig:"AUTH_IDENTITY"`
	Credential string `mapstructure:"credential" envconfig:"AUTH_CREDENTIAL"`
	// AWS-style environment variables (take precedence if set)
	AWSAccessKeyID     string `mapstructure:"-" envconfig:"AWS_ACCESS_KEY_ID"`
	AWSSecretAccessKey string `mapstructure:"-" envconfig:"AWS_SECRET_ACCESS_KEY"`
}

// EncryptionConfig specifies encryption settings
type EncryptionConfig struct {
	Enabled      bool                      `mapstructure:"enabled" envconfig:"ENCRYPTION_ENABLED" default:"false"`
	Algorithm    string                    `mapstructure:"algorithm" envconfig:"ENCRYPTION_ALGORITHM" default:"AES-256-GCM"`
	KeyProvider  string                    `mapstructure:"key_provider" envconfig:"ENCRYPTION_KEY_PROVIDER" default:"local"`
	Local        *LocalKeyConfig           `mapstructure:"local"`
	KMS          *KMSKeyConfig             `mapstructure:"kms"`
	AzureKV      *AzureKeyVaultConfig      `mapstructure:"azure_keyvault"`
	Custom       *CustomKeyConfig          `mapstructure:"custom"`
	KeyProviders map[string]ProviderConfig `mapstructure:"key_providers"` // Named providers for multi-provider support
	Policies     []EncryptionPolicy        `mapstructure:"policies"`
}

// LocalKeyConfig contains settings for local key management
type LocalKeyConfig struct {
	MasterKey string `mapstructure:"master_key" envconfig:"ENCRYPTION_LOCAL_MASTER_KEY"`
}

// KMSKeyConfig contains settings for AWS KMS key management
type KMSKeyConfig struct {
	Enabled           bool              `mapstructure:"enabled" envconfig:"KMS_ENABLED" default:"false"`
	DefaultKeyID      string            `mapstructure:"default_key_id" envconfig:"KMS_DEFAULT_KEY_ID"`
	KeySpec           string            `mapstructure:"key_spec" envconfig:"KMS_KEY_SPEC" default:"AES_256"`
	Region            string            `mapstructure:"region" envconfig:"KMS_REGION"`
	EncryptionContext map[string]string `mapstructure:"encryption_context"`
	DataKeyCacheTTL   string            `mapstructure:"data_key_cache_ttl" envconfig:"KMS_DATA_KEY_CACHE_TTL" default:"5m"`
	ValidateKeys      bool              `mapstructure:"validate_keys" envconfig:"KMS_VALIDATE_KEYS" default:"true"`
	EnableKeyRotation bool              `mapstructure:"enable_key_rotation" envconfig:"KMS_ENABLE_KEY_ROTATION" default:"false"`
}

// AzureKeyVaultConfig contains settings for Azure Key Vault
type AzureKeyVaultConfig struct {
	VaultURL        string `mapstructure:"vault_url" envconfig:"AZURE_KV_VAULT_URL"`
	ClientID        string `mapstructure:"client_id" envconfig:"AZURE_CLIENT_ID"`
	ClientSecret    string `mapstructure:"client_secret" envconfig:"AZURE_CLIENT_SECRET"`
	TenantID        string `mapstructure:"tenant_id" envconfig:"AZURE_TENANT_ID"`
	KeySize         int    `mapstructure:"key_size" envconfig:"AZURE_KV_KEY_SIZE" default:"256"`
	DataKeyCacheTTL string `mapstructure:"data_key_cache_ttl" envconfig:"AZURE_KV_DATA_KEY_CACHE_TTL" default:"5m"`
}

// CustomKeyConfig contains settings for custom key provider
type CustomKeyConfig struct {
	MasterKey         string `mapstructure:"master_key" envconfig:"CUSTOM_MASTER_KEY"`
	MasterKeyFile     string `mapstructure:"master_key_file" envconfig:"CUSTOM_MASTER_KEY_FILE"`
	KeyDerivationSalt string `mapstructure:"key_derivation_salt" envconfig:"CUSTOM_KEY_DERIVATION_SALT"`
	DataKeyCacheTTL   string `mapstructure:"data_key_cache_ttl" envconfig:"CUSTOM_DATA_KEY_CACHE_TTL" default:"5m"`
}

// ProviderConfig represents a generic provider configuration
type ProviderConfig struct {
	Type   string                 `mapstructure:"type"` // aws-kms, azure-keyvault, custom, local
	Config map[string]interface{} `mapstructure:"config"`
}

// EncryptionPolicy defines bucket-specific encryption policies
type EncryptionPolicy struct {
	BucketPattern string `mapstructure:"bucket_pattern"`
	Algorithm     string `mapstructure:"algorithm"`
	KeyProvider   string `mapstructure:"key_provider"`
	Mandatory     bool   `mapstructure:"mandatory"`
}

// Load reads and validates configuration from a file
func Load(configFile string) (*Config, error) {
	cfg := &Config{}

	if configFile != "" {
		viper.SetConfigFile(configFile)
		if err := viper.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		if err := viper.Unmarshal(cfg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	if err := envconfig.Process("", cfg); err != nil {
		return nil, fmt.Errorf("failed to process env vars: %w", err)
	}

	// AWS environment variables take precedence
	if cfg.Auth.AWSAccessKeyID != "" {
		cfg.Auth.Identity = cfg.Auth.AWSAccessKeyID
	}
	if cfg.Auth.AWSSecretAccessKey != "" {
		cfg.Auth.Credential = cfg.Auth.AWSSecretAccessKey
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

func validate(cfg *Config) error {
	if cfg.Storage.Provider == "" {
		return fmt.Errorf("storage provider is required")
	}

	switch cfg.Storage.Provider {
	case "azure", "azureblob":
		if cfg.Storage.Azure == nil {
			return fmt.Errorf("azure storage config is required")
		}
		if cfg.Storage.Azure.AccountName == "" || cfg.Storage.Azure.AccountKey == "" {
			if !cfg.Storage.Azure.UseSAS || cfg.Storage.Azure.SASToken == "" {
				return fmt.Errorf("azure account name and key or SAS token are required")
			}
		}
	case "s3":
		if cfg.Storage.S3 == nil {
			return fmt.Errorf("s3 storage config is required")
		}
		// When using AWS profile or IAM roles, explicit credentials are not required
		// Allow the SDK to use its credential chain (env vars, IAM role, etc.)
		// Only validate if we're using a custom endpoint (MinIO, etc.)
		if cfg.Storage.S3.Endpoint != "" {
			// For custom endpoints, we need explicit credentials
			if cfg.Storage.S3.Profile == "" && cfg.Storage.S3.AccessKey == "" && cfg.Storage.S3.SecretKey == "" {
				return fmt.Errorf("s3 credentials are required for custom endpoint: specify profile or access/secret keys")
			}
		}
		// For real AWS, credentials are optional - can use IAM roles
	case "filesystem":
		if cfg.Storage.FileSystem == nil {
			return fmt.Errorf("filesystem storage config is required")
		}
	default:
		return fmt.Errorf("unsupported storage provider: %s", cfg.Storage.Provider)
	}

	return nil
}
