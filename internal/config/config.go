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
	Database   DatabaseConfig   `mapstructure:"database"`
	Encryption EncryptionConfig `mapstructure:"encryption"`
	Chunking   ChunkingConfig   `mapstructure:"chunking"`
	UI         UIConfig         `mapstructure:"ui"`
	Auth0      Auth0Config      `mapstructure:"auth0"`
	VirusTotal VirusTotalConfig `mapstructure:"virustotal"`
	ShareLinks ShareLinksConfig `mapstructure:"share_links"`
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
	Sentry     SentryConfig     `mapstructure:"sentry"`
	OPA        OPAConfig        `mapstructure:"opa"`
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

// UIConfig contains web UI configuration settings
type UIConfig struct {
	Enabled    bool   `mapstructure:"enabled" envconfig:"UI_ENABLED" default:"false"`
	StaticPath string `mapstructure:"static_path" envconfig:"UI_STATIC_PATH" default:"./web"`
	BasePath   string `mapstructure:"base_path" envconfig:"UI_BASE_PATH" default:"/ui"`
}

// Auth0Config contains Auth0 configuration settings
type Auth0Config struct {
	Enabled           bool              `mapstructure:"enabled" envconfig:"AUTH0_ENABLED" default:"false"`
	Domain            string            `mapstructure:"domain" envconfig:"AUTH0_DOMAIN"`
	ClientID          string            `mapstructure:"client_id" envconfig:"AUTH0_CLIENT_ID"`
	ClientSecret      string            `mapstructure:"client_secret" envconfig:"AUTH0_CLIENT_SECRET"`
	RedirectURI       string            `mapstructure:"redirect_uri" envconfig:"AUTH0_REDIRECT_URI" default:"/api/auth/callback"`
	LogoutURI         string            `mapstructure:"logout_uri" envconfig:"AUTH0_LOGOUT_URI" default:"/ui/login.html"`
	SessionKey        string            `mapstructure:"session_key" envconfig:"AUTH0_SESSION_KEY"`
	Audience          string            `mapstructure:"audience" envconfig:"AUTH0_AUDIENCE"`
	Scopes            []string          `mapstructure:"scopes" envconfig:"AUTH0_SCOPES" default:"openid,profile,email"`
	JWTValidation     bool              `mapstructure:"jwt_validation" envconfig:"AUTH0_JWT_VALIDATION" default:"true"`
	PermissionMapping map[string]string `mapstructure:"permission_mapping"`
	SessionTimeout    time.Duration     `mapstructure:"session_timeout" envconfig:"AUTH0_SESSION_TIMEOUT" default:"24h"`
	TokenCacheTTL     time.Duration     `mapstructure:"token_cache_ttl" envconfig:"AUTH0_TOKEN_CACHE_TTL" default:"5m"`
	EnablePKCE        bool              `mapstructure:"enable_pkce" envconfig:"AUTH0_ENABLE_PKCE" default:"true"`
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
	AccountName      string                      `mapstructure:"account_name" envconfig:"AZURE_ACCOUNT_NAME"`
	AccountKey       string                      `mapstructure:"account_key" envconfig:"AZURE_ACCOUNT_KEY"`
	ContainerName    string                      `mapstructure:"container_name" envconfig:"AZURE_CONTAINER_NAME"`
	Endpoint         string                      `mapstructure:"endpoint" envconfig:"AZURE_ENDPOINT"`
	UseSAS           bool                        `mapstructure:"use_sas" envconfig:"AZURE_USE_SAS" default:"false"`
	SASToken         string                      `mapstructure:"sas_token" envconfig:"AZURE_SAS_TOKEN"`
	ContainerConfigs map[string]*ContainerConfig `mapstructure:"container_configs"` // Per-container configuration
}

// ContainerConfig contains per-container configuration settings for Azure
type ContainerConfig struct {
	ContainerName string `mapstructure:"container_name"` // Real container name in Azure
	Prefix        string `mapstructure:"prefix"`         // Optional prefix (subdirectory) within the container
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
	Type       string     `mapstructure:"type" envconfig:"AUTH_TYPE" default:"none"` // none, basic, awsv2, awsv4, database
	Identity   string     `mapstructure:"identity" envconfig:"AUTH_IDENTITY"`
	Credential string     `mapstructure:"credential" envconfig:"AUTH_CREDENTIAL"`
	AWSV4      *AWSV4Auth `mapstructure:"aws_v4"`
	// AWS-style environment variables (take precedence if set)
	AWSAccessKeyID     string `mapstructure:"-" envconfig:"AWS_ACCESS_KEY_ID"`
	AWSSecretAccessKey string `mapstructure:"-" envconfig:"AWS_SECRET_ACCESS_KEY"`
}

// AWSV4Auth contains AWS V4 specific authentication configuration
type AWSV4Auth struct {
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
	Region    string `mapstructure:"region"`
}

// DatabaseConfig specifies database configuration for authentication
type DatabaseConfig struct {
	Enabled          bool          `mapstructure:"enabled" envconfig:"DB_ENABLED" default:"false"`
	Driver           string        `mapstructure:"driver" envconfig:"DB_DRIVER" default:"postgres"`
	ConnectionString string        `mapstructure:"connection_string" envconfig:"DB_CONNECTION_STRING"`
	MaxOpenConns     int           `mapstructure:"max_open_conns" envconfig:"DB_MAX_OPEN_CONNS" default:"25"`
	MaxIdleConns     int           `mapstructure:"max_idle_conns" envconfig:"DB_MAX_IDLE_CONNS" default:"5"`
	ConnMaxLifetime  time.Duration `mapstructure:"conn_max_lifetime" envconfig:"DB_CONN_MAX_LIFETIME" default:"5m"`
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

// Load reads and validates configuration from a file or environment variables.
// If configFile is empty, only environment variables are processed.
// Returns a validated Config struct or an error if validation fails.
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

	// For awsv4 auth type, populate Identity/Credential from nested aws_v4 structure if not already set
	if cfg.Auth.Type == "awsv4" {
		fmt.Printf("DEBUG: Auth type is awsv4, AWSV4 config detected\n")
		if cfg.Auth.AWSV4 != nil {
			fmt.Printf("DEBUG: Found aws_v4 config - AccessKey: '%s', SecretKey: [REDACTED]\n", maskCredential(cfg.Auth.AWSV4.AccessKey))
			if cfg.Auth.Identity == "" && cfg.Auth.AWSV4.AccessKey != "" {
				cfg.Auth.Identity = cfg.Auth.AWSV4.AccessKey
				fmt.Printf("DEBUG: Set Identity to: '%s'\n", maskCredential(cfg.Auth.Identity))
			}
			if cfg.Auth.Credential == "" && cfg.Auth.AWSV4.SecretKey != "" {
				cfg.Auth.Credential = cfg.Auth.AWSV4.SecretKey
				fmt.Printf("DEBUG: Set Credential to: [REDACTED]\n")
			}
		} else {
			fmt.Printf("DEBUG: AWSV4 struct is nil\n")
		}
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// validate performs comprehensive validation of the configuration structure.
// It ensures that all required fields are present and correctly configured
// based on the selected providers and authentication methods.
func validate(cfg *Config) error {
	if cfg.Storage.Provider == "" {
		return fmt.Errorf("storage provider is required")
	}

	switch cfg.Storage.Provider {
	case "azure", "azureblob":
		if cfg.Storage.Azure == nil {
			return fmt.Errorf("azure storage config is required for provider '%s'", cfg.Storage.Provider)
		}
		if cfg.Storage.Azure.AccountName == "" || cfg.Storage.Azure.AccountKey == "" {
			if !cfg.Storage.Azure.UseSAS || cfg.Storage.Azure.SASToken == "" {
				return fmt.Errorf("azure account name and key or SAS token are required for provider '%s'", cfg.Storage.Provider)
			}
		}
	case "s3":
		if cfg.Storage.S3 == nil {
			return fmt.Errorf("s3 storage config is required for provider '%s'", cfg.Storage.Provider)
		}
		// When using AWS profile or IAM roles, explicit credentials are not required
		// Allow the SDK to use its credential chain (env vars, IAM role, etc.)
		// Only validate if we're using a custom endpoint (MinIO, etc.)
		if cfg.Storage.S3.Endpoint != "" {
			// For custom endpoints, we need explicit credentials
			if cfg.Storage.S3.Profile == "" && cfg.Storage.S3.AccessKey == "" && cfg.Storage.S3.SecretKey == "" {
				return fmt.Errorf("s3 credentials are required for custom endpoint '%s': specify profile or access/secret keys", cfg.Storage.S3.Endpoint)
			}
		}
		// For real AWS, credentials are optional - can use IAM roles
	case "filesystem":
		if cfg.Storage.FileSystem == nil {
			return fmt.Errorf("filesystem storage config is required for provider '%s'", cfg.Storage.Provider)
		}
	case "multi":
		// For multi-provider, at least one backend must be configured
		hasBackend := false
		if cfg.Storage.S3 != nil {
			hasBackend = true
			// Validate S3 config if present
			if cfg.Storage.S3.Endpoint != "" {
				if cfg.Storage.S3.Profile == "" && cfg.Storage.S3.AccessKey == "" && cfg.Storage.S3.SecretKey == "" {
					return fmt.Errorf("s3 credentials are required for custom endpoint in multi-provider mode")
				}
			}
		}
		if cfg.Storage.Azure != nil {
			hasBackend = true
			// Validate Azure config if present
			if cfg.Storage.Azure.AccountName == "" || cfg.Storage.Azure.AccountKey == "" {
				if !cfg.Storage.Azure.UseSAS || cfg.Storage.Azure.SASToken == "" {
					return fmt.Errorf("azure account name and key or SAS token are required in multi-provider mode")
				}
			}
		}
		if cfg.Storage.FileSystem != nil {
			hasBackend = true
		}
		if !hasBackend {
			return fmt.Errorf("at least one storage backend must be configured for multi-provider mode")
		}
	default:
		return fmt.Errorf("unsupported storage provider: %s", cfg.Storage.Provider)
	}

	return nil
}

// VirusTotalConfig contains VirusTotal malware scanning configuration
type VirusTotalConfig struct {
	Enabled      bool   `mapstructure:"enabled" envconfig:"VIRUSTOTAL_ENABLED" default:"false"`
	APIKey       string `mapstructure:"api_key" envconfig:"VIRUSTOTAL_API_KEY"`
	ScanUploads  bool   `mapstructure:"scan_uploads" envconfig:"VIRUSTOTAL_SCAN_UPLOADS" default:"false"`
	BlockThreats bool   `mapstructure:"block_threats" envconfig:"VIRUSTOTAL_BLOCK_THREATS" default:"false"`
	MaxFileSize  string `mapstructure:"max_file_size" envconfig:"VIRUSTOTAL_MAX_FILE_SIZE" default:"1MB"`
}

// ShareLinksConfig contains share link configuration
type ShareLinksConfig struct {
	Enabled bool `mapstructure:"enabled" envconfig:"SHARE_LINKS_ENABLED" default:"true"`
}

// MonitoringConfig contains monitoring and profiling configuration
type MonitoringConfig struct {
	MetricsEnabled bool `mapstructure:"metrics_enabled" envconfig:"MONITORING_METRICS_ENABLED" default:"true"`
	PprofEnabled   bool `mapstructure:"pprof_enabled" envconfig:"MONITORING_PPROF_ENABLED" default:"false"`
}

// SentryConfig contains Sentry error tracking configuration
type SentryConfig struct {
	Enabled              bool     `mapstructure:"enabled" envconfig:"SENTRY_ENABLED" default:"false"`
	DSN                  string   `mapstructure:"dsn" envconfig:"SENTRY_DSN"`
	Environment          string   `mapstructure:"environment" envconfig:"SENTRY_ENVIRONMENT" default:"production"`
	SampleRate           float64  `mapstructure:"sample_rate" envconfig:"SENTRY_SAMPLE_RATE" default:"1.0"`
	TracesSampleRate     float64  `mapstructure:"traces_sample_rate" envconfig:"SENTRY_TRACES_SAMPLE_RATE" default:"0.1"`
	AttachStacktrace     bool     `mapstructure:"attach_stacktrace" envconfig:"SENTRY_ATTACH_STACKTRACE" default:"true"`
	EnableTracing        bool     `mapstructure:"enable_tracing" envconfig:"SENTRY_ENABLE_TRACING" default:"true"`
	Debug                bool     `mapstructure:"debug" envconfig:"SENTRY_DEBUG" default:"false"`
	MaxBreadcrumbs       int      `mapstructure:"max_breadcrumbs" envconfig:"SENTRY_MAX_BREADCRUMBS" default:"30"`
	IgnoreErrors         []string `mapstructure:"ignore_errors"`
	ServerName           string   `mapstructure:"server_name" envconfig:"SENTRY_SERVER_NAME"`
	Release              string   `mapstructure:"release" envconfig:"SENTRY_RELEASE"`
	EnableLogs           bool     `mapstructure:"enable_logs" envconfig:"SENTRY_ENABLE_LOGS" default:"true"`
}

// OPAConfig contains Open Policy Agent configuration settings
type OPAConfig struct {
	Enabled bool          `mapstructure:"enabled" envconfig:"OPA_ENABLED" default:"false"`
	URL     string        `mapstructure:"url" envconfig:"OPA_URL" default:"http://localhost:8181"`
	Timeout time.Duration `mapstructure:"timeout" envconfig:"OPA_TIMEOUT" default:"5s"`
}

// maskCredential masks sensitive credential values for safe logging
func maskCredential(credential string) string {
	if len(credential) <= 4 {
		return "[REDACTED]"
	}
	// Show first 4 characters, mask the rest
	return credential[:4] + "****"
}
