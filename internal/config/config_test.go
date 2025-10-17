package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoad_EmptyConfig(t *testing.T) {
	// Set required storage provider
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg == nil {
		t.Fatal("Config should not be nil")
	}

	// Test default values
	if cfg.Server.Listen != ":8080" {
		t.Errorf("Expected default listen :8080, got %s", cfg.Server.Listen)
	}

	if cfg.Server.MaxBodySize != 5368709120 {
		t.Errorf("Expected default max body size 5GB, got %d", cfg.Server.MaxBodySize)
	}

	if cfg.S3.Region != "us-east-1" {
		t.Errorf("Expected default S3 region us-east-1, got %s", cfg.S3.Region)
	}
}

func TestLoad_EnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("SERVER_LISTEN", ":9090")
	os.Setenv("STORAGE_PROVIDER", "s3")
	os.Setenv("S3_REGION", "us-west-2")
	defer func() {
		os.Unsetenv("SERVER_LISTEN")
		os.Unsetenv("STORAGE_PROVIDER")
		os.Unsetenv("S3_REGION")
	}()

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.Server.Listen != ":9090" {
		t.Errorf("Expected listen :9090, got %s", cfg.Server.Listen)
	}

	if cfg.Storage.Provider != "s3" {
		t.Errorf("Expected storage provider s3, got %s", cfg.Storage.Provider)
	}

	if cfg.S3.Region != "us-west-2" {
		t.Errorf("Expected S3 region us-west-2, got %s", cfg.S3.Region)
	}
}

func TestLoad_AWSEnvironmentVariables(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	os.Setenv("STORAGE_PROVIDER", "s3")
	defer func() {
		os.Unsetenv("AWS_ACCESS_KEY_ID")
		os.Unsetenv("AWS_SECRET_ACCESS_KEY")
		os.Unsetenv("STORAGE_PROVIDER")
	}()

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.Auth.Identity != "test-access-key" {
		t.Errorf("Expected auth identity test-access-key, got %s", cfg.Auth.Identity)
	}

	if cfg.Auth.Credential != "test-secret-key" {
		t.Errorf("Expected auth credential test-secret-key, got %s", cfg.Auth.Credential)
	}
}

func TestValidate_MissingStorageProvider(t *testing.T) {
	cfg := &Config{}
	
	err := validate(cfg)
	if err == nil {
		t.Error("Expected validation error for missing storage provider")
	}

	if !strings.Contains(err.Error(), "storage provider is required") {
		t.Errorf("Expected storage provider error, got: %v", err)
	}
}

func TestValidate_AzureStorage_Valid(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "azure",
			Azure: &AzureStorageConfig{
				AccountName: "testaccount",
				AccountKey:  "testkey",
			},
		},
	}

	err := validate(cfg)
	if err != nil {
		t.Errorf("Expected no validation error, got: %v", err)
	}
}

func TestValidate_AzureStorage_MissingConfig(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "azure",
		},
	}

	err := validate(cfg)
	if err == nil {
		t.Error("Expected validation error for missing azure config")
	}

	if !strings.Contains(err.Error(), "azure storage config is required") {
		t.Errorf("Expected azure config error, got: %v", err)
	}
}

func TestValidate_AzureStorage_SASToken(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "azure",
			Azure: &AzureStorageConfig{
				UseSAS:   true,
				SASToken: "test-sas-token",
			},
		},
	}

	err := validate(cfg)
	if err != nil {
		t.Errorf("Expected no validation error with SAS token, got: %v", err)
	}
}

func TestValidate_AzureStorage_MissingCredentials(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "azure",
			Azure: &AzureStorageConfig{
				AccountName: "testaccount",
				// Missing AccountKey and SAS
			},
		},
	}

	err := validate(cfg)
	if err == nil {
		t.Error("Expected validation error for missing azure credentials")
	}

	if !strings.Contains(err.Error(), "azure account name and key or SAS token are required") {
		t.Errorf("Expected azure credentials error, got: %v", err)
	}
}

func TestValidate_S3Storage_Valid(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "s3",
			S3: &S3StorageConfig{
				Region: "us-east-1",
			},
		},
	}

	err := validate(cfg)
	if err != nil {
		t.Errorf("Expected no validation error for S3 without explicit credentials, got: %v", err)
	}
}

func TestValidate_S3Storage_CustomEndpoint(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "s3",
			S3: &S3StorageConfig{
				Endpoint:  "http://minio:9000",
				AccessKey: "minioaccess",
				SecretKey: "miniosecret",
			},
		},
	}

	err := validate(cfg)
	if err != nil {
		t.Errorf("Expected no validation error for S3 with custom endpoint and credentials, got: %v", err)
	}
}

func TestValidate_S3Storage_CustomEndpointMissingCredentials(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "s3",
			S3: &S3StorageConfig{
				Endpoint: "http://minio:9000",
				// Missing credentials
			},
		},
	}

	err := validate(cfg)
	if err == nil {
		t.Error("Expected validation error for custom endpoint without credentials")
	}

	if !strings.Contains(err.Error(), "s3 credentials are required for custom endpoint") {
		t.Errorf("Expected S3 credentials error, got: %v", err)
	}
}

func TestValidate_FilesystemStorage_Valid(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "filesystem",
			FileSystem: &FileSystemConfig{
				BaseDir: "/tmp/storage",
			},
		},
	}

	err := validate(cfg)
	if err != nil {
		t.Errorf("Expected no validation error for filesystem storage, got: %v", err)
	}
}

func TestValidate_FilesystemStorage_MissingConfig(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "filesystem",
		},
	}

	err := validate(cfg)
	if err == nil {
		t.Error("Expected validation error for missing filesystem config")
	}

	if !strings.Contains(err.Error(), "filesystem storage config is required") {
		t.Errorf("Expected filesystem config error, got: %v", err)
	}
}

func TestValidate_MultiStorage_Valid(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "multi",
			S3: &S3StorageConfig{
				Region: "us-east-1",
			},
			Azure: &AzureStorageConfig{
				AccountName: "testaccount",
				AccountKey:  "testkey",
			},
		},
	}

	err := validate(cfg)
	if err != nil {
		t.Errorf("Expected no validation error for multi storage, got: %v", err)
	}
}

func TestValidate_MultiStorage_NoBackends(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "multi",
		},
	}

	err := validate(cfg)
	if err == nil {
		t.Error("Expected validation error for multi storage without backends")
	}

	if !strings.Contains(err.Error(), "at least one storage backend must be configured") {
		t.Errorf("Expected multi storage backends error, got: %v", err)
	}
}

func TestValidate_UnsupportedProvider(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "unknown",
		},
	}

	err := validate(cfg)
	if err == nil {
		t.Error("Expected validation error for unsupported provider")
	}

	if !strings.Contains(err.Error(), "unsupported storage provider: unknown") {
		t.Errorf("Expected unsupported provider error, got: %v", err)
	}
}

func TestServerConfig_Defaults(t *testing.T) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.Server.ReadTimeout != 60*time.Second {
		t.Errorf("Expected default read timeout 60s, got %v", cfg.Server.ReadTimeout)
	}

	if cfg.Server.WriteTimeout != 60*time.Second {
		t.Errorf("Expected default write timeout 60s, got %v", cfg.Server.WriteTimeout)
	}

	if cfg.Server.IdleTimeout != 120*time.Second {
		t.Errorf("Expected default idle timeout 120s, got %v", cfg.Server.IdleTimeout)
	}
}

func TestAuth0Config_Defaults(t *testing.T) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.Auth0.Enabled {
		t.Error("Expected Auth0 to be disabled by default")
	}

	if cfg.Auth0.RedirectURI != "/api/auth/callback" {
		t.Errorf("Expected default redirect URI, got %s", cfg.Auth0.RedirectURI)
	}

	if cfg.Auth0.SessionTimeout != 24*time.Hour {
		t.Errorf("Expected default session timeout 24h, got %v", cfg.Auth0.SessionTimeout)
	}

	if !cfg.Auth0.EnablePKCE {
		t.Error("Expected PKCE to be enabled by default")
	}
}

func TestEncryptionConfig_Defaults(t *testing.T) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.Encryption.Enabled {
		t.Error("Expected encryption to be disabled by default")
	}

	if cfg.Encryption.Algorithm != "AES-256-GCM" {
		t.Errorf("Expected default algorithm AES-256-GCM, got %s", cfg.Encryption.Algorithm)
	}

	if cfg.Encryption.KeyProvider != "local" {
		t.Errorf("Expected default key provider local, got %s", cfg.Encryption.KeyProvider)
	}
}

func TestVirusTotalConfig_Defaults(t *testing.T) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.VirusTotal.Enabled {
		t.Error("Expected VirusTotal to be disabled by default")
	}

	if cfg.VirusTotal.ScanUploads {
		t.Error("Expected scan uploads to be disabled by default")
	}

	if cfg.VirusTotal.MaxFileSize != "1MB" {
		t.Errorf("Expected default max file size 1MB, got %s", cfg.VirusTotal.MaxFileSize)
	}
}

func TestSentryConfig_Defaults(t *testing.T) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.Sentry.Enabled {
		t.Error("Expected Sentry to be disabled by default")
	}

	if cfg.Sentry.SampleRate != 1.0 {
		t.Errorf("Expected default sample rate 1.0, got %f", cfg.Sentry.SampleRate)
	}

	if cfg.Sentry.TracesSampleRate != 0.1 {
		t.Errorf("Expected default traces sample rate 0.1, got %f", cfg.Sentry.TracesSampleRate)
	}

	if cfg.Sentry.MaxBreadcrumbs != 30 {
		t.Errorf("Expected default max breadcrumbs 30, got %d", cfg.Sentry.MaxBreadcrumbs)
	}
}

func TestOPAConfig_Defaults(t *testing.T) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.OPA.Enabled {
		t.Error("Expected OPA to be disabled by default")
	}

	if cfg.OPA.URL != "http://localhost:8181" {
		t.Errorf("Expected default OPA URL, got %s", cfg.OPA.URL)
	}

	if cfg.OPA.Timeout != 5*time.Second {
		t.Errorf("Expected default OPA timeout 5s, got %v", cfg.OPA.Timeout)
	}
}

func TestDatabaseConfig_Defaults(t *testing.T) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.Database.Enabled {
		t.Error("Expected database to be disabled by default")
	}

	if cfg.Database.Driver != "postgres" {
		t.Errorf("Expected default driver postgres, got %s", cfg.Database.Driver)
	}

	if cfg.Database.MaxOpenConns != 25 {
		t.Errorf("Expected default max open conns 25, got %d", cfg.Database.MaxOpenConns)
	}

	if cfg.Database.ConnMaxLifetime != 5*time.Minute {
		t.Errorf("Expected default conn max lifetime 5m, got %v", cfg.Database.ConnMaxLifetime)
	}
}

func TestMonitoringConfig_Defaults(t *testing.T) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !cfg.Monitoring.MetricsEnabled {
		t.Error("Expected metrics to be enabled by default")
	}

	if cfg.Monitoring.PprofEnabled {
		t.Error("Expected pprof to be disabled by default")
	}
}

func TestChunkingConfig_FieldTypes(t *testing.T) {
	config := ChunkingConfig{
		VerifySignatures:        true,
		RequireChunkedUpload:    false,
		MaxChunkSize:            2097152,
		RequestTimeWindow:       600,
		LogOnlyMode:             false,
		StoreChunkedFormat:      true,
		PreserveChunkedResponse: true,
		ChunkResponseSize:       131072,
	}

	if !config.VerifySignatures {
		t.Error("Expected VerifySignatures to be true")
	}

	if config.MaxChunkSize != 2097152 {
		t.Errorf("Expected MaxChunkSize 2097152, got %d", config.MaxChunkSize)
	}

	if config.ChunkResponseSize != 131072 {
		t.Errorf("Expected ChunkResponseSize 131072, got %d", config.ChunkResponseSize)
	}
}

func TestLoad_InvalidConfigFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent config file")
	}

	if !strings.Contains(err.Error(), "failed to read config file") {
		t.Errorf("Expected config file read error, got: %v", err)
	}
}

func BenchmarkLoad_EmptyConfig(b *testing.B) {
	os.Setenv("STORAGE_PROVIDER", "filesystem")
	defer os.Unsetenv("STORAGE_PROVIDER")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Load("")
		if err != nil {
			b.Fatalf("Load failed: %v", err)
		}
	}
}

func BenchmarkValidate(b *testing.B) {
	cfg := &Config{
		Storage: StorageConfig{
			Provider: "s3",
			S3: &S3StorageConfig{
				Region: "us-east-1",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := validate(cfg)
		if err != nil {
			b.Fatalf("Validate failed: %v", err)
		}
	}
}