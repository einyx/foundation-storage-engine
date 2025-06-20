package storage

import (
	"testing"

	"github.com/einyx/s3proxy-go/internal/config"
)

func TestNewBackend(t *testing.T) {
	tests := []struct {
		name        string
		cfg         config.StorageConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "filesystem provider",
			cfg: config.StorageConfig{
				Provider: "filesystem",
				FileSystem: &config.FileSystemConfig{
					BaseDir: "/tmp/test",
				},
			},
			wantErr: false,
		},
		{
			name: "s3 provider",
			cfg: config.StorageConfig{
				Provider: "s3",
				S3: &config.S3StorageConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test",
					SecretKey: "test", // pragma: allowlist secret
					Region:    "us-east-1",
				},
			},
			wantErr: false,
		},
		{
			name: "azure provider",
			cfg: config.StorageConfig{
				Provider: "azure",
				Azure: &config.AzureStorageConfig{
					AccountName:   "test",
					AccountKey:    "dGVzdA==", // base64 encoded "test" // pragma: allowlist secret
					ContainerName: "test",
				},
			},
			wantErr: false,
		},
		{
			name: "azureblob provider alias",
			cfg: config.StorageConfig{
				Provider: "azureblob",
				Azure: &config.AzureStorageConfig{
					AccountName:   "test",
					AccountKey:    "dGVzdA==", // pragma: allowlist secret
					ContainerName: "test",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid provider",
			cfg: config.StorageConfig{
				Provider: "invalid",
			},
			wantErr:     true,
			errContains: "unsupported storage provider",
		},
		{
			name: "empty provider",
			cfg: config.StorageConfig{
				Provider: "",
			},
			wantErr:     true,
			errContains: "unsupported storage provider",
		},
		{
			name: "filesystem missing config",
			cfg: config.StorageConfig{
				Provider: "filesystem",
			},
			wantErr:     true,
			errContains: "filesystem configuration required",
		},
		{
			name: "s3 with invalid key",
			cfg: config.StorageConfig{
				Provider: "s3",
				S3: &config.S3StorageConfig{
					AccessKey: "test",
					SecretKey: "", // empty secret key should cause error during actual AWS client creation
				},
			},
			wantErr: false, // The factory doesn't validate S3 creds, AWS client creation would fail
		},
		{
			name: "azure with invalid key",
			cfg: config.StorageConfig{
				Provider: "azure",
				Azure: &config.AzureStorageConfig{
					AccountName:   "test",
					AccountKey:    "not-valid-base64!@#$", // pragma: allowlist secret
					ContainerName: "test",
				},
			},
			wantErr:     true,
			errContains: "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewBackend(tt.cfg)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewBackend() expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("NewBackend() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("NewBackend() unexpected error = %v", err)
				}
				if backend == nil {
					t.Errorf("NewBackend() returned nil backend")
				}
			}
		})
	}
}
