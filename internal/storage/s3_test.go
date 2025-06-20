package storage

import (
	"testing"

	"github.com/einyx/s3proxy-go/internal/config"
)

func TestNewS3Backend(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.S3StorageConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config with endpoint",
			cfg: &config.S3StorageConfig{
				Endpoint:  "http://localhost:9000",
				Region:    "us-east-1",
				AccessKey: "test",
				SecretKey: "test",
			},
			wantErr: false,
		},
		{
			name: "valid config without endpoint",
			cfg: &config.S3StorageConfig{
				Region:    "us-east-1",
				AccessKey: "test",
				SecretKey: "test",
			},
			wantErr: false,
		},
		{
			name: "config with path style",
			cfg: &config.S3StorageConfig{
				Endpoint:     "http://localhost:9000",
				Region:       "us-east-1",
				AccessKey:    "test",
				SecretKey:    "test",
				UsePathStyle: true,
			},
			wantErr: false,
		},
		{
			name: "config with SSL disabled",
			cfg: &config.S3StorageConfig{
				Endpoint:   "http://localhost:9000",
				Region:     "us-east-1",
				AccessKey:  "test",
				SecretKey:  "test",
				DisableSSL: true,
			},
			wantErr: false,
		},
		{
			name: "missing region defaults to us-east-1",
			cfg: &config.S3StorageConfig{
				AccessKey: "test",
				SecretKey: "test",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewS3Backend(tt.cfg)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewS3Backend() expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("NewS3Backend() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("NewS3Backend() unexpected error = %v", err)
				}
			}
		})
	}
}
