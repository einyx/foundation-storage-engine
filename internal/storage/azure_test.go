package storage

import (
	"testing"

	"github.com/einyx/s3proxy-go/internal/config"
)

func TestNewAzureBackend(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.AzureStorageConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config with shared key",
			cfg: &config.AzureStorageConfig{
				AccountName:   "testaccount",
				AccountKey:    "dGVzdGtleQ==", // base64 encoded "testkey"
				ContainerName: "testcontainer",
				UseSAS:        false,
			},
			wantErr: false,
		},
		{
			name: "valid config with SAS",
			cfg: &config.AzureStorageConfig{
				AccountName:   "testaccount",
				ContainerName: "testcontainer",
				UseSAS:        true,
				SASToken:      "sv=2019-12-12&ss=b&srt=sco&sp=rwdlacx&se=2021-08-20T03:42:31Z&st=2021-08-19T19:42:31Z&spr=https&sig=abcd",
			},
			wantErr: false,
		},
		{
			name: "invalid base64 account key",
			cfg: &config.AzureStorageConfig{
				AccountName:   "testaccount",
				AccountKey:    "not-valid-base64!@#$",
				ContainerName: "testcontainer",
				UseSAS:        false,
			},
			wantErr:     true,
			errContains: "invalid credentials",
		},
		{
			name: "custom endpoint",
			cfg: &config.AzureStorageConfig{
				AccountName:   "testaccount",
				AccountKey:    "dGVzdGtleQ==",
				ContainerName: "testcontainer",
				Endpoint:      "http://127.0.0.1:10000/devstoreaccount1",
				UseSAS:        false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAzureBackend(tt.cfg)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewAzureBackend() expected error but got none")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("NewAzureBackend() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("NewAzureBackend() unexpected error = %v", err)
				}
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}
