package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"

	"github.com/einyx/foundation-storage-engine/internal/config"
)

type vaultAWSV4Provider struct {
	cfg             config.VaultAuthConfig
	client          *vaultapi.Client
	logger          *logrus.Entry
	mu              sync.RWMutex
	identity        string
	credential      string
	refreshInterval time.Duration
	requestTimeout  time.Duration
}

func NewVaultAWSV4Provider(cfg config.AuthConfig) (Provider, error) {
	if cfg.Vault == nil || !cfg.Vault.Enabled {
		return nil, fmt.Errorf("vault authentication is not enabled")
	}

	clientCfg := vaultapi.DefaultConfig()
	if cfg.Vault.Address != "" {
		clientCfg.Address = cfg.Vault.Address
	}

	client, err := vaultapi.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	token, err := resolveVaultToken(cfg.Vault)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	provider := &vaultAWSV4Provider{
		cfg:             *cfg.Vault,
		client:          client,
		logger:          logrus.WithField("component", "vault-auth"),
		refreshInterval: cfg.Vault.RefreshInterval,
		requestTimeout:  cfg.Vault.RequestTimeout,
		identity:        cfg.Identity,
		credential:      cfg.Credential,
	}

	if err := provider.refreshCredentials(); err != nil {
		if provider.identity == "" || provider.credential == "" {
			return nil, err
		}
		provider.logger.WithError(err).Warn("failed to load credentials from Vault, falling back to static credentials")
	}

	if provider.refreshInterval > 0 {
		go provider.refreshLoop()
	}

	return provider, nil
}

func resolveVaultToken(cfg *config.VaultAuthConfig) (string, error) {
	if cfg.Token != "" {
		return cfg.Token, nil
	}

	if cfg.TokenFile != "" {
		data, err := os.ReadFile(cfg.TokenFile)
		if err != nil {
			return "", fmt.Errorf("failed to read Vault token file: %w", err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("Vault token file is empty")
		}
		return token, nil
	}

	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token, nil
	}

	return "", fmt.Errorf("vault token not provided")
}

func (p *vaultAWSV4Provider) refreshLoop() {
	ticker := time.NewTicker(p.refreshInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := p.refreshCredentials(); err != nil {
			p.logger.WithError(err).Warn("failed to refresh credentials from Vault")
		}
	}
}

func (p *vaultAWSV4Provider) refreshCredentials() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.requestTimeout)
	defer cancel()

	mount := strings.Trim(p.cfg.MountPath, "/")
	if mount == "" {
		mount = "secret"
	}

	secretName := strings.Trim(p.cfg.SecretName, "/")
	if secretName == "" {
		secretName = "storage-engine"
	}

	secret, err := p.client.KVv2(mount).Get(ctx, secretName)
	if err != nil {
		return fmt.Errorf("failed to read credentials from Vault (%s/%s): %w", mount, secretName, err)
	}

	identityValue, ok := secret.Data[p.cfg.IdentityField]
	if !ok {
		return fmt.Errorf("vault secret missing identity field '%s'", p.cfg.IdentityField)
	}
	identity, ok := identityValue.(string)
	if !ok || identity == "" {
		return fmt.Errorf("vault identity field '%s' is empty or not a string", p.cfg.IdentityField)
	}

	credentialValue, ok := secret.Data[p.cfg.CredentialField]
	if !ok {
		return fmt.Errorf("vault secret missing credential field '%s'", p.cfg.CredentialField)
	}
	credential, ok := credentialValue.(string)
	if !ok || credential == "" {
		return fmt.Errorf("vault credential field '%s' is empty or not a string", p.cfg.CredentialField)
	}

	p.mu.Lock()
	p.identity = identity
	p.credential = credential
	p.mu.Unlock()

	p.logger.WithField("access_key", maskValue(identity)).Info("loaded credentials from Vault")
	return nil
}

func (p *vaultAWSV4Provider) getCredentials() (string, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.identity, p.credential
}

func (p *vaultAWSV4Provider) Authenticate(r *http.Request) error {
	identity, credential := p.getCredentials()
	if identity == "" || credential == "" {
		return fmt.Errorf("vault credentials unavailable")
	}

	provider := &AWSV4Provider{
		identity:   identity,
		credential: credential,
	}
	return provider.Authenticate(r)
}

func (p *vaultAWSV4Provider) GetSecretKey(accessKey string) (string, error) {
	identity, credential := p.getCredentials()
	if accessKey == identity && credential != "" {
		return credential, nil
	}
	return "", fmt.Errorf("unknown access key")
}

func maskValue(value string) string {
	if len(value) <= 4 {
		return "[REDACTED]"
	}
	return value[:4] + "****"
}
