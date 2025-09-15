# S3 Proxy Helm Chart

This Helm chart deploys the S3 Proxy application on a Kubernetes cluster.

## Installation

### Add the repository (when published)

```bash
helm repo add s3proxy https://ghcr.io/alessio/s3proxy-go
helm repo update
```

### Install from local directory

```bash
# Install with default values (service named "minio" for compatibility)
helm install s3proxy ./charts/s3proxy

# Install with Azure backend
helm install s3proxy ./charts/s3proxy -f ./charts/s3proxy/values-azure.yaml

# Install with S3 backend
helm install s3proxy ./charts/s3proxy -f ./charts/s3proxy/values-s3.yaml

# Install with ExternalSecrets for Azure
helm install s3proxy ./charts/s3proxy -f ./charts/s3proxy/values-externalsecrets-azure.yaml

# Install with ExternalSecrets for AWS
helm install s3proxy ./charts/s3proxy -f ./charts/s3proxy/values-externalsecrets-aws.yaml
```

## Configuration

### Key Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.name` | Service name (use "minio" for MinIO compatibility) | `minio` |
| `service.port` | Service port | `9000` |
| `config.storage.provider` | Storage backend provider | `azure` |
| `config.auth.type` | Authentication type | `none` |
| `awsCredentials.enabled` | Enable AWS credentials for fast auth | `false` |
| `image.tag` | Image tag (uses commit SHA in CI/CD) | `""` |

### Storage Backends

#### Azure Blob Storage

```yaml
config:
  storage:
    provider: "azure"
    azure:
      accountName: "mystorageaccount"
      accountKey: "base64-encoded-key"  # pragma: allowlist secret
      containerName: "mycontainer"
```

#### AWS S3

```yaml
config:
  storage:
    provider: "s3"
    s3:
      endpoint: "https://s3.amazonaws.com"
      region: "us-east-1"
      accessKey: "your-access-key"
      secretKey: "your-secret-key"  # pragma: allowlist secret
```

#### Local Filesystem

```yaml
config:
  storage:
    provider: "filesystem"
    filesystem:
      baseDir: "/data"

persistence:
  enabled: true
  size: 100Gi
```

### Authentication

The proxy supports multiple authentication methods:

```yaml
# No authentication
config:
  auth:
    type: "none"

# Basic authentication
config:
  auth:
    type: "basic"
    identity: "admin"
    credential: "secret"

# AWS Signature V4 (with fast path)
config:
  auth:
    type: "awsv4"
    identity: "access-key"
    credential: "secret-key"

# Or use environment variables for fast auth
awsCredentials:
  enabled: true
  accessKeyId: "your-access-key-id"
  secretAccessKey: "your-secret-access-key"  # pragma: allowlist secret
```

### Using ExternalSecrets

S3Proxy supports [ExternalSecrets Operator](https://external-secrets.io/) for managing sensitive credentials from external secret management systems like Vault, AWS Secrets Manager, Azure Key Vault, etc.

#### Prerequisites

1. Install ExternalSecrets Operator in your cluster
2. Create a SecretStore or ClusterSecretStore for your backend

#### Azure Storage with ExternalSecrets

```yaml
# Configure ExternalSecrets to fetch Azure credentials
externalSecrets:
  enabled: true
  secretStore:
    name: "vault-backend"  # Your SecretStore name
    kind: "SecretStore"

  azure:
    enabled: true
    remoteRefs:
      accountName:
        key: "secret/data/azure/storage"  # Path in Vault
        property: "account_name"          # JSON property
      accountKey:
        key: "secret/data/azure/storage"
        property: "account_key"
      # Optional: SAS token
      sasToken:
        key: "secret/data/azure/storage"
        property: "sas_token"
```

#### AWS S3 with ExternalSecrets

```yaml
# Configure ExternalSecrets to fetch AWS credentials
externalSecrets:
  enabled: true
  secretStore:
    name: "aws-secrets-manager"
    kind: "SecretStore"

  aws:
    enabled: true
    remoteRefs:
      accessKeyId:
        key: "s3-credentials"       # Secret name in AWS SM
        property: "accessKeyId"     # JSON property
      secretAccessKey:
        key: "s3-credentials"
        property: "secretAccessKey"
```

#### Authentication Credentials with ExternalSecrets

```yaml
# S3Proxy authentication from external secrets
externalSecrets:
  auth:
    enabled: true
    remoteRefs:
      identity:
        key: "s3proxy/auth"
        property: "username"
      credential:
        key: "s3proxy/auth"
        property: "password"
```

#### Complete Example with Vault

```yaml
# values-externalsecrets.yaml
config:
  storage:
    provider: "azure"
    azure:
      containerName: "my-container"
      # Credentials come from ExternalSecrets

  auth:
    type: "awsv4"
    # Credentials come from ExternalSecrets

externalSecrets:
  enabled: true
  refreshInterval: 15s

  secretStore:
    name: "vault-backend"
    kind: "SecretStore"

  azure:
    enabled: true
    remoteRefs:
      accountName:
        key: "secret/data/azure/storage"
        property: "account_name"
      accountKey:
        key: "secret/data/azure/storage"
        property: "account_key"

  auth:
    enabled: true
    remoteRefs:
      identity:
        key: "secret/data/s3proxy/auth"
        property: "access_key"
      credential:
        key: "secret/data/s3proxy/auth"
        property: "secret_key"
```

Deploy with:

```bash
helm install s3proxy ./charts/s3proxy -f values-externalsecrets.yaml
```

### High Availability

```yaml
replicaCount: 3

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

### Ingress

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: minio.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: minio-tls
      hosts:
        - minio.example.com
```

## Deployment Patterns

### MinIO Compatibility Mode

The default configuration names the service "minio" for drop-in compatibility:

```bash
# Deploy as MinIO replacement
helm install minio ./charts/s3proxy \
  --set service.name=minio \
  --set service.port=9000
```

### Custom Service Name

```bash
# Deploy with custom service name
helm install s3proxy ./charts/s3proxy \
  --set service.name=s3-gateway \
  --set service.port=80
```

### Using Commit SHA (CI/CD)

In CI/CD pipelines, images are tagged with commit SHA:

```bash
helm upgrade --install s3proxy ./charts/s3proxy \
  --set image.tag="sha-${GITHUB_SHA}" \
  --set image.repository="ghcr.io/alessio/s3proxy-go"
```

## Connecting to the Service

### Within the cluster

```bash
# Default (MinIO compatible)
http://minio:9000

# With namespace
http://minio.default.svc.cluster.local:9000

# Custom service name
http://s3-gateway:80
```

### Using AWS CLI

```bash
# Port-forward for local access
kubectl port-forward svc/minio 9000:9000

# Configure AWS CLI
aws configure set aws_access_key_id admin
aws configure set aws_secret_access_key secret

# Use the proxy
aws --endpoint-url http://localhost:9000 s3 ls
```

## Monitoring

### Enable Prometheus monitoring

```yaml
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus
```

## Troubleshooting

### Check pod status

```bash
kubectl get pods -l app.kubernetes.io/name=s3proxy
kubectl logs -l app.kubernetes.io/name=s3proxy
```

### Verify service

```bash
kubectl get svc
kubectl describe svc minio  # or your custom service name
```

### Test connectivity

```bash
kubectl run test-pod --image=amazonlinux:2 --rm -it -- bash
# Inside the pod:
curl -I http://minio:9000
```
