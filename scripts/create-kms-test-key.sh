#!/bin/bash
# Script to create AWS KMS keys for testing S3 proxy encryption

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
AWS_REGION="${AWS_REGION:-us-east-1}"
KEY_ALIAS="alias/s3proxy-test"
KEY_DESCRIPTION="S3 Proxy test key for KMS encryption"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    print_error "AWS CLI is not installed. Please install it first."
    exit 1
fi

# Check AWS credentials
if [ -z "$ACCOUNT_ID" ]; then
    print_error "Unable to get AWS account ID. Please configure AWS credentials."
    exit 1
fi

print_info "AWS Account ID: $ACCOUNT_ID"
print_info "Region: $AWS_REGION"

# Function to create KMS key
create_kms_key() {
    local key_alias=$1
    local key_description=$2
    local key_policy=$3

    print_info "Creating KMS key with alias: $key_alias"

    # Check if key alias already exists
    if aws kms describe-key --key-id "$key_alias" --region "$AWS_REGION" >/dev/null 2>&1; then
        print_warning "Key with alias $key_alias already exists"
        KEY_ID=$(aws kms describe-key --key-id "$key_alias" --region "$AWS_REGION" --query 'KeyMetadata.KeyId' --output text)
        print_info "Existing Key ID: $KEY_ID"
        return 0
    fi

    # Create the key
    KEY_RESPONSE=$(aws kms create-key \
        --description "$key_description" \
        --key-usage ENCRYPT_DECRYPT \
        --origin AWS_KMS \
        --region "$AWS_REGION" \
        --key-policy "$key_policy")

    KEY_ID=$(echo "$KEY_RESPONSE" | jq -r '.KeyMetadata.KeyId')
    KEY_ARN=$(echo "$KEY_RESPONSE" | jq -r '.KeyMetadata.Arn')

    print_success "Created KMS key: $KEY_ID"

    # Create alias
    aws kms create-alias \
        --alias-name "$key_alias" \
        --target-key-id "$KEY_ID" \
        --region "$AWS_REGION"

    print_success "Created alias: $key_alias"

    # Enable key rotation
    aws kms enable-key-rotation \
        --key-id "$KEY_ID" \
        --region "$AWS_REGION"

    print_success "Enabled automatic key rotation"
}

# Function to create S3 bucket for testing
create_test_bucket() {
    local bucket_name=$1

    print_info "Creating S3 bucket: $bucket_name"

    # Check if bucket exists
    if aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
        print_warning "Bucket $bucket_name already exists"
        return 0
    fi

    # Create bucket with appropriate configuration for region
    if [ "$AWS_REGION" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "$bucket_name" \
            --region "$AWS_REGION"
    else
        aws s3api create-bucket \
            --bucket "$bucket_name" \
            --region "$AWS_REGION" \
            --create-bucket-configuration LocationConstraint="$AWS_REGION"
    fi

    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "$bucket_name" \
        --versioning-configuration Status=Enabled

    # Block public access
    aws s3api put-public-access-block \
        --bucket "$bucket_name" \
        --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

    print_success "Created bucket: $bucket_name"
}

# Create key policy
KEY_POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Id": "s3proxy-test-key-policy",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow S3 Proxy Operations",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey",
                "kms:GetKeyRotationStatus"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:CallerAccount": "${ACCOUNT_ID}",
                    "kms:EncryptionContext:application": "s3proxy"
                }
            }
        },
        {
            "Sid": "Allow CloudTrail to encrypt logs",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": [
                "kms:GenerateDataKey",
                "kms:DescribeKey"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${ACCOUNT_ID}:trail/*"
                }
            }
        }
    ]
}
EOF
)

# Main execution
print_info "Starting KMS test setup..."

# Create multiple keys for different scenarios
create_kms_key "alias/s3proxy-test" "S3 Proxy test key for general testing" "$KEY_POLICY"
create_kms_key "alias/s3proxy-sensitive" "S3 Proxy test key for sensitive data" "$KEY_POLICY"
create_kms_key "alias/s3proxy-financial" "S3 Proxy test key for financial data" "$KEY_POLICY"

# Create test buckets
BUCKET_PREFIX="s3proxy-test-${ACCOUNT_ID}"
create_test_bucket "${BUCKET_PREFIX}-public"
create_test_bucket "${BUCKET_PREFIX}-internal"
create_test_bucket "${BUCKET_PREFIX}-sensitive"
create_test_bucket "${BUCKET_PREFIX}-financial"

# Output configuration
print_success "KMS test setup completed!"
echo ""
print_info "Add the following to your S3 proxy configuration:"
echo ""
cat <<EOF
# Test Configuration for S3 Proxy with KMS

storage:
  provider: "s3"
  s3:
    region: "${AWS_REGION}"
    bucket_configs:
      public-data:
        real_name: "${BUCKET_PREFIX}-public"
        region: "${AWS_REGION}"

      internal-data:
        real_name: "${BUCKET_PREFIX}-internal"
        region: "${AWS_REGION}"
        kms_key_id: "alias/s3proxy-test"
        kms_encryption_context:
          bucket: "internal-data"
          application: "s3proxy"

      sensitive-data:
        real_name: "${BUCKET_PREFIX}-sensitive"
        region: "${AWS_REGION}"
        kms_key_id: "alias/s3proxy-sensitive"
        kms_encryption_context:
          bucket: "sensitive-data"
          application: "s3proxy"
          classification: "confidential"

      financial-data:
        real_name: "${BUCKET_PREFIX}-financial"
        region: "${AWS_REGION}"
        kms_key_id: "alias/s3proxy-financial"
        kms_encryption_context:
          bucket: "financial-data"
          application: "s3proxy"
          compliance: "financial"

encryption:
  kms:
    enabled: true
    default_key_id: "alias/s3proxy-test"
    region: "${AWS_REGION}"
    encryption_context:
      application: "s3proxy"
      environment: "test"
    data_key_cache_ttl: "5m"
    validate_keys: true
    enable_key_rotation: true
EOF

echo ""
print_info "Test environment variables:"
echo "export AWS_REGION=${AWS_REGION}"
echo "export TEST_KMS_KEY_ID=alias/s3proxy-test"
echo "export TEST_BUCKET_PREFIX=${BUCKET_PREFIX}"

# Save test configuration
CONFIG_FILE="test-config-kms.yaml"
print_info "Saving test configuration to ${CONFIG_FILE}"
cat > "${CONFIG_FILE}" <<EOF
# Auto-generated test configuration for S3 Proxy with KMS
# Generated on: $(date)
# AWS Account: ${ACCOUNT_ID}
# Region: ${AWS_REGION}

server:
  listen: ":8080"
  read_timeout: 60s
  write_timeout: 60s
  max_body_size: 5368709120

s3:
  region: "${AWS_REGION}"
  path_style: true
  ignore_unknown_headers: true

storage:
  provider: "s3"
  s3:
    region: "${AWS_REGION}"
    bucket_configs:
      public-data:
        real_name: "${BUCKET_PREFIX}-public"
        region: "${AWS_REGION}"

      internal-data:
        real_name: "${BUCKET_PREFIX}-internal"
        region: "${AWS_REGION}"
        kms_key_id: "alias/s3proxy-test"
        kms_encryption_context:
          bucket: "internal-data"
          application: "s3proxy"

      sensitive-data:
        real_name: "${BUCKET_PREFIX}-sensitive"
        region: "${AWS_REGION}"
        kms_key_id: "alias/s3proxy-sensitive"
        kms_encryption_context:
          bucket: "sensitive-data"
          application: "s3proxy"
          classification: "confidential"

      financial-data:
        real_name: "${BUCKET_PREFIX}-financial"
        region: "${AWS_REGION}"
        kms_key_id: "alias/s3proxy-financial"
        kms_encryption_context:
          bucket: "financial-data"
          application: "s3proxy"
          compliance: "financial"

auth:
  type: "awsv4"

encryption:
  kms:
    enabled: true
    default_key_id: "alias/s3proxy-test"
    region: "${AWS_REGION}"
    encryption_context:
      application: "s3proxy"
      environment: "test"
    data_key_cache_ttl: "5m"
    validate_keys: true
    enable_key_rotation: true

logging:
  level: "debug"
  format: "json"
EOF

print_success "Configuration saved to ${CONFIG_FILE}"
