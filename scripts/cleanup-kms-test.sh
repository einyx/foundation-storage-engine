#!/bin/bash
# Script to clean up AWS KMS test resources

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
AWS_REGION="${AWS_REGION:-us-east-1}"
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

print_warning "This script will delete test KMS keys and S3 buckets"
print_warning "AWS Account: $ACCOUNT_ID"
print_warning "Region: $AWS_REGION"
echo ""
read -p "Are you sure you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    print_info "Cleanup cancelled"
    exit 0
fi

# Function to schedule key deletion
delete_kms_key() {
    local key_alias=$1

    print_info "Scheduling deletion for KMS key: $key_alias"

    # Get key ID from alias
    KEY_ID=$(aws kms describe-key --key-id "$key_alias" --region "$AWS_REGION" --query 'KeyMetadata.KeyId' --output text 2>/dev/null || echo "")

    if [ -z "$KEY_ID" ]; then
        print_warning "Key with alias $key_alias not found"
        return 0
    fi

    # Delete alias first
    aws kms delete-alias --alias-name "$key_alias" --region "$AWS_REGION" 2>/dev/null || true
    print_info "Deleted alias: $key_alias"

    # Schedule key deletion (minimum 7 days)
    aws kms schedule-key-deletion \
        --key-id "$KEY_ID" \
        --pending-window-in-days 7 \
        --region "$AWS_REGION"

    print_success "Scheduled deletion for key $KEY_ID (will be deleted in 7 days)"
}

# Function to delete S3 bucket
delete_s3_bucket() {
    local bucket_name=$1

    print_info "Deleting S3 bucket: $bucket_name"

    # Check if bucket exists
    if ! aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
        print_warning "Bucket $bucket_name not found"
        return 0
    fi

    # Delete all objects and versions
    print_info "Removing all objects from $bucket_name..."

    # Delete all object versions
    aws s3api list-object-versions --bucket "$bucket_name" --output json | \
    jq -r '.Versions[]? | "\(.Key) \(.VersionId)"' | \
    while read key version_id; do
        if [ -n "$key" ] && [ -n "$version_id" ]; then
            aws s3api delete-object --bucket "$bucket_name" --key "$key" --version-id "$version_id"
        fi
    done

    # Delete all delete markers
    aws s3api list-object-versions --bucket "$bucket_name" --output json | \
    jq -r '.DeleteMarkers[]? | "\(.Key) \(.VersionId)"' | \
    while read key version_id; do
        if [ -n "$key" ] && [ -n "$version_id" ]; then
            aws s3api delete-object --bucket "$bucket_name" --key "$key" --version-id "$version_id"
        fi
    done

    # Delete the bucket
    aws s3api delete-bucket --bucket "$bucket_name" --region "$AWS_REGION"

    print_success "Deleted bucket: $bucket_name"
}

# Main cleanup
print_info "Starting cleanup of KMS test resources..."

# Delete KMS keys
delete_kms_key "alias/s3proxy-test"
delete_kms_key "alias/s3proxy-sensitive"
delete_kms_key "alias/s3proxy-financial"

# Delete S3 buckets
BUCKET_PREFIX="s3proxy-test-${ACCOUNT_ID}"
delete_s3_bucket "${BUCKET_PREFIX}-public"
delete_s3_bucket "${BUCKET_PREFIX}-internal"
delete_s3_bucket "${BUCKET_PREFIX}-sensitive"
delete_s3_bucket "${BUCKET_PREFIX}-financial"

# Remove test configuration file
if [ -f "test-config-kms.yaml" ]; then
    rm -f "test-config-kms.yaml"
    print_info "Removed test-config-kms.yaml"
fi

print_success "Cleanup completed!"
print_warning "Note: KMS keys are scheduled for deletion and will be removed after 7 days"
print_info "To cancel key deletion, use: aws kms cancel-key-deletion --key-id <KEY_ID>"
