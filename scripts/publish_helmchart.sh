#!/bin/bash

# Script to publish Helm charts to Amazon ECR
# Prerequisites:
# - AWS CLI configured with appropriate credentials
# - Helm 3.8.0+ (with OCI support)
# - jq (for JSON parsing)

set -e

# Configuration
CHART_PATH="${1:-./charts/foundation-storage-engine}"  # Path to your Helm chart directory
CHART_NAME="${2:-foundation-storage-engine}"  # Chart name (will be used as repository name)
CHART_VERSION="${3:-}"       # Chart version (optional, will use Chart.yaml version if not provided)
AWS_REGION="${AWS_REGION:-me-central-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_REPOSITORY="foundation/storage-engine"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Validate prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if Helm is installed
    if ! command -v helm &> /dev/null; then
        log_error "Helm is not installed. Please install it first."
        exit 1
    fi
    
    # Check Helm version (needs 3.8.0+ for OCI support)
    HELM_VERSION=$(helm version --short | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | sed 's/v//')
    REQUIRED_VERSION="3.8.0"
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$HELM_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
        log_error "Helm version $HELM_VERSION is too old. Please upgrade to 3.8.0 or later."
        exit 1
    fi
    
    # Check if chart directory exists
    if [ ! -d "$CHART_PATH" ]; then
        log_error "Chart directory not found: $CHART_PATH"
        exit 1
    fi
    
    # Check if Chart.yaml exists
    if [ ! -f "$CHART_PATH/Chart.yaml" ]; then
        log_error "Chart.yaml not found in $CHART_PATH"
        exit 1
    fi
    
    log_info "Prerequisites check passed."
}

# Get chart version from Chart.yaml if not provided
get_chart_version() {
    if [ -z "$CHART_VERSION" ]; then
        CHART_VERSION=$(helm show chart "$CHART_PATH" | grep '^version:' | awk '{print $2}')
        log_info "Using version from Chart.yaml: $CHART_VERSION"
    else
        log_info "Using provided version: $CHART_VERSION"
    fi
}

# Create ECR repository if it doesn't exist
create_ecr_repository() {
    # For Helm charts in ECR, the repository name should match the chart name
    # ECR expects the repository to exist before pushing
    ACTUAL_REPO_NAME="${CHART_NAME}"
    
    log_info "Checking if ECR repository exists: $ACTUAL_REPO_NAME"
    
    if aws ecr describe-repositories --repository-names "$ACTUAL_REPO_NAME" --region "$AWS_REGION" &> /dev/null; then
        log_info "ECR repository already exists: $ACTUAL_REPO_NAME"
    else
        log_info "Creating ECR repository: $ACTUAL_REPO_NAME"
        aws ecr create-repository \
            --repository-name "$ACTUAL_REPO_NAME" \
            --region "$AWS_REGION" \
            --image-scanning-configuration scanOnPush=true \
            --encryption-configuration encryptionType=AES256
        
        if [ $? -eq 0 ]; then
            log_info "Repository created successfully"
        else
            log_error "Failed to create repository"
            exit 1
        fi
    fi
    
    # Update the ECR_REPOSITORY variable to use the actual repo name
    ECR_REPOSITORY="$ACTUAL_REPO_NAME"
}

# Login to ECR
ecr_login() {
    log_info "Logging in to ECR..."
    aws ecr get-login-password --region "$AWS_REGION" | helm registry login --username AWS --password-stdin "$ECR_REGISTRY"
    
    if [ $? -eq 0 ]; then
        log_info "Successfully logged in to ECR"
    else
        log_error "Failed to login to ECR"
        exit 1
    fi
}

# Package Helm chart
package_chart() {
    log_info "Packaging Helm chart..."
    
    # Create a temporary directory for the packaged chart
    TEMP_DIR=$(mktemp -d)
    
    # Package the chart
    helm package "$CHART_PATH" --destination "$TEMP_DIR" --version "$CHART_VERSION"
    
    # Get the packaged chart filename
    CHART_PACKAGE="$TEMP_DIR/${CHART_NAME}-${CHART_VERSION}.tgz"
    
    if [ -f "$CHART_PACKAGE" ]; then
        log_info "Chart packaged successfully: $CHART_PACKAGE"
    else
        log_error "Failed to package chart"
        exit 1
    fi
}

# Push chart to ECR
push_chart() {
    log_info "Pushing chart to ECR..."
    
    # For ECR, we need to push to the registry root, not include the repository name in the OCI URL
    # The repository name is determined from the chart name
    OCI_URL="oci://${ECR_REGISTRY}"
    
    log_info "Pushing to: $OCI_URL"
    log_info "Chart package: $CHART_PACKAGE"
    
    # First, let's make sure we're logged in
    aws ecr get-login-password --region "$AWS_REGION" | helm registry login --username AWS --password-stdin "$ECR_REGISTRY" 2>/dev/null
    
    # Push the chart - Helm will use the chart name from the package
    helm push "$CHART_PACKAGE" "$OCI_URL" 2>&1 | tee /tmp/helm-push.log
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        log_info "Chart pushed successfully!"
        log_info "Full chart reference: ${ECR_REGISTRY}/${CHART_NAME}:${CHART_VERSION}"
    else
        log_error "Failed to push chart to ECR"
        log_error "Error output:"
        cat /tmp/helm-push.log
        exit 1
    fi
}

# Verify the pushed chart
verify_chart() {
    log_info "Verifying pushed chart..."
    
    # Pull the chart to verify it was pushed correctly
    VERIFY_DIR=$(mktemp -d)
    
    # For ECR, the chart is available at registry/chart-name
    PULL_URL="oci://${ECR_REGISTRY}/${CHART_NAME}"
    
    log_info "Attempting to pull from: $PULL_URL"
    
    helm pull "$PULL_URL" --version "$CHART_VERSION" --destination "$VERIFY_DIR" 2>&1 | tee /tmp/helm-verify.log
    
    if [ -f "$VERIFY_DIR/${CHART_NAME}-${CHART_VERSION}.tgz" ]; then
        log_info "Chart verified successfully!"
        
        # Show chart info
        log_info "Chart information:"
        helm show chart "$VERIFY_DIR/${CHART_NAME}-${CHART_VERSION}.tgz"
    else
        log_warning "Could not verify chart pull, but push might have succeeded"
        log_warning "Verify output:"
        cat /tmp/helm-verify.log
    fi
    
    # Cleanup
    rm -rf "$VERIFY_DIR"
    rm -f /tmp/helm-verify.log
}

# Cleanup function
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Main execution
main() {
    log_info "Starting Helm chart publish to ECR"
    log_info "AWS Account ID: $AWS_ACCOUNT_ID"
    log_info "AWS Region: $AWS_REGION"
    log_info "Chart Path: $CHART_PATH"
    log_info "Chart Name: $CHART_NAME"
    
    check_prerequisites
    get_chart_version
    create_ecr_repository
    ecr_login
    package_chart
    push_chart
    verify_chart
    
    log_info "✅ Helm chart published successfully!"
    log_info ""
    log_info "To use this chart:"
    log_info "  helm pull oci://${ECR_REGISTRY}/${CHART_NAME} --version ${CHART_VERSION}"
    log_info "  helm install my-release oci://${ECR_REGISTRY}/${CHART_NAME} --version ${CHART_VERSION}"
}

# Run main function
main