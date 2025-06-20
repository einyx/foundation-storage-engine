#!/bin/bash

# Setup script for S3Proxy with KMS using Docker Compose
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up S3Proxy with KMS encryption using Docker Compose${NC}"

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
        exit 1
    fi

    # Check if docker-compose is installed
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Docker Compose is not installed. Please install Docker Compose first.${NC}"
        exit 1
    fi

    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}AWS CLI is not installed. Please install AWS CLI first.${NC}"
        exit 1
    fi

    echo -e "${GREEN}All prerequisites met!${NC}"
}

# Check AWS profile
check_aws_profile() {
    echo -e "${YELLOW}Checking AWS profile 'dev'...${NC}"

    if ! aws configure list-profiles | grep -q "^dev$"; then
        echo -e "${RED}AWS profile 'dev' not found.${NC}"
        echo -e "${YELLOW}Creating AWS profile 'dev'...${NC}"
        echo "Please enter your AWS credentials for the dev profile:"
        aws configure --profile dev
    else
        echo -e "${GREEN}AWS profile 'dev' found!${NC}"
    fi

    # Test AWS credentials
    if ! aws sts get-caller-identity --profile dev &> /dev/null; then
        echo -e "${RED}AWS credentials for profile 'dev' are not working.${NC}"
        echo -e "${YELLOW}Please reconfigure your AWS profile:${NC}"
        aws configure --profile dev
    fi

    # Get AWS account info
    ACCOUNT_ID=$(aws sts get-caller-identity --profile dev --query Account --output text)
    REGION=$(aws configure get region --profile dev)
    echo -e "${GREEN}AWS Account ID: ${ACCOUNT_ID}${NC}"
    echo -e "${GREEN}AWS Region: ${REGION}${NC}"
}

# Create or check KMS key
setup_kms_key() {
    echo -e "${YELLOW}Setting up KMS key...${NC}"

    REGION=$(aws configure get region --profile dev)

    # Check if alias exists
    if aws kms describe-key --key-id alias/s3proxy-dev --profile dev &> /dev/null; then
        echo -e "${GREEN}KMS key alias 's3proxy-dev' already exists!${NC}"
        KEY_ID=$(aws kms describe-key --key-id alias/s3proxy-dev --profile dev --query KeyMetadata.KeyId --output text)
        echo -e "${GREEN}Key ID: ${KEY_ID}${NC}"
    else
        echo -e "${YELLOW}Creating KMS key for S3Proxy development...${NC}"

        # Create key
        KEY_ID=$(aws kms create-key \
            --description "S3Proxy Development Key" \
            --key-usage ENCRYPT_DECRYPT \
            --origin AWS_KMS \
            --profile dev \
            --query KeyMetadata.KeyId \
            --output text)

        echo -e "${GREEN}Created KMS key: ${KEY_ID}${NC}"

        # Create alias
        aws kms create-alias \
            --alias-name alias/s3proxy-dev \
            --target-key-id $KEY_ID \
            --profile dev

        echo -e "${GREEN}Created alias: alias/s3proxy-dev${NC}"
    fi

    # Export for docker-compose
    export KMS_KEY_ID="alias/s3proxy-dev"
    export AWS_REGION=$REGION
}

# Setup environment
setup_environment() {
    echo -e "${YELLOW}Setting up environment variables...${NC}"

    # Create .env file for docker-compose
    cat > .env << EOF
# AWS Configuration
AWS_PROFILE=dev
AWS_REGION=${AWS_REGION}
KMS_KEY_ID=${KMS_KEY_ID}

# S3Proxy Configuration
S3PROXY_PORT=8080
MINIO_PORT=9000
MINIO_CONSOLE_PORT=9001
EOF

    echo -e "${GREEN}Created .env file${NC}"
}

# Start services
start_services() {
    echo -e "${YELLOW}Starting Docker services...${NC}"

    # Build and start services
    docker-compose -f docker-compose.kms.yml up --build -d

    echo -e "${GREEN}Services started!${NC}"
    echo -e "${BLUE}Access points:${NC}"
    echo -e "  S3Proxy:     http://localhost:8082"
    echo -e "  MinIO:       http://localhost:9000"
    echo -e "  MinIO UI:    http://localhost:9001"
    echo ""
    echo -e "${BLUE}Credentials:${NC}"
    echo -e "  S3Proxy:     admin / secret"
    echo -e "  MinIO:       minioadmin / minioadmin"
}

# Test the setup
test_setup() {
    echo -e "${YELLOW}Testing the setup...${NC}"

    # Wait for services to be ready
    echo "Waiting for services to start..."
    sleep 10

    # Test S3Proxy health
    if curl -sf http://localhost:8082/health > /dev/null; then
        echo -e "${GREEN}S3Proxy is running!${NC}"
    else
        echo -e "${RED}S3Proxy health check failed${NC}"
        echo "Check logs with: docker-compose -f docker-compose.kms.yml logs s3proxy"
    fi

    # Test MinIO
    if curl -sf http://localhost:9000/minio/health/live > /dev/null; then
        echo -e "${GREEN}MinIO is running!${NC}"
    else
        echo -e "${RED}MinIO health check failed${NC}"
    fi
}

# LocalStack option
setup_localstack() {
    echo -e "${YELLOW}Would you like to use LocalStack instead of real AWS KMS? (y/n)${NC}"
    read -r USE_LOCALSTACK

    if [[ $USE_LOCALSTACK =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Starting with LocalStack...${NC}"
        docker-compose -f docker-compose.kms.yml --profile localstack up --build -d

        echo -e "${GREEN}LocalStack setup complete!${NC}"
        echo -e "${BLUE}Access points:${NC}"
        echo -e "  S3Proxy:     http://localhost:8082"
        echo -e "  MinIO:       http://localhost:9000"
        echo -e "  LocalStack:  http://localhost:4566"

        return 0
    fi
}

# Main execution
main() {
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}S3Proxy KMS Docker Setup${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # Ask about LocalStack first
    setup_localstack && return 0

    # Continue with real AWS setup
    check_prerequisites
    check_aws_profile
    setup_kms_key
    setup_environment
    start_services
    test_setup

    echo -e "${GREEN}===========================================${NC}"
    echo -e "${GREEN}Setup complete!${NC}"
    echo -e "${GREEN}===========================================${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Create a bucket: curl -X PUT http://admin:secret@localhost:8082/encrypted-bucket"
    echo "2. Upload a file: curl -X PUT http://admin:secret@localhost:8082/encrypted-bucket/test.txt -d 'Hello, encrypted world!'"
    echo "3. Download the file: curl http://admin:secret@localhost:8082/encrypted-bucket/test.txt"
    echo ""
    echo -e "${BLUE}Management:${NC}"
    echo "- View logs: docker-compose -f docker-compose.kms.yml logs -f"
    echo "- Stop services: docker-compose -f docker-compose.kms.yml down"
    echo "- Clean up: docker-compose -f docker-compose.kms.yml down -v"
}

# Run main function
main "$@"
