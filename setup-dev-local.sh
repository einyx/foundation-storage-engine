#!/bin/bash

# Setup script for running foundation-storage-engine locally with dev namespace configuration

echo "Foundation Storage Engine - Local Dev Setup"
echo "=========================================="
echo ""
echo "This script sets up the local environment to match the Kubernetes dev namespace configuration."
echo ""

# Check if AWS credentials are configured
if ! aws sts get-caller-identity --region me-central-1 &>/dev/null; then
    echo "❌ AWS credentials not configured or invalid!"
    echo ""
    echo "You can configure credentials using:"
    echo "  - export AWS_ACCESS_KEY_ID=your_key"
    echo "  - export AWS_SECRET_ACCESS_KEY=your_secret"
    echo "  - export AWS_SESSION_TOKEN=your_token (if using temporary credentials)"
    echo ""
    echo "Or use AWS CLI profiles:"
    echo "  - aws configure --profile"
    echo "  - export AWS_PROFILE="
    exit 1
fi

echo "✅ AWS credentials detected"
echo ""

# Build the Docker image
echo "Building Docker image..."
docker compose -f docker-compose.dev.yml build

# Start the service
echo ""
echo "Starting foundation-storage-engine..."
docker compose -f docker-compose.dev.yml up -d

echo ""
echo "✅ Setup complete!"
echo ""
echo "Service is running at:"
echo "  - http://localhost:8080 (main endpoint)"
echo "  - http://localhost:9000 (MinIO compatibility)"
echo ""
echo ""
echo "All buckets map to prefixes in: dev-terraform-managed-bucket"
echo ""
echo "To test the connection:"
echo "  aws --endpoint-url http://localhost:9000 s3 ls --no-sign-request"
echo ""
echo "To view logs:"
echo "  docker compose -f docker-compose.dev.yml logs -f"
echo ""
echo "To stop the service:"
echo "  docker compose -f docker-compose.dev.yml down"
