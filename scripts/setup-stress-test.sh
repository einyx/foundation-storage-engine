#!/bin/bash

# Setup script for stress test buckets
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get Docker host
DOCKER_HOST="${DOCKER_REMOTE_HOST:-localhost}"
PROXY_ENDPOINT="http://admin:secret@${DOCKER_HOST}:8082"

echo -e "${BLUE}Setting up stress test buckets${NC}"
echo -e "${BLUE}===========================================${NC}"

# Create test buckets
buckets=("internal-data" "sensitive-data" "financial-data")

for bucket in "${buckets[@]}"; do
    echo -e "${YELLOW}Creating bucket: ${bucket}${NC}"
    if curl -sf -X PUT "${PROXY_ENDPOINT}/${bucket}" > /dev/null; then
        echo -e "${GREEN}✓ Created bucket: ${bucket}${NC}"
    else
        echo -e "${YELLOW}! Bucket might already exist: ${bucket}${NC}"
    fi
done

echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN}Stress test buckets ready!${NC}"
echo -e "${GREEN}===========================================${NC}"

echo -e "${BLUE}Now you can run the stress test:${NC}"
echo "export PROXY_ENDPOINT=http://${DOCKER_HOST}:8082"
echo "./tests/stress/run_stress_test.sh"
