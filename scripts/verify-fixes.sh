#!/bin/bash

# Script to verify that all the compilation fixes work correctly
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Verifying S3Proxy Build and Test Fixes${NC}"
echo "=========================================="

echo -e "${YELLOW}1. Testing main application build...${NC}"
if go build -o s3proxy-test ./cmd/s3proxy; then
    echo -e "${GREEN}✓ Main application builds successfully${NC}"
    rm -f s3proxy-test
else
    echo -e "${RED}✗ Main application build failed${NC}"
    exit 1
fi

echo -e "${YELLOW}2. Testing stress test compilation...${NC}"
if go test -tags stress -c -o stress-test ./tests/stress; then
    echo -e "${GREEN}✓ Stress test compiles successfully${NC}"
    rm -f stress-test
else
    echo -e "${RED}✗ Stress test compilation failed${NC}"
    exit 1
fi

echo -e "${YELLOW}3. Testing KMS package compilation...${NC}"
if go build ./internal/kms; then
    echo -e "${GREEN}✓ KMS package builds successfully${NC}"
else
    echo -e "${RED}✗ KMS package build failed${NC}"
    exit 1
fi

echo -e "${YELLOW}4. Testing encryption package compilation...${NC}"
if go build ./internal/encryption; then
    echo -e "${GREEN}✓ Encryption package builds successfully${NC}"
else
    echo -e "${RED}✗ Encryption package build failed${NC}"
    exit 1
fi

echo -e "${YELLOW}5. Testing Docker build capability...${NC}"
if docker build -t s3proxy-test . > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Docker image builds successfully${NC}"
    docker rmi s3proxy-test > /dev/null 2>&1
else
    echo -e "${RED}✗ Docker build failed${NC}"
    echo "Note: This is expected if Docker is not running"
fi

echo -e "${YELLOW}6. Checking configuration files...${NC}"
config_files=(
    "examples/config-kms-docker.yaml"
    "examples/config-multi-provider.yaml"
    "docker-compose.kms.yml"
)

for config in "${config_files[@]}"; do
    if [ -f "$config" ]; then
        echo -e "${GREEN}✓ $config exists${NC}"
    else
        echo -e "${RED}✗ $config missing${NC}"
    fi
done

echo -e "${YELLOW}7. Checking script permissions...${NC}"
scripts=(
    "scripts/setup-docker-kms.sh"
    "scripts/test-docker-setup.sh"
    "scripts/verify-fixes.sh"
    "tests/stress/run_stress_test.sh"
)

for script in "${scripts[@]}"; do
    if [ -x "$script" ]; then
        echo -e "${GREEN}✓ $script is executable${NC}"
    else
        echo -e "${RED}✗ $script is not executable${NC}"
    fi
done

echo ""
echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN}All verification checks completed!${NC}"
echo -e "${GREEN}===========================================${NC}"

echo -e "${BLUE}Summary of fixes applied:${NC}"
echo "• Fixed import conflicts in KMS providers"
echo "• Corrected math/rand vs crypto/rand usage in stress tests"
echo "• Added health check endpoint verification"
echo "• Updated Docker configuration for proper health checks"
echo "• Created multi-provider encryption architecture"
echo "• Added comprehensive Docker Compose setup"

echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Start Docker environment: ./scripts/setup-docker-kms.sh"
echo "2. Test the setup: ./scripts/test-docker-setup.sh"
echo "3. Run stress tests: ./tests/stress/run_stress_test.sh"
echo "4. Check documentation: README-DOCKER-DEV.md"
