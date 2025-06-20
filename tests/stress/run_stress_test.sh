#!/bin/bash
# Script to run stress tests for S3 proxy with KMS

set -e

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Default test parameters
export PROXY_ENDPOINT="${PROXY_ENDPOINT:-http://localhost:8082}"
export RUN_STRESS_TESTS="true"

# Test scenarios
run_scenario() {
    local name=$1
    local concurrency=$2
    local duration=$3
    local min_size=$4
    local max_size=$5
    local read_ratio=$6

    print_info "Running scenario: $name"
    print_info "Concurrency: $concurrency, Duration: $duration, Size: $min_size-$max_size, Read ratio: $read_ratio"

    export STRESS_CONCURRENCY=$concurrency
    export STRESS_DURATION=$duration
    export OBJECT_SIZE_MIN=$min_size
    export OBJECT_SIZE_MAX=$max_size
    export READ_WRITE_RATIO=$read_ratio

    go test -tags=stress -v -run TestKMSStress ./tests/stress/... -timeout 30m

    print_success "Completed scenario: $name"
    echo ""
}

# Check if proxy is running
print_info "Checking S3 proxy at $PROXY_ENDPOINT..."
if ! curl -s -f "$PROXY_ENDPOINT/health" > /dev/null 2>&1; then
    print_warning "S3 proxy might not be running at $PROXY_ENDPOINT"
    print_info "For Docker setup: docker-compose -f docker-compose.kms.yml up -d"
    print_info "For local setup: go run cmd/s3proxy/main.go -c examples/config-kms-docker.yaml"
    exit 1
fi

print_success "S3 proxy is running"

# Run different stress test scenarios
print_info "Starting KMS stress test suite..."

# Scenario 1: High concurrency, small objects
run_scenario \
    "High Concurrency - Small Objects" \
    100 \
    "2m" \
    1024 \
    10240 \
    0.7

# Scenario 2: Medium concurrency, mixed objects
run_scenario \
    "Medium Concurrency - Mixed Objects" \
    50 \
    "3m" \
    1024 \
    1048576 \
    0.5

# Scenario 3: Low concurrency, large objects
run_scenario \
    "Low Concurrency - Large Objects" \
    10 \
    "2m" \
    1048576 \
    10485760 \
    0.3

# Scenario 4: Write-heavy workload
run_scenario \
    "Write-Heavy Workload" \
    75 \
    "2m" \
    10240 \
    102400 \
    0.1

# Scenario 5: Read-heavy workload
run_scenario \
    "Read-Heavy Workload" \
    75 \
    "2m" \
    10240 \
    102400 \
    0.9

print_success "All stress test scenarios completed!"

# Generate summary report
print_info "Generating summary report..."
cat > stress_test_report.md <<EOF
# S3 Proxy KMS Stress Test Report

Date: $(date)
Proxy Endpoint: $PROXY_ENDPOINT

## Test Scenarios

1. **High Concurrency - Small Objects**
   - Concurrency: 100 workers
   - Object Size: 1KB - 10KB
   - Read/Write Ratio: 70/30
   - Tests proxy's ability to handle many concurrent small requests

2. **Medium Concurrency - Mixed Objects**
   - Concurrency: 50 workers
   - Object Size: 1KB - 1MB
   - Read/Write Ratio: 50/50
   - Balanced test of typical workload

3. **Low Concurrency - Large Objects**
   - Concurrency: 10 workers
   - Object Size: 1MB - 10MB
   - Read/Write Ratio: 30/70
   - Tests KMS performance with large data volumes

4. **Write-Heavy Workload**
   - Concurrency: 75 workers
   - Object Size: 10KB - 100KB
   - Read/Write Ratio: 10/90
   - Tests KMS encryption performance

5. **Read-Heavy Workload**
   - Concurrency: 75 workers
   - Object Size: 10KB - 100KB
   - Read/Write Ratio: 90/10
   - Tests KMS decryption and caching

## Key Metrics to Monitor

- Request throughput (requests/second)
- Data throughput (MB/second)
- KMS operation count
- Latency percentiles (P50, P95, P99)
- Error rates
- Memory usage
- CPU utilization

## Recommendations

1. Monitor CloudWatch metrics for KMS throttling
2. Check S3 proxy logs for any errors
3. Verify data key cache hit rates
4. Review latency patterns for optimization opportunities
EOF

print_success "Report saved to stress_test_report.md"
