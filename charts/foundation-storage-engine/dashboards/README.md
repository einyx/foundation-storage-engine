# Foundation Storage Engine - Grafana Dashboards

This directory contains Grafana dashboards for monitoring the Foundation Storage Engine.

## Available Dashboards

### 1. `foundation-storage-engine.json` - Main Dashboard
**Purpose**: Overview dashboard for general monitoring  
**Metrics Covered**:
- Request rate and error rate overview
- Request latency percentiles by bucket
- Memory usage and system health
- Basic throughput metrics

**Best For**: Daily operations monitoring, quick health checks

### 2. `foundation-storage-engine-complete.json` - Complete Metrics Dashboard  
**Purpose**: Comprehensive monitoring with all available metrics  
**Metrics Covered**:
- **System Overview**: Request rates, error rates, in-flight requests, goroutines
- **Request Metrics**: Request rates by method/bucket, duration percentiles, response sizes
- **Storage Operations**: Backend operations, durations, error rates
- **Data Transfer**: Upload/download rates, transfer speeds
- **Authentication & Security**: Auth attempts/failures, active tokens, rate limiting
- **KMS Operations**: Encryption operations, key management, cache performance
- **Cache Performance**: Hit/miss ratios, cache sizes
- **Connection Pools**: Active/idle connections, wait times
- **System Resources**: Memory usage, garbage collection, goroutines
- **Auth0 Metrics**: Login activity, JWT cache performance

**Best For**: Deep troubleshooting, performance analysis, security monitoring

## Deprecated Dashboards

### `foundation-storage-engine-old.json` and `foundation-storage-engine-enhanced-old.json`
These are the previous dashboards that have been replaced. They are kept for reference but should not be used for new deployments.

## Metrics Prerequisites

For the dashboards to work properly, ensure:

1. **Prometheus Scraping**: Service must have annotations:
   ```yaml
   prometheus.io/scrape: "true"
   prometheus.io/port: "8080"
   prometheus.io/path: "/metrics"
   ```

2. **Service Discovery**: Prometheus must be configured to discover services with these annotations

3. **Metrics Endpoint**: The application exposes metrics at `/metrics` on port 8080

## Dashboard Variables

Both dashboards use the following template variables:

- `DS_PROMETHEUS`: Prometheus datasource selector

## Metric Names Reference

All metrics use the prefix `foundation_storage_engine_` and include:

### Request Metrics
- `foundation_storage_engine_requests_total` - Total requests by method, bucket, status
- `foundation_storage_engine_request_duration_seconds` - Request duration histogram
- `foundation_storage_engine_requests_in_flight` - Current active requests
- `foundation_storage_engine_response_size_bytes` - Response size histogram

### Storage Metrics
- `foundation_storage_engine_storage_operations_total` - Storage backend operations
- `foundation_storage_engine_storage_operation_duration_seconds` - Storage operation durations
- `foundation_storage_engine_storage_errors_total` - Storage operation errors

### Authentication Metrics
- `foundation_storage_engine_auth_attempts_total` - Authentication attempts
- `foundation_storage_engine_auth_failures_total` - Authentication failures
- `foundation_storage_engine_auth_tokens_active` - Active authentication tokens

### KMS Metrics
- `foundation_storage_engine_kms_operations_total` - KMS operations
- `foundation_storage_engine_kms_operation_duration_seconds` - KMS operation durations
- `foundation_storage_engine_kms_data_keys_active` - Active encryption keys

### Cache Metrics
- `foundation_storage_engine_cache_hits_total` - Cache hits
- `foundation_storage_engine_cache_misses_total` - Cache misses
- `foundation_storage_engine_cache_size_bytes` - Current cache size

### System Metrics
- `foundation_storage_engine_memory_usage_bytes` - Memory usage
- `foundation_storage_engine_goroutines_count` - Active goroutines
- `foundation_storage_engine_gc_duration_seconds` - Garbage collection duration

### Auth0 Metrics
- `foundation_storage_engine_auth0_login_attempts_total` - Auth0 login attempts
- `foundation_storage_engine_auth0_jwt_cache_hits_total` - JWT cache hits

## Installation

These dashboards are automatically included when deploying the Foundation Storage Engine Helm chart. To manually import:

1. Copy the JSON content
2. Go to Grafana → Dashboards → Import
3. Paste the JSON content
4. Configure the Prometheus datasource
5. Save the dashboard

## Troubleshooting

### No Data Showing
1. Verify Prometheus is scraping the service endpoints
2. Check that the service has the correct annotations
3. Ensure the `/metrics` endpoint is accessible
4. Verify the Prometheus datasource is configured correctly in Grafana

### Missing Metrics
Some metrics may only appear when certain features are used:
- KMS metrics require encryption to be enabled
- Auth0 metrics require Auth0 authentication to be configured
- Cache metrics require caching to be enabled

### Performance Impact
The complete dashboard with all metrics may have higher query load. For production environments with high traffic, consider:
- Using longer refresh intervals (30s-60s)
- Using the main dashboard for routine monitoring
- Using the complete dashboard only for troubleshooting