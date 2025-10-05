# Performance Optimization Guide

This document explains the performance optimization features implemented in osv-scraper and how to configure them for your environment.

## Overview

The osv-scraper has been optimized for efficient data fetching with the following features:

1. **Rate Limiting**: Prevents API throttling by limiting requests per second
2. **Parallel Processing**: Processes multiple vulnerabilities concurrently
3. **Batch Processing**: Processes entries in configurable batch sizes
4. **HTTP Timeout**: Prevents hanging on slow network connections
5. **Cursor-based Incremental Fetching**: Only fetches new or updated data

## Configuration Parameters

All performance parameters can be configured via environment variables:

### OSV_RATE_LIMIT

**Description**: Maximum number of API requests per second

**Default**: `10.0` (10 requests per second)

**Recommendation**:
- **Development/Testing**: `5.0` - Conservative for testing
- **Production (single instance)**: `10.0` - Default, safe for OSV API
- **Production (multiple instances)**: `5.0` or lower - Distribute load across instances

**Impact**:
- Too high: Risk of hitting API rate limits (429 errors)
- Too low: Slower data fetching
- Automatic retry with backoff on 429 errors

```bash
export OSV_RATE_LIMIT=10.0
```

### OSV_MAX_CONCURRENCY

**Description**: Maximum number of concurrent API requests

**Default**: `5` (5 parallel requests)

**Recommendation**:
- **Small dataset (<1000 entries)**: `3-5` - Balanced performance
- **Medium dataset (1000-10000 entries)**: `5-10` - Higher throughput
- **Large dataset (>10000 entries)**: `10-20` - Maximum throughput
- **Limited bandwidth**: `2-3` - Reduce network pressure

**Impact**:
- Higher values: Faster processing but more memory and network usage
- Lower values: Slower but more stable
- Works with rate limiting to prevent API throttling

```bash
export OSV_MAX_CONCURRENCY=5
```

### OSV_BATCH_SIZE

**Description**: Number of entries to process in each batch

**Default**: `100` (100 entries per batch)

**Recommendation**:
- **Memory constrained environments**: `50-100` - Lower memory usage
- **Standard environments**: `100-500` - Balanced
- **High-memory environments**: `500-1000` - Faster processing

**Impact**:
- Larger batches: Better throughput but higher peak memory usage
- Smaller batches: More frequent database transactions but lower memory
- Each batch is processed with parallel processing

```bash
export OSV_BATCH_SIZE=100
```

### OSV_HTTP_TIMEOUT

**Description**: HTTP client timeout in seconds

**Default**: `30` (30 seconds)

**Recommendation**:
- **Fast network**: `15-30` - Quick failure detection
- **Slow/unreliable network**: `60-120` - More tolerance
- **Satellite/mobile connections**: `120+` - Maximum tolerance

**Impact**:
- Shorter timeout: Faster failure detection but may fail on slow networks
- Longer timeout: More tolerance but may hang longer on network issues

```bash
export OSV_HTTP_TIMEOUT=30
```

### OSV_DATA_RETENTION_DAYS

**Description**: Number of days to retain vulnerability data

**Default**: `7` (7 days)

**Recommendation**:
- **Daily monitoring**: `7-14` - Keep recent history
- **Weekly monitoring**: `30-60` - Longer retention
- **Compliance/audit**: `365+` - Long-term storage

**Impact**:
- Longer retention: Larger database, slower queries
- Shorter retention: Smaller database, faster queries
- Old data is automatically deleted after fetching

```bash
export OSV_DATA_RETENTION_DAYS=7
```

## Performance Scenarios

### Scenario 1: Fast Initial Fetch (First Time Setup)

Optimize for maximum speed on first run:

```bash
export OSV_RATE_LIMIT=10.0
export OSV_MAX_CONCURRENCY=10
export OSV_BATCH_SIZE=200
export OSV_HTTP_TIMEOUT=30
```

**Expected Performance**:
- ~100-200 entries/second (depending on network)
- High CPU and network usage
- Completes large ecosystems (npm, pypi) in 30-60 minutes

### Scenario 2: Daily Incremental Updates

Optimize for stability and consistency:

```bash
export OSV_RATE_LIMIT=5.0
export OSV_MAX_CONCURRENCY=3
export OSV_BATCH_SIZE=50
export OSV_HTTP_TIMEOUT=60
export OSV_DATA_RETENTION_DAYS=7
```

**Expected Performance**:
- ~30-50 entries/second
- Low resource usage
- Completes incremental updates in 1-5 minutes

### Scenario 3: Resource-Constrained Environment

Optimize for minimal resource usage:

```bash
export OSV_RATE_LIMIT=3.0
export OSV_MAX_CONCURRENCY=2
export OSV_BATCH_SIZE=25
export OSV_HTTP_TIMEOUT=90
```

**Expected Performance**:
- ~10-20 entries/second
- Very low memory and CPU usage
- Suitable for small VPS or containers with limited resources

### Scenario 4: Multiple Parallel Instances

When running multiple instances (e.g., for different ecosystems):

```bash
# Instance 1: npm, pypi
export OSV_ECOSYSTEMS=npm,pypi
export OSV_RATE_LIMIT=5.0
export OSV_MAX_CONCURRENCY=5

# Instance 2: go, maven
export OSV_ECOSYSTEMS=go,maven
export OSV_RATE_LIMIT=5.0
export OSV_MAX_CONCURRENCY=5
```

**Expected Performance**:
- Total: ~10 req/sec across all instances
- Shared API rate limit distribution
- Parallel ecosystem processing

## Monitoring and Optimization

### Performance Metrics

The application logs key performance metrics:

```
INFO starting vulnerability fetch ecosystems=[npm pypi] rateLimit=10 maxConcurrency=5 batchSize=100
INFO processing batch ecosystem=npm batchStart=0 batchEnd=100 total=1523
INFO completed ecosystem ecosystem=npm processed=1523 cursor=2025-10-04T10:30:00Z
```

### Optimization Tips

1. **Monitor API Rate Limit Errors**:
   - If you see frequent 429 errors, reduce `OSV_RATE_LIMIT`
   - The client automatically retries with exponential backoff

2. **Balance Concurrency and Rate Limit**:
   - Formula: `effective_rate = min(OSV_RATE_LIMIT, OSV_MAX_CONCURRENCY * request_time)`
   - If requests take 200ms: `5 concurrent * 5 req/sec = 25 req/sec theoretical max`
   - Rate limiter will cap at `OSV_RATE_LIMIT`

3. **Batch Size Tuning**:
   - Monitor memory usage during processing
   - Larger batches reduce transaction overhead
   - Adjust based on available memory

4. **Network Optimization**:
   - Use shorter timeouts on fast, reliable networks
   - Use longer timeouts on slow or unreliable connections
   - Consider running closer to OSV API servers (geographic proximity)

## Troubleshooting

### Problem: Processing is too slow

**Solutions**:
1. Increase `OSV_MAX_CONCURRENCY` (e.g., from 5 to 10)
2. Increase `OSV_BATCH_SIZE` (e.g., from 100 to 200)
3. Check network latency to api.osv.dev
4. Verify no other rate limits are active

### Problem: Frequent 429 errors

**Solutions**:
1. Reduce `OSV_RATE_LIMIT` (e.g., from 10 to 5)
2. Reduce `OSV_MAX_CONCURRENCY` (e.g., from 10 to 5)
3. Check if multiple instances are running
4. Wait for automatic retry with exponential backoff

### Problem: High memory usage

**Solutions**:
1. Reduce `OSV_BATCH_SIZE` (e.g., from 200 to 50)
2. Reduce `OSV_MAX_CONCURRENCY` (e.g., from 10 to 5)
3. Reduce `OSV_DATA_RETENTION_DAYS` (e.g., from 30 to 7)
4. Run vacuum on SQLite database

### Problem: Timeout errors

**Solutions**:
1. Increase `OSV_HTTP_TIMEOUT` (e.g., from 30 to 60)
2. Check network connectivity to api.osv.dev
3. Reduce concurrent requests to lower network pressure
4. Consider geographic proximity to API servers

## Performance Testing

### Benchmark Command

```bash
# Test with small dataset
time OSV_ECOSYSTEMS=go OSV_MAX_CONCURRENCY=5 ./osv-scraper -fetch

# Test with different concurrency levels
for conc in 1 2 5 10; do
  echo "Testing concurrency: $conc"
  time OSV_MAX_CONCURRENCY=$conc ./osv-scraper -fetch
done
```

### Expected Results

With default settings on a good network connection:

| Ecosystem | Approximate Size | Fetch Time (initial) | Fetch Time (incremental) |
|-----------|-----------------|---------------------|-------------------------|
| Go        | ~2,000 vulns    | 3-5 minutes         | 10-30 seconds          |
| npm       | ~5,000 vulns    | 8-12 minutes        | 30-60 seconds          |
| PyPI      | ~1,500 vulns    | 2-4 minutes         | 10-30 seconds          |
| Maven     | ~3,000 vulns    | 5-8 minutes         | 20-40 seconds          |

*Note: Times vary based on network speed, API response time, and current ecosystem size*

## Best Practices

1. **Start Conservative**: Begin with default values and adjust based on monitoring
2. **Incremental Tuning**: Change one parameter at a time and measure impact
3. **Monitor Logs**: Watch for errors and performance indicators
4. **Test Before Production**: Validate settings in development environment
5. **Document Changes**: Keep track of what works best for your environment
6. **Regular Reviews**: Re-evaluate settings as data volume grows
