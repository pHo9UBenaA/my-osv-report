# Performance Optimization Guide

This document explains the performance characteristics of osv-report and how its internal parameters affect fetch throughput.

## Overview

osv-report is optimized for efficient data fetching with the following features:

1. **Rate Limiting**: Prevents API throttling by limiting requests per second
2. **Parallel Processing**: Processes multiple vulnerabilities concurrently
3. **Batch Processing**: Processes entries in fixed batch sizes
4. **HTTP Timeout**: Prevents hanging on slow network connections
5. **Cursor-based Incremental Fetching**: Only fetches new or updated data

## Compiled-in Constants

All performance parameters are compiled-in constants defined in `internal/config/config.go`. To change them, edit the source and rebuild.

### Rate Limit

**Value**: `10.0` requests per second

Controls the maximum number of API requests per second. The client automatically retries with backoff on 429 errors.

**Trade-offs**:
- Higher values risk hitting API rate limits (429 errors)
- Lower values result in slower data fetching

### Max Concurrency

**Value**: `5` parallel requests

Controls the maximum number of concurrent API requests.

**Trade-offs**:
- Higher values: faster processing but more memory and network usage
- Lower values: slower but more stable
- Works in combination with rate limiting to prevent API throttling

### Batch Size

**Value**: `100` entries per batch

Controls the number of entries processed in each batch.

**Trade-offs**:
- Larger batches: better throughput but higher peak memory usage
- Smaller batches: more frequent database transactions but lower memory
- Each batch is processed with parallel processing (up to max concurrency)

### HTTP Timeout

**Value**: `30` seconds

Controls the per-request HTTP client timeout.

**Trade-offs**:
- Shorter timeout: faster failure detection but may fail on slow networks
- Longer timeout: more tolerance but may hang longer on network issues

### Data Retention Days

**Value**: configurable via `OSV_DATA_RETENTION_DAYS` (default: `7`)

This is the only performance-related parameter that can be changed at runtime.

**Trade-offs**:
- Longer retention: larger database, slower queries
- Shorter retention: smaller database, faster queries
- Old data is automatically deleted after each fetch

## Expected Performance

With the default constants on a good network connection:

| Ecosystem | Approximate Size | Fetch Time (initial) | Fetch Time (incremental) |
|-----------|-----------------|---------------------|-------------------------|
| Go        | ~2,000 vulns    | 3-5 minutes         | 10-30 seconds          |
| npm       | ~5,000 vulns    | 8-12 minutes        | 30-60 seconds          |
| PyPI      | ~1,500 vulns    | 2-4 minutes         | 10-30 seconds          |
| Maven     | ~3,000 vulns    | 5-8 minutes         | 20-40 seconds          |

*Note: Times vary based on network speed, API response time, and current ecosystem size*

## Monitoring

The application logs key performance metrics:

```
INFO starting vulnerability fetch ecosystems=[npm pypi] rateLimit=10 maxConcurrency=5 batchSize=100
INFO processing batch ecosystem=npm batchStart=0 batchEnd=100 total=1523
INFO completed ecosystem ecosystem=npm processed=1523 cursor=2025-10-04T10:30:00Z
```

### Tips

1. **Monitor API Rate Limit Errors**: if you see frequent 429 errors in the logs, the current rate limit may be too aggressive for your network conditions. Reduce `RateLimit` in `config.go` and rebuild.

2. **Balance Concurrency and Rate Limit**: effective rate is `min(RateLimit, MaxConcurrency / avg_request_time)`. With 200ms average latency: `5 concurrent * 5 req/sec = 25 req/sec theoretical max`, capped at 10 by the rate limiter.

3. **Database Size**: reduce `OSV_DATA_RETENTION_DAYS` to keep the database small. Run `VACUUM` on the SQLite file periodically if size is a concern.

## Benchmarking

```bash
# Test with small dataset
time OSV_ECOSYSTEMS=Go ./osv-report fetch

# Compare initial vs incremental
time OSV_ECOSYSTEMS=Go ./osv-report fetch   # initial
time OSV_ECOSYSTEMS=Go ./osv-report fetch   # incremental (much faster)
```

## Troubleshooting

### Problem: Processing is too slow

1. Check network latency to api.osv.dev
2. If needed, increase `MaxConcurrency` in `config.go` and rebuild
3. Verify no other rate limits are active (e.g., corporate proxy)

### Problem: Frequent 429 errors

1. Reduce `RateLimit` in `config.go` and rebuild (e.g., from 10.0 to 5.0)
2. Reduce `MaxConcurrency` if running multiple instances
3. The client automatically retries with exponential backoff

### Problem: High memory usage

1. Reduce `BatchSize` in `config.go` and rebuild (e.g., from 100 to 50)
2. Reduce `OSV_DATA_RETENTION_DAYS` (e.g., from 30 to 7)
3. Run `VACUUM` on the SQLite database

### Problem: Timeout errors

1. Increase `HTTPTimeout` in `config.go` and rebuild (e.g., from 30s to 60s)
2. Check network connectivity to api.osv.dev
3. Consider geographic proximity to API servers
