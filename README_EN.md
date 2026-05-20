# AK/SK Authentication

HMAC-SHA256 based request signing for identity authentication, tamper-proofing, and replay attack prevention.

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![中文](https://img.shields.io/badge/中文-README-red)](README.md)

## Architecture

```
┌──────────────────────────────┐
│ middleware.go (Gin)          │  ← Integration: Extract headers → Invoke Verifier
├──────────────────────────────┤
│ verify.go / sign.go          │  ← Engine: Pure logic, zero external deps
├──────────────────────────────┤
│ types.go (interfaces) / nonce.go (impl) │  ← Storage: Interface abstraction + Redis/Memory impls
└──────────────────────────────┘
```

## Quick Start

### Installation

```bash
go get github.com/Iristack/accesskey-manager
```

### 5-Minute Quick Start

**Server-Side** — Initialize verifier and register Gin middleware:

```go
// 1. Implement SKStore (query SK from database)
type mySKStore struct{ db *gorm.DB }
func (m *mySKStore) GetSK(ctx context.Context, ak string) (string, error) {
    // SELECT app_secret FROM config_signature WHERE app_id = ?
}

// 2. Initialize verifier
skStore := akm.NewCachedSKStore(&mySKStore{db}, 60*time.Second, 0)
nonceStore := akm.NewRedisNonceStore(redisClient)
verifier := akm.NewVerifier(skStore, nonceStore, akm.Config{TimeWindow: 5 * time.Minute})

// 3. Register middleware
api := router.Group("/api/open/v1")
api.Use(akm.GinAuth(verifier))
```

**Client-Side** — Generate signature and send request:

```go
ak, sk := "your-ak", "your-sk"
body := []byte(`{"job_sn":"JOB-001"}`)
timestamp := time.Now().Unix()
nonce := uuid.New().String()

strToSign := akm.BuildStringToSign("POST", "/api/trigger", "", body, timestamp, nonce, nil)
sig := akm.Sign(sk, strToSign)

req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
req.Header.Set("X-AK", ak)
req.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
req.Header.Set("X-Nonce", nonce)
req.Header.Set("X-Signature", sig)
```

## Signing Algorithm

```
StringToSign = Method        + "\n"
             + Path          + "\n"
             + SortedQuery        + "\n"
             + Hex(SHA256(Body)) + "\n"
             + Timestamp          + "\n"
             + Nonce
             + ExtendFields...  // Optional, appended in key-sorted order

Signature = Hex(HMAC-SHA256(SK, StringToSign))
```

### Worked Example

```
Given:
  AK        = "a1b2c3d4e5f6a7b8c9d0"
  SK        = "e3b0c44298fc1c149afbf4c8996fb924..."
  Method    = "POST"
  Path      = "/api/v1/jobs/trigger"
  RawQuery  = "page=1&size=10"
  Body      = {"job_sn":"JOB-2024-001"}
  Timestamp = 1716123456
  Nonce     = "x7k9m2p4-v8n1-r5q3-t6w0-y2a4b6c8d0e1"

Step 1: Sort query        → "page=1&size=10"
Step 2: SHA256(body)      → "a7f5c8e3..."
Step 3: Build StringToSign
Step 4: HMAC-SHA256(SK)   → "8f3a2e1b..."

Request Headers:
  X-AK: a1b2c3d4e5f6a7b8c9d0
  X-Timestamp: 1716123456
  X-Nonce: x7k9m2p4-v8n1-r5q3-t6w0-y2a4b6c8d0e1
  X-Signature: 8f3a2e1b...
```

## Verification Flow

```
Client                                Server
  │                                     │
  │  POST /api/xxx                      │
  │  X-AK: {ak}                         │
  │  X-Timestamp: {ts} ─────────────→  1. Extract headers
  │  X-Nonce: {nonce}                   2. Lookup SK by AK (SKStore)
  │  X-Signature: {sig}                 3. Validate |now - ts| ≤ TimeWindow
  │                                     4. Recompute signature → ConstantTimeCompare
  │                                     5. Atomic nonce check (NonceStore)
  │                                     6. Pass → proceed
```

## API Reference

### Core Interfaces

```go
type SKStore interface {
    GetSK(ctx context.Context, ak string) (sk string, err error)
}

type NonceStore interface {
    CheckAndSet(ctx context.Context, nonce string, ttl time.Duration) (exists bool, err error)
}
```

### AuthHeaders

When calling `Verifier.Verify()` directly (bypassing `GinAuth`), populate this struct:

```go
headers := akm.AuthHeaders{
    AK:           c.GetHeader("X-AK"),
    Timestamp:    timestamp,
    Nonce:        c.GetHeader("X-Nonce"),
    Signature:    c.GetHeader("X-Signature"),
    ExtendFields: map[string]string{"appcode": c.GetHeader("X-AppCode")},
}
err := verifier.Verify(ctx, headers, method, path, sortedQuery, body)
```

### Default Config

```go
cfg := akm.DefaultConfig() // TimeWindow: 5 minutes
verifier := akm.NewVerifier(skStore, nonceStore, cfg) // aligned with DefaultConfig
```

`DefaultConfig()` returns a config consistent with `NewVerifier`'s internal default, avoiding time-window mismatches.

### Key Generation

```go
kp, err := akm.GenerateKeyPair()
// kp.AK — 20-char hex
// kp.SK — 64-char hex (never log, never transmit, never hardcode)
```

### Query Sort Cache

`GinAuth` middleware uses `SortQueryCached()` by default — an LRU-cached query sorter (capacity 1024, concurrency-safe). This eliminates repeated sort overhead for high-frequency APIs. For direct use:

```go
sortedQuery := akm.SortQueryCached(c.Request.URL.RawQuery) // cached
sortedQuery := akm.SortQuery(rawQuery)                     // uncached
```

### Built-in Implementations

| Interface | Implementation | Notes |
|-----------|---------------|-------|
| `SKStore` | `CachedSKStore` | In-memory cache decorator, configurable TTL (commonly 60s), zero DB hits on cache |
| `NonceStore` | `RedisNonceStore` | Redis SETNX atomic operation |
| `NonceStore` | `MemoryNonceStore` | Local memory fallback with background GC |

### Extend Fields

Include custom business headers in the signature to prevent tampering:

```go
verifier := akm.NewVerifier(skStore, nonceStore, akm.Config{
    TimeWindow: 5 * time.Minute,
    ExtendFields: map[string]string{
        "appcode": "X-AppCode",
    },
})
```

- Fields are appended to `StringToSign` in key-sorted order
- Middleware automatically extracts values from corresponding headers; returns 401 if missing
- Keys/values containing `\n` or `\r` are silently skipped

### Gin Middleware

```go
// One-liner
api.Use(akm.GinAuth(verifier))
```

The middleware handles: header extraction → timestamp validation → body read → extend field extraction → signature verification → nonce replay check.

## Error Codes

| Error | HTTP Status | Meaning |
|-------|-------------|---------|
| `ErrInvalidAK` | 401 | AK does not exist |
| `ErrTimestampExpired` | 401 | Timestamp outside allowed window |
| `ErrNonceReplayed` | 401 | Nonce already used (replay attack) |
| `ErrSignatureMismatch` | 401 | Signature mismatch (tampering or wrong SK) |
| Missing auth headers | 401 | Required headers absent |
| Bad X-Timestamp format | 401 | Not a Unix second timestamp |
| Body read failure | 500 | Request body unreadable |
| Body too large | 413 | Exceeds 10 MB limit |

## Security

| Goal | Mechanism | Details |
|------|-----------|---------|
| Identity | AK/SK signing | Only clients with correct SK can produce valid signatures |
| Integrity | Full-parameter signing | Method, Path, Query, Body all feed into signature |
| Anti-replay | Timestamp + Nonce | Time window + Redis atomic SETNX |
| SK protection | Signature-only transmission | SK never sent over the wire; cannot be reversed |
| Timing attacks | `ConstantTimeCompare` | `crypto/subtle` constant-time comparison |
| Injection | `\n` `\r` filtering | Extend fields with newlines are silently skipped |

## Best Practices

### Clock Synchronization

Both client and server must use NTP. Default time window is 5 minutes, configurable via `Config.TimeWindow`. Nonce TTL = `TimeWindow × 2` to prevent failures at window boundaries.

### Request Body Size

Middleware limits body to 10 MB max; returns 413 on exceed. Body reading uses a dual-path strategy: precise preallocation when `Content-Length` is known, falling back to `LimitReader` streaming for chunked requests. After reading, the body is reset via `NopCloser(Buffer)` for downstream handler reuse. Keep bodies under 1 MB for best performance. Use presigned URLs for large file transfers.

### Query Parameter Convention

`SortQuery` splits on `&` and sorts by ASCII dictionary order. Both client and server must use the identical raw encoding (percent-encoding form). Do not URL-decode queries before signing.

### SK Management

- **Never hardcode** — read from environment variables, KMS, or secrets manager
- **Never log** — no SK output in logs, errors, or traces
- **Rotate regularly** — call `GenerateKeyPair()` periodically; keep old SK for one time window during rotation. After rotation, call `cachedStore.Invalidate(ak)` to evict the local cache entry and avoid inconsistency windows.

### Production Checklist

- [ ] Implement `SKStore` (query SK from database / KMS)
- [ ] Wrap with `CachedSKStore` to reduce DB queries
- [ ] Configure `NonceStore` (Redis preferred, `MemoryNonceStore` as fallback)
- [ ] Register `GinAuth` middleware on protected route groups
- [ ] (Optional) Enable rate limiting
- [ ] Monitor auth failure rate and Redis connectivity

## License

MIT