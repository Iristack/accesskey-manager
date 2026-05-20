# AK/SK 鉴权包

基于 HMAC-SHA256 的请求签名鉴权系统，提供身份认证、请求防篡改、防重放攻击。

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![EN](https://img.shields.io/badge/English-README_EN-blue)](README_EN.md)

## 架构

```
┌──────────────────────────────┐
│ middleware.go (Gin)          │  ← 集成层：提取 Header → 调用 Verifier
├──────────────────────────────┤
│ verify.go / sign.go          │  ← 引擎层：纯逻辑，零外部依赖
├──────────────────────────────┤
│ types.go (接口) / nonce.go (实现) │  ← 存储层：接口抽象 + Redis/Memory 实现
└──────────────────────────────┘
```

## 快速开始

### 安装

```bash
go get github.com/Iristack/accesskey-manager
```

### 5 分钟接入

**服务端** — 初始化 Verifier 并注册 Gin 中间件：

```go
// 1. 实现 SKStore（从数据库查 SK）
type mySKStore struct{ db *gorm.DB }
func (m *mySKStore) GetSK(ctx context.Context, ak string) (string, error) {
    // SELECT app_secret FROM config_signature WHERE app_id = ?
}

// 2. 初始化
skStore := akm.NewCachedSKStore(&mySKStore{db}, 60*time.Second, 0)
nonceStore := akm.NewRedisNonceStore(redisClient)
verifier := akm.NewVerifier(skStore, nonceStore, akm.Config{TimeWindow: 5 * time.Minute})

// 3. 注册中间件
api := router.Group("/api/open/v1")
api.Use(akm.GinAuth(verifier))
```

**客户端** — 生成签名并发送请求：

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

## 签名算法

```
StringToSign = Method        + "\n"
             + Path          + "\n"
             + SortedQuery        + "\n"
             + Hex(SHA256(Body)) + "\n"
             + Timestamp          + "\n"
             + Nonce
             + ExtendFields...  // 可选，按 key 字典序追加

Signature = Hex(HMAC-SHA256(SK, StringToSign))
```

### 签名示例

```
输入:
  AK        = "a1b2c3d4e5f6a7b8c9d0"
  SK        = "e3b0c44298fc1c149afbf4c8996fb924..."
  Method    = "POST"
  Path      = "/api/v1/jobs/trigger"
  RawQuery  = "page=1&size=10"
  Body      = {"job_sn":"JOB-2024-001"}
  Timestamp = 1716123456
  Nonce     = "x7k9m2p4-v8n1-r5q3-t6w0-y2a4b6c8d0e1"

Step 1: Query 字典序排序 → "page=1&size=10"
Step 2: Body SHA256      → "a7f5c8e3..."
Step 3: 拼接待签名字符串
Step 4: HMAC-SHA256(SK)  → "8f3a2e1b..."

请求 Header:
  X-AK: a1b2c3d4e5f6a7b8c9d0
  X-Timestamp: 1716123456
  X-Nonce: x7k9m2p4-v8n1-r5q3-t6w0-y2a4b6c8d0e1
  X-Signature: 8f3a2e1b...
```

## 验签流程

```
客户端                                服务端
  │                                     │
  │  POST /api/xxx                      │
  │  X-AK: {ak}                         │
  │  X-Timestamp: {ts} ──────────────→  1. 提取 Header
  │  X-Nonce: {nonce}                   2. 根据 AK 查 SK (SKStore)
  │  X-Signature: {sig}                 3. 校验 |now - ts| ≤ TimeWindow
  │                                     4. 重算签名 → ConstantTimeCompare
  │                                     5. Nonce 原子检查 (NonceStore)
  │                                     6. 通过 → 放行
```

## API 参考

### 核心接口

```go
type SKStore interface {
    GetSK(ctx context.Context, ak string) (sk string, err error)
}

type NonceStore interface {
    CheckAndSet(ctx context.Context, nonce string, ttl time.Duration) (exists bool, err error)
}
```

### AuthHeaders

绕过 `GinAuth` 直接调用 `Verifier.Verify()` 时需要传入此结构体：

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

### 默认配置

```go
cfg := akm.DefaultConfig() // TimeWindow: 5 分钟
verifier := akm.NewVerifier(skStore, nonceStore, cfg) // 与 DefaultConfig 对齐
```

`DefaultConfig()` 返回与 `NewVerifier` 默认值一致的配置，避免时间窗口不一致。

### 密钥生成

```go
kp, err := akm.GenerateKeyPair()
// kp.AK — 20 字符 hex
// kp.SK — 64 字符 hex（绝不打日志、不传输、不硬编码）
```

### Query 排序缓存

`GinAuth` 中间件默认使用 `SortQueryCached()` 对 query 参数排序，基于 LRU 缓存（容量 1024），并发安全。高频 API 场景下可消除重复排序开销。如需直接使用：

```go
sortedQuery := akm.SortQueryCached(c.Request.URL.RawQuery) // 缓存版
sortedQuery := akm.SortQuery(rawQuery)                     // 无缓存版
```

### 内建实现

| 接口 | 实现 | 说明 |
|------|------|------|
| `SKStore` | `CachedSKStore` | 本地缓存装饰器，TTL 可配（常用 60s），零 DB 穿透 |
| `NonceStore` | `RedisNonceStore` | 基于 Redis SETNX 原子操作 |
| `NonceStore` | `MemoryNonceStore` | 本地内存降级方案（含后台 GC） |

### 拓展字段

通过 `ExtendFields` 将业务 Header 纳入签名，防止篡改：

```go
verifier := akm.NewVerifier(skStore, nonceStore, akm.Config{
    TimeWindow: 5 * time.Minute,
    ExtendFields: map[string]string{
        "appcode": "X-AppCode",
    },
})
```

- 拓展字段按 `field_name` 字典序追加到 `StringToSign`
- 中间件自动从对应 Header 提取，缺失则返回 401
- 键/值含 `\n` `\r` 的字段自动跳过

### Gin 中间件

```go
// 一行接入
api.Use(akm.GinAuth(verifier))
```

中间件自动完成：Header 提取 → 时间戳校验 → Body 读取 → 拓展字段提取 → 签名验证 → Nonce 防重放。

## 错误码

| 错误 | HTTP | 含义 |
|------|------|------|
| `ErrInvalidAK` | 401 | AK 不存在 |
| `ErrTimestampExpired` | 401 | 时间戳超出允许窗口 |
| `ErrNonceReplayed` | 401 | Nonce 已被使用（重放攻击） |
| `ErrSignatureMismatch` | 401 | 签名不匹配（篡改或 SK 错误） |
| 缺少鉴权头 | 401 | 必需 Header 缺失 |
| X-Timestamp 格式错误 | 401 | 非 Unix 秒级时间戳 |
| 请求体读取失败 | 500 | Body 不可读 |
| 请求体过大 | 413 | 超过 10 MB |

## 安全机制

| 目标 | 机制 | 细节 |
|------|------|------|
| 身份真实性 | AK/SK 签名 | 只有持有正确 SK 的客户端才能生成合法签名 |
| 数据完整性 | 全参数签名 | Method、Path、Query、Body 均参与签名 |
| 防重放 | Timestamp + Nonce | 时间窗口 + Redis 原子 SETNX |
| SK 不传输 | 仅传签名结果 | 截获也无法逆推 SK |
| 防时序攻击 | `ConstantTimeCompare` | `crypto/subtle` 固定时间比较 |
| 防注入 | `\n` `\r` 过滤 | 拓展字段自动跳过含换行符的值 |

## 最佳实践

### 时钟同步

客户端和服务端均使用 NTP 同步。默认时间窗口 5 分钟，可通过 `Config.TimeWindow` 调整。Nonce TTL = `TimeWindow × 2`，确保请求在窗口边界处不会因 Nonce 过期而失败。

### 请求体大小

中间件限制 Body 最大 10 MB，超过返回 413。读取采用双路径策略：已知 `Content-Length` 时精准预分配一次读取；无法确定大小时回退 `LimitReader` 流式读取，最后通过 `NopCloser(Buffer)` 重置 Body 供后续 handler 复用。建议客户端控制在 1 MB 以内。大文件传输使用对象存储预签名 URL。

### Query 参数排序约定

`SortQuery` 对原始 query 字符串按 `&` 分割后以 ASCII 字典序排序。客户端和服务端必须使用相同的原始编码（percent-encoding），不要在签名前对 query 进行 URL-decode。

### SK 管理

- **绝不硬编码** — 从环境变量、KMS 或密钥管理服务读取
- **绝不打日志** — 不在日志、错误消息、追踪系统中输出 SK
- **定期轮换** — 定期调用 `GenerateKeyPair()` 轮换，旧 SK 保留一个时间窗口。轮换后调用 `cachedStore.Invalidate(ak)` 主动失效本地缓存，避免不一致窗口。

### 生产部署 Checklist

- [ ] 实现 `SKStore` 接口（从数据库/KMS 查询 SK）
- [ ] 使用 `CachedSKStore` 装饰器缓存 SK（减少 DB 查询）
- [ ] 配置 `NonceStore`（Redis 优先，`MemoryNonceStore` 降级）
- [ ] 注册 `GinAuth` 中间件到需鉴权的路由组
- [ ] （可选）启用速率限制
- [ ] 监控鉴权失败率和 Redis 连接状态

## License

MIT
