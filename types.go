package akm

import (
	"context"
	"errors"
	"time"
)

// KeyPair AK/SK 密钥对。
type KeyPair struct {
	AK string // 20 字符 hex（10 字节随机）
	SK string // 64 字符 hex（32 字节随机）
}

// Config 验签引擎配置。
type Config struct {
	TimeWindow   time.Duration     // 允许的时间偏移，默认 5 分钟
	ExtendFields map[string]string // 拓展字段：field_name → header_name，如 {"appcode": "X-AppCode"}
}

// DefaultConfig 返回默认配置（5 分钟时间窗口）。
func DefaultConfig() Config {
	return Config{TimeWindow: 5 * time.Minute}
}

// AuthHeaders 客户端发送的鉴权头。
type AuthHeaders struct {
	AK           string
	Timestamp    int64
	Nonce        string
	Signature    string
	ExtendFields map[string]string // 拓展字段：field_name → field_value，如 {"appcode": "my-app"}
}

// SKStore 提供根据 AK 查询 SK 的能力。
type SKStore interface {
	GetSK(ctx context.Context, ak string) (sk string, err error)
}

// NonceStore 提供 Nonce 防重放的原子检查与存储能力。
type NonceStore interface {
	// CheckAndSet 原子操作：如果 nonce 已存在返回 true（重放攻击），否则设置并返回 false。
	CheckAndSet(ctx context.Context, nonce string, ttl time.Duration) (exists bool, err error)
}

// 验签错误类型。
var (
	ErrInvalidAK         = errors.New("akm: AK 不存在")
	ErrTimestampExpired  = errors.New("akm: 时间戳已过期")
	ErrNonceReplayed     = errors.New("akm: Nonce 已被使用（重放攻击）")
	ErrSignatureMismatch = errors.New("akm: 签名不匹配")
)
