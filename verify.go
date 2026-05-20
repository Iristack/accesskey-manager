package akm

import (
	"context"
	"crypto/subtle"
	"fmt"
	"math"
	"sort"
	"time"
)

// Verifier AK/SK 请求验签器。
type Verifier struct {
	skStore          SKStore
	nonceStore       NonceStore
	timeWindow       time.Duration
	extendFields     map[string]string // field_name → header_name
	sortedFieldNames []string          // 预排序的 field_name 列表
}

// NewVerifier 创建验签器实例。
func NewVerifier(skStore SKStore, nonceStore NonceStore, cfg Config) *Verifier {
	tw := cfg.TimeWindow
	if tw <= 0 {
		tw = 5 * time.Minute
	}
	ef := make(map[string]string, len(cfg.ExtendFields))
	sortedKeys := make([]string, 0, len(cfg.ExtendFields))
	for k, v := range cfg.ExtendFields {
		ef[k] = v
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	return &Verifier{
		skStore:          skStore,
		nonceStore:       nonceStore,
		timeWindow:       tw,
		extendFields:     ef,
		sortedFieldNames: sortedKeys,
	}
}

// Verify 执行完整的验签流程：查 SK → 检查时间戳 → 比对签名 → 防重放。
//
// sortedQuery 应为按 key 字典序排序后的 query 字符串（可通过 SortQuery 获得）。
// body 为原始请求体字节（未经任何处理）。
func (v *Verifier) Verify(ctx context.Context, headers AuthHeaders, method, path, sortedQuery string, body []byte) error {
	// 1. 查 SK
	sk, err := v.skStore.GetSK(ctx, headers.AK)
	if err != nil {
		return fmt.Errorf("查询 SK 失败: %w", err)
	}
	if sk == "" {
		return ErrInvalidAK
	}

	// 2. 检查时间戳合法性
	if headers.Timestamp <= 0 {
		return ErrTimestampExpired
	}
	now := time.Now().Unix()
	diff := math.Abs(float64(now - headers.Timestamp))
	if diff > v.timeWindow.Seconds() {
		return ErrTimestampExpired
	}

	// 3. 重新计算签名并比对（在 Nonce 消耗之前）
	expected := BuildStringToSign(method, path, sortedQuery, body, headers.Timestamp, headers.Nonce, headers.ExtendFields)
	expectedSig := Sign(sk, expected)

	if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(headers.Signature)) != 1 {
		return ErrSignatureMismatch
	}

	// 4. Nonce 防重放（仅在签名验证通过后消耗 Nonce）
	exists, err := v.nonceStore.CheckAndSet(ctx, headers.Nonce, v.timeWindow*2)
	if err != nil {
		return fmt.Errorf("Nonce 校验失败: %w", err)
	}
	if exists {
		return ErrNonceReplayed
	}

	return nil
}
