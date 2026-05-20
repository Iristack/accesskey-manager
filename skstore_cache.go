package akm

import (
	"context"
	"sync"
	"time"
)

type cacheEntry struct {
	sk     string
	expiry int64 // UnixNano
}

// CachedSKStore 包装 SKStore，提供本地内存缓存。
// 缓存命中时零网络开销，TTL 内 SK 变更存在不一致窗口。
type CachedSKStore struct {
	inner   SKStore
	ttl     time.Duration
	maxSize int
	mu      sync.RWMutex
	cache   map[string]cacheEntry
}

// NewCachedSKStore 创建缓存装饰器。maxSize 限制缓存条目数（0 表示不限制）。
func NewCachedSKStore(inner SKStore, ttl time.Duration, maxSize int) *CachedSKStore {
	return &CachedSKStore{
		inner:   inner,
		ttl:     ttl,
		maxSize: maxSize,
		cache:   make(map[string]cacheEntry),
	}
}

func (c *CachedSKStore) GetSK(ctx context.Context, ak string) (string, error) {
	c.mu.RLock()
	entry, ok := c.cache[ak]
	c.mu.RUnlock()
	if ok && time.Now().UnixNano() < entry.expiry {
		return entry.sk, nil
	}

	sk, err := c.inner.GetSK(ctx, ak)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	if c.maxSize <= 0 || len(c.cache) < c.maxSize {
		c.cache[ak] = cacheEntry{sk: sk, expiry: time.Now().Add(c.ttl).UnixNano()}
	}
	c.mu.Unlock()

	return sk, nil
}

// Invalidate 主动清除指定 AK 的缓存（SK 变更时调用）。
func (c *CachedSKStore) Invalidate(ak string) {
	c.mu.Lock()
	delete(c.cache, ak)
	c.mu.Unlock()
}
