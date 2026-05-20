package akm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const nonceKeyPrefix = "akm:nonce:"

// RedisNonceStore 基于 Redis 的 NonceStore 实现。
// 使用 SET key value NX EX ttl 原子命令保证并发安全。
type RedisNonceStore struct {
	client *redis.Client
}

// NewRedisNonceStore 创建 Redis Nonce 存储实例。
func NewRedisNonceStore(client *redis.Client) *RedisNonceStore {
	return &RedisNonceStore{client: client}
}

// CheckAndSet 原子检查并设置 nonce。
// 若 nonce 已存在（重放）返回 (true, nil)；首次出现则设置并返回 (false, nil)。
func (r *RedisNonceStore) CheckAndSet(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
	key := nonceKeyPrefix + nonce
	// SET key value NX EX ttl → NX 保证 key 不存在时才设置
	ok, err := r.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis SetNX 失败: %w", err)
	}
	// ok=true 表示首次设置成功（非重放），返回 false
	// ok=false 表示 key 已存在（重放），返回 true
	return !ok, nil
}

// MemoryNonceStore 基于本地内存的 NonceStore 实现。
// 用于 Redis 不可用时的降级方案。
// 注意：分布式部署下各实例 Nonce 不共享，但 Nonce 碰撞概率可忽略，且仍受时间窗口约束。
type MemoryNonceStore struct {
	mu    sync.Mutex
	items map[string]time.Time
}

// NewMemoryNonceStore 创建本地内存 Nonce 存储实例，并启动后台 GC 协程。
func NewMemoryNonceStore() *MemoryNonceStore {
	s := &MemoryNonceStore{items: make(map[string]time.Time)}
	go s.gc()
	return s
}

// CheckAndSet 原子检查并设置 nonce。
func (m *MemoryNonceStore) CheckAndSet(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if expiry, ok := m.items[nonce]; ok && time.Now().Before(expiry) {
		return true, nil // 重放
	}
	m.items[nonce] = time.Now().Add(ttl)
	return false, nil
}

// gc 后台定期清理过期的 nonce 条目，防止内存无限增长。
func (m *MemoryNonceStore) gc() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for k, v := range m.items {
			if now.After(v) {
				delete(m.items, k)
			}
		}
		m.mu.Unlock()
	}
}
