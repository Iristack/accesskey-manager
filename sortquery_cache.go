package akm

import (
	"container/list"
	"sync"
)

type cacheItem struct {
	key   string
	value string
}

// queryCache 基于 LRU 的 SortQuery 结果缓存，并发安全。
type queryCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	order    *list.List
}

func newQueryCache(capacity int) *queryCache {
	return &queryCache{
		capacity: capacity,
		items:    make(map[string]*list.Element, capacity),
		order:    list.New(),
	}
}

func (c *queryCache) get(rawQuery string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[rawQuery]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*cacheItem).value, true
	}
	return "", false
}

func (c *queryCache) set(rawQuery, sorted string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[rawQuery]; ok {
		elem.Value.(*cacheItem).value = sorted
		c.order.MoveToFront(elem)
		return
	}
	if c.order.Len() >= c.capacity {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*cacheItem).key)
		}
	}
	item := &cacheItem{key: rawQuery, value: sorted}
	elem := c.order.PushFront(item)
	c.items[rawQuery] = elem
}

// defaultQueryCache 包级缓存实例，容量 1024。
var defaultQueryCache = newQueryCache(1024)

// SortQueryCached 带 LRU 缓存的 SortQuery。对于高频重复 query 参数组合的 API，
// 缓存命中时零分配，避免每次 strings.Split + sort.Strings + strings.Join。
func SortQueryCached(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	if cached, ok := defaultQueryCache.get(rawQuery); ok {
		return cached
	}
	sorted := SortQuery(rawQuery)
	defaultQueryCache.set(rawQuery, sorted)
	return sorted
}
