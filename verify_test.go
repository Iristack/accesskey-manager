package akm

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ======================== Mock Stores ========================

type mockSKStore struct {
	mu  sync.RWMutex
	kvs map[string]string // ak → sk
}

func (m *mockSKStore) GetSK(_ context.Context, ak string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sk, ok := m.kvs[ak]
	if !ok {
		return "", nil
	}
	return sk, nil
}

type mockNonceStore struct {
	mu     sync.RWMutex
	nonces map[string]bool
}

func (m *mockNonceStore) CheckAndSet(_ context.Context, nonce string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nonces[nonce] {
		return true, nil // 已存在 → 重放
	}
	m.nonces[nonce] = true
	return false, nil
}

// ======================== Test Helpers ========================

func signRequest(sk, method, path, sortedQuery string, body []byte, timestamp int64, nonce string, extendFields map[string]string) string {
	strToSign := BuildStringToSign(method, path, sortedQuery, body, timestamp, nonce, extendFields)
	return Sign(sk, strToSign)
}

// ======================== Test Cases ========================

func TestNormalSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, DefaultConfig())

	body := []byte(`{"key":"value"}`)
	now := time.Now().Unix()
	nonce := "test-nonce-001"
	sortedQuery := SortQuery("b=2&a=1")
	sig := signRequest(kp.SK, "POST", "/api/test", sortedQuery, body, now, nonce, nil)

	headers := AuthHeaders{
		AK:        kp.AK,
		Timestamp: now,
		Nonce:     nonce,
		Signature: sig,
	}

	if err := verifier.Verify(context.Background(), headers, "POST", "/api/test", sortedQuery, body); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
}

func TestWrongSignature(t *testing.T) {
	kp, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, DefaultConfig())

	body := []byte(`{"a":1}`)
	now := time.Now().Unix()
	nonce := "nonce-wrong-sig"

	// 使用 kp2.SK 签名，但用 kp.AK 验签 → 签名不匹配
	sig := signRequest(kp2.SK, "GET", "/test", "", body, now, nonce, nil)
	headers := AuthHeaders{AK: kp.AK, Timestamp: now, Nonce: nonce, Signature: sig}

	err := verifier.Verify(context.Background(), headers, "GET", "/test", "", body)
	if err != ErrSignatureMismatch {
		t.Fatalf("expected ErrSignatureMismatch, got: %v", err)
	}
}

func TestExpiredTimestamp(t *testing.T) {
	kp, _ := GenerateKeyPair()

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	// 时间窗口 1 分钟
	verifier := NewVerifier(skStore, nonceStore, Config{TimeWindow: 1 * time.Minute})

	body := []byte(`{}`)
	// 6 分钟前的时间戳
	past := time.Now().Unix() - 6*60
	nonce := "nonce-expired"

	sig := signRequest(kp.SK, "GET", "/test", "", body, past, nonce, nil)
	headers := AuthHeaders{AK: kp.AK, Timestamp: past, Nonce: nonce, Signature: sig}

	err := verifier.Verify(context.Background(), headers, "GET", "/test", "", body)
	if err != ErrTimestampExpired {
		t.Fatalf("expected ErrTimestampExpired, got: %v", err)
	}
}

func TestNonceReplay(t *testing.T) {
	kp, _ := GenerateKeyPair()

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, DefaultConfig())

	body := []byte(`{}`)
	now := time.Now().Unix()
	nonce := "nonce-replay"
	sig := signRequest(kp.SK, "GET", "/test", "", body, now, nonce, nil)
	headers := AuthHeaders{AK: kp.AK, Timestamp: now, Nonce: nonce, Signature: sig}

	// 第一次应通过
	if err := verifier.Verify(context.Background(), headers, "GET", "/test", "", body); err != nil {
		t.Fatalf("first verify should pass, got: %v", err)
	}

	// 第二次 Nonce 重复 → 重放攻击
	if err := verifier.Verify(context.Background(), headers, "GET", "/test", "", body); err != ErrNonceReplayed {
		t.Fatalf("expected ErrNonceReplayed, got: %v", err)
	}
}

func TestBodyTampered(t *testing.T) {
	kp, _ := GenerateKeyPair()

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, DefaultConfig())

	originalBody := []byte(`{"amount":100}`)
	tamperedBody := []byte(`{"amount":999}`)
	now := time.Now().Unix()
	nonce := "nonce-tamper"

	// 客户端对原始 body 签名
	sig := signRequest(kp.SK, "POST", "/pay", "", originalBody, now, nonce, nil)
	headers := AuthHeaders{AK: kp.AK, Timestamp: now, Nonce: nonce, Signature: sig}

	// 服务端收到被篡改的 body → 验签失败
	err := verifier.Verify(context.Background(), headers, "POST", "/pay", "", tamperedBody)
	if err != ErrSignatureMismatch {
		t.Fatalf("expected ErrSignatureMismatch, got: %v", err)
	}
}

func TestInvalidAK(t *testing.T) {
	skStore := &mockSKStore{kvs: make(map[string]string)}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, DefaultConfig())

	headers := AuthHeaders{AK: "nonexistent", Timestamp: time.Now().Unix(), Nonce: "n", Signature: "xx"}
	err := verifier.Verify(context.Background(), headers, "GET", "/test", "", nil)
	if err != ErrInvalidAK {
		t.Fatalf("expected ErrInvalidAK, got: %v", err)
	}
}

func TestQueryOrderIndependence(t *testing.T) {
	kp, _ := GenerateKeyPair()

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, DefaultConfig())

	body := []byte(`{}`)
	now := time.Now().Unix()
	nonce := "nonce-query-order"

	// 客户端用排序后的 query 签名
	sortedQuery := SortQuery("c=3&a=1&b=2") // → "a=1&b=2&c=3"
	sig := signRequest(kp.SK, "GET", "/test", sortedQuery, body, now, nonce, nil)
	headers := AuthHeaders{AK: kp.AK, Timestamp: now, Nonce: nonce, Signature: sig}

	// 服务端也对相同 query 排序后验签 → 应通过
	serverSorted := SortQuery("a=1&c=3&b=2") // 同样排为 "a=1&b=2&c=3"
	if sortedQuery != serverSorted {
		t.Fatalf("SortQuery inconsistent: %q vs %q", sortedQuery, serverSorted)
	}

	if err := verifier.Verify(context.Background(), headers, "GET", "/test", serverSorted, body); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(kp.AK) != 20 {
		t.Fatalf("expected AK length 20, got %d", len(kp.AK))
	}
	if len(kp.SK) != 64 {
		t.Fatalf("expected SK length 64, got %d", len(kp.SK))
	}
	// 两次生成应不同
	kp2, _ := GenerateKeyPair()
	if kp.AK == kp2.AK || kp.SK == kp2.SK {
		t.Fatal("two KeyPairs should differ")
	}
}

func TestSortQuery(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"a=1", "a=1"},
		{"c=3&a=1&b=2", "a=1&b=2&c=3"},
		{"z=z&a=a", "a=a&z=z"},
	}

	for _, tc := range tests {
		result := SortQuery(tc.input)
		if result != tc.expected {
			t.Errorf("SortQuery(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestConfigDefaultTimeWindow(t *testing.T) {
	v := NewVerifier(
		&mockSKStore{kvs: make(map[string]string)},
		&mockNonceStore{nonces: make(map[string]bool)},
		Config{TimeWindow: 0},
	)
	if v.timeWindow != 5*time.Minute {
		t.Fatalf("expected default 5m time window, got %v", v.timeWindow)
	}
}

func TestExtendFieldsNormal(t *testing.T) {
	kp, _ := GenerateKeyPair()

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, Config{
		TimeWindow:   5 * time.Minute,
		ExtendFields: map[string]string{"appcode": "X-AppCode"},
	})

	body := []byte(`{"key":"value"}`)
	now := time.Now().Unix()
	nonce := "test-extend-001"
	extendFields := map[string]string{"appcode": "my-app"}
	sig := signRequest(kp.SK, "POST", "/api/test", "", body, now, nonce, extendFields)

	headers := AuthHeaders{
		AK:           kp.AK,
		Timestamp:    now,
		Nonce:        nonce,
		Signature:    sig,
		ExtendFields: extendFields,
	}

	if err := verifier.Verify(context.Background(), headers, "POST", "/api/test", "", body); err != nil {
		t.Fatalf("expected pass with extend fields, got: %v", err)
	}
}

func TestExtendFieldsMultiSorted(t *testing.T) {
	kp, _ := GenerateKeyPair()

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, Config{
		ExtendFields: map[string]string{"zulu": "X-Zulu", "alpha": "X-Alpha"},
	})

	body := []byte(`{}`)
	now := time.Now().Unix()
	nonce := "test-extend-sort"
	extendFields := map[string]string{"alpha": "a-val", "zulu": "z-val"}
	sig := signRequest(kp.SK, "GET", "/test", "", body, now, nonce, extendFields)

	headers := AuthHeaders{
		AK:           kp.AK,
		Timestamp:    now,
		Nonce:        nonce,
		Signature:    sig,
		ExtendFields: extendFields,
	}

	if err := verifier.Verify(context.Background(), headers, "GET", "/test", "", body); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
}

func TestExtendFieldsTampered(t *testing.T) {
	kp, _ := GenerateKeyPair()

	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, Config{
		ExtendFields: map[string]string{"appcode": "X-AppCode"},
	})

	body := []byte(`{}`)
	now := time.Now().Unix()
	nonce := "test-extend-tamper"
	extendFields := map[string]string{"appcode": "legit-app"}
	sig := signRequest(kp.SK, "GET", "/test", "", body, now, nonce, extendFields)

	// 篡改拓展字段
	headers := AuthHeaders{
		AK:           kp.AK,
		Timestamp:    now,
		Nonce:        nonce,
		Signature:    sig,
		ExtendFields: map[string]string{"appcode": "hacked-app"},
	}

	err := verifier.Verify(context.Background(), headers, "GET", "/test", "", body)
	if err != ErrSignatureMismatch {
		t.Fatalf("expected ErrSignatureMismatch, got: %v", err)
	}
}
