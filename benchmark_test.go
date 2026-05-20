package akm

import (
	"context"
	"strings"
	"testing"
	"time"
)

func BenchmarkFullVerify(b *testing.B) {
	kp, _ := GenerateKeyPair()
	skStore := &mockSKStore{kvs: map[string]string{kp.AK: kp.SK}}
	nonceStore := &mockNonceStore{nonces: make(map[string]bool)}
	verifier := NewVerifier(skStore, nonceStore, DefaultConfig())

	body := []byte(`{"job_sn":"JOB-2024-001","action":"trigger","params":{"k1":"v1","k2":"v2","k3":"v3"}}`)
	method := "POST"
	path := "/api/v1/jobs/trigger"
	sortedQuery := SortQuery("page=1&size=10&order=desc&status=active&type=script")
	timestamp := time.Now().Unix()
	sig := signRequest(kp.SK, method, path, sortedQuery, body, timestamp, "bench-nonce", nil)
	headers := AuthHeaders{AK: kp.AK, Timestamp: timestamp, Nonce: "bench-nonce", Signature: sig}

	b.ResetTimer()
	for i := range b.N {
		nonceStore.mu.Lock()
		nonceStore.nonces = make(map[string]bool)
		nonceStore.mu.Unlock()
		headers.Nonce = "bench-nonce" + string(rune(i%100000))
		_ = verifier.Verify(context.Background(), headers, method, path, sortedQuery, body)
	}
}

func BenchmarkReadBody(b *testing.B) {
	sizes := []int{0, 1024, 65536, 1048576}

	for _, size := range sizes {
		b.Run(sizeLabel(size), func(b *testing.B) {
			raw := strings.Repeat("x", size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				r := strings.NewReader(raw)
				buf := make([]byte, size)
				_, _ = r.Read(buf)
			}
		})
	}
}

func BenchmarkSortQuery(b *testing.B) {
	queries := []struct {
		name  string
		query string
	}{
		{"empty", ""},
		{"1param", "a=1"},
		{"5params", "e=5&d=4&c=3&b=2&a=1"},
		{"20params", genQuery(20)},
	}

	for _, q := range queries {
		b.Run(q.name, func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				_ = SortQuery(q.query)
			}
		})
	}
}

func BenchmarkBuildStringToSign(b *testing.B) {
	body := []byte(`{"key":"value"}`)
	extendFields := map[string]string{"appcode": "my-app", "region": "cn-east"}

	b.Run("noExtend", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			_ = BuildStringToSign("POST", "/api/test", "a=1&b=2", body, 1700000000, "nonce", nil)
		}
	})
	b.Run("withExtend", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			_ = BuildStringToSign("POST", "/api/test", "a=1&b=2", body, 1700000000, "nonce", extendFields)
		}
	})
}

func BenchmarkSign(b *testing.B) {
	sk := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	strToSign := "POST\n/api/test\na=1&b=2\nabcdef1234567890\n1700000000\nnonce-001"
	b.ResetTimer()
	for range b.N {
		_ = Sign(sk, strToSign)
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	b.ResetTimer()
	for range b.N {
		_, _ = GenerateKeyPair()
	}
}

func sizeLabel(size int) string {
	switch {
	case size == 0:
		return "empty"
	case size < 2048:
		return "1KB"
	case size < 131072:
		return "64KB"
	default:
		return "1MB"
	}
}

func genQuery(n int) string {
	pairs := make([]string, n)
	for i := range n {
		pairs[i] = string(rune('a'+i%26)) + "=val" + string(rune('0'+i%10))
	}
	return strings.Join(pairs, "&")
}
