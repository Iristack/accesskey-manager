package akm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	akLen = 10 // AK 原始字节数
	skLen = 32 // SK 原始字节数
)

// GenerateKeyPair 生成新的 AK/SK 密钥对。
// AK = 20 字符 hex（10 字节随机），SK = 64 字符 hex（32 字节随机）。
func GenerateKeyPair() (*KeyPair, error) {
	akBytes := make([]byte, akLen)
	if _, err := rand.Read(akBytes); err != nil {
		return nil, fmt.Errorf("生成 AK 失败: %w", err)
	}

	skBytes := make([]byte, skLen)
	if _, err := rand.Read(skBytes); err != nil {
		return nil, fmt.Errorf("生成 SK 失败: %w", err)
	}

	return &KeyPair{
		AK: hex.EncodeToString(akBytes),
		SK: hex.EncodeToString(skBytes),
	}, nil
}

// BuildStringToSign 按规范拼接待签名字符串。
//
//	格式: Method + "\n" + Path + "\n" + SortedQuery + "\n" + Hex(SHA256(Body)) + "\n" + Timestamp + "\n" + Nonce
//	      + "\n" + ExtendField1Name=ExtendField1Value + ... （按 field_name 字典序）
func BuildStringToSign(method, path, sortedQuery string, body []byte, timestamp int64, nonce string, extendFields map[string]string) string {
	bodyHash := sha256Hex(body)
	s := fmt.Sprintf("%s\n%s\n%s\n%s\n%d\n%s", method, path, sortedQuery, bodyHash, timestamp, nonce)
	if len(extendFields) > 0 {
		keys := make([]string, 0, len(extendFields))
		for k, v := range extendFields {
			if !strings.ContainsAny(k, "\n\r") && !strings.ContainsAny(v, "\n\r") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			var sb strings.Builder
			sb.WriteString(s)
			for _, k := range keys {
				sb.WriteByte('\n')
				sb.WriteString(k)
				sb.WriteByte('=')
				sb.WriteString(extendFields[k])
			}
			return sb.String()
		}
	}
	return s
}

// Sign 使用 SK 对 stringToSign 进行 HMAC-SHA256 签名，返回 hex 字符串。
func Sign(sk, stringToSign string) string {
	mac := hmac.New(sha256.New, []byte(sk))
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil))
}

// SortQuery 将原始 query 字符串按 key 字典序排序后返回。
// 输入如 "c=3&a=1&b=2"，输出 "a=1&b=2&c=3"。
// 空字符串或仅含 "=" 的 key 会保留。
func SortQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	pairs := strings.Split(rawQuery, "&")
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
