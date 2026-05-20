package akm

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	headerAK        = "X-AK"
	headerTimestamp = "X-Timestamp"
	headerNonce     = "X-Nonce"
	headerSignature = "X-Signature"

	maxBodySize = 10 << 20 // 10 MB
)

// GinAuth 返回 Gin 中间件，对每个请求执行 AK/SK 验签。
// 验证失败时返回 401 并中断请求链。
func GinAuth(verifier *Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		ak := c.GetHeader(headerAK)
		timestampStr := c.GetHeader(headerTimestamp)
		nonce := c.GetHeader(headerNonce)
		signature := c.GetHeader(headerSignature)

		if ak == "" || timestampStr == "" || nonce == "" || signature == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "缺少鉴权头: X-AK, X-Timestamp, X-Nonce, X-Signature",
			})
			return
		}

		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "X-Timestamp 格式错误，应为 Unix 秒级时间戳",
			})
			return
		}

		body, err := readBody(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"code":    500,
				"message": "读取请求体失败",
			})
			return
		}

		// 提取拓展字段
		var extendFields map[string]string
		if len(verifier.extendFields) > 0 {
			extendFields = make(map[string]string, len(verifier.extendFields))
			for fieldName, headerName := range verifier.extendFields {
				v := c.GetHeader(headerName)
				if v == "" {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"code":    401,
						"message": "缺少拓展鉴权头: " + headerName,
					})
					return
				}
				extendFields[fieldName] = v
			}
		}

		headers := AuthHeaders{
			AK:           ak,
			Timestamp:    timestamp,
			Nonce:        nonce,
			Signature:    signature,
			ExtendFields: extendFields,
		}

		sortedQuery := SortQueryCached(c.Request.URL.RawQuery)

		if err := verifier.Verify(c.Request.Context(), headers, c.Request.Method, c.Request.URL.Path, sortedQuery, body); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "鉴权失败",
			})
			return
		}

		c.Next()
	}
}

// readBody 读取请求体字节（最多 maxBodySize），并重置以便后续 handler 可重复读取。
// 若 Content-Length 已知且合法，使用一次精准分配；否则回退 LimitReader 路径。
func readBody(c *gin.Context) ([]byte, error) {
	cl := c.Request.ContentLength

	if cl > 0 && cl <= maxBodySize {
		body := make([]byte, cl)
		if _, err := io.ReadFull(c.Request.Body, body); err != nil {
			return nil, err
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
		return body, nil
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodySize {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
			"code":    413,
			"message": "请求体过大",
		})
		return nil, fmt.Errorf("body exceeds max size %d", maxBodySize)
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}
