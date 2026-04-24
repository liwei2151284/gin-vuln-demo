package handler

import (
	"crypto/rand"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── JWT 辅助 ──────────────────────────────────────────────────────────────────

// [SAFE] 修复原因：从环境变量读取密钥，替代硬编码 "secret123"
func safeJWTSecret() []byte {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return []byte(s)
	}
	// 若环境变量未设置，使用足够长的占位密钥（生产环境必须通过 env 注入）
	return []byte("REPLACE_ME_WITH_256BIT_ENV_SECRET_IN_PRODUCTION")
}

// parseJWTUID 从 Authorization: Bearer <token> 中提取 uid
func parseJWTUID(authHeader string) (uint, bool) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return 0, false
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return safeJWTSecret(), nil
	})
	if err != nil || !token.Valid {
		return 0, false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, false
	}
	uid, ok := claims["uid"].(float64)
	return uint(uid), ok
}

// ── 内存限流 ──────────────────────────────────────────────────────────────────

type rateBucket struct {
	mu        sync.Mutex
	attempts  []time.Time
}

var loginRateMap sync.Map   // key: username → *rateBucket
var withdrawRateMap sync.Map // key: playerID → *rateBucket

// [SAFE] 修复原因：滑动窗口限流，window 内超过 max 次则拒绝
func checkRate(m *sync.Map, key string, window time.Duration, max int) bool {
	v, _ := m.LoadOrStore(key, &rateBucket{})
	b := v.(*rateBucket)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)
	valid := b.attempts[:0]
	for _, t := range b.attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	b.attempts = valid

	if len(b.attempts) >= max {
		return false
	}
	b.attempts = append(b.attempts, now)
	return true
}

// ── 密码学安全随机数 ──────────────────────────────────────────────────────────

// [SAFE] 修复原因：使用 crypto/rand 替代 math/rand，生成 8 位邀请码
func cryptoRandInviteCode() (string, error) {
	const digits = "0123456789"
	const length = 8
	code := make([]byte, length)
	for i := range code {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[n.Int64()]
	}
	return string(code), nil
}

// ── SSRF 内网 IP 过滤 ─────────────────────────────────────────────────────────

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
		"::1/128", "fc00::/7", "fe80::/10",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, network)
	}
}

// [SAFE] 修复原因：拒绝私有/链路本地 IP，防止 SSRF 访问内网
func isPrivateAddr(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// ── 日志脱钩 ──────────────────────────────────────────────────────────────────

// [SAFE] 修复原因：替换换行符，防止 CWE-117 日志注入
func sanitizeLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// ── CSRF Origin 校验 ─────────────────────────────────────────────────────────

var allowedOrigins = map[string]bool{
	"http://localhost:8080":  true,
	"https://game.example.com": true,
}

// [SAFE] 修复原因：校验 Origin 头，阻止跨站写入请求
func isOriginAllowed(origin string) bool {
	if origin == "" {
		return true // 非浏览器请求（如 curl）无 Origin
	}
	return allowedOrigins[origin]
}
