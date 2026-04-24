package handler

import (
	"net/http"
	"strings"
	"time"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// RegisterSafe POST /api/register/safe
func RegisterSafe(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [SAFE] 修复原因：CWE-256 — bcrypt hash 替代明文存储，cost=12 符合 OWASP 建议
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码处理失败"})
		return
	}

	// [SAFE] 修复原因：CWE-310 — crypto/rand 生成 8 位密码学安全邀请码
	inviteCode, err := cryptoRandInviteCode()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "邀请码生成失败"})
		return
	}

	player := model.Player{
		Username: req.Username,
		Password: string(hashed), // 存储 bcrypt hash
		Email:    req.Email,
	}
	if err := database.DB.Create(&player).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户名或邮箱已存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "注册成功",
		"id":          player.ID,
		"username":    player.Username,
		"invite_code": inviteCode,
	})
}

// LoginSafe POST /api/login/safe
func LoginSafe(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [SAFE] 修复原因：CWE-307 — 滑动窗口限流，5 分钟内失败 ≥5 次拒绝登录
	if !checkRate(&loginRateMap, req.Username, 5*time.Minute, 5) {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": "登录尝试过于频繁，请 5 分钟后重试",
		})
		return
	}

	var player model.Player
	if err := database.DB.Where("username = ?", req.Username).First(&player).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// [SAFE] 修复原因：CWE-256 — bcrypt 比对，避免时序攻击
	if err := bcrypt.CompareHashAndPassword([]byte(player.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// [SAFE] 修复原因：CWE-321 — 从环境变量读取 JWT 密钥，不硬编码
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":      player.ID,
		"username": player.Username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(safeJWTSecret())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token 生成失败"})
		return
	}

	// [SAFE] 修复原因：CWE-601 — 仅允许以 "/" 开头的相对路径，拒绝外部域名跳转
	if req.Redirect != "" {
		if !strings.HasPrefix(req.Redirect, "/") || strings.HasPrefix(req.Redirect, "//") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "redirect 仅允许相对路径"})
			return
		}
		c.Redirect(http.StatusFound, req.Redirect)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   tokenStr,
	})
}
