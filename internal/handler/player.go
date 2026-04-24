package handler

import (
	"math/rand"
	"net/http"
	"time"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// [CWE-321] JWT 签名密钥硬编码
const jwtSecret = "secret123"

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email"    binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Redirect string `json:"redirect"`
}

// Register POST /api/register
func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [CWE-310] 伪随机数生成邀请码，空间仅 0-99998，可枚举
	inviteCode := rand.Intn(99999)

	// [CWE-256] 密码直接明文写入数据库，不做任何哈希
	player := model.Player{
		Username: req.Username,
		Password: req.Password,
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

// Login POST /api/login
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [CWE-307] 无失败计数，无频率限制，允许无限爆破
	var player model.Player
	if err := database.DB.Where("username = ? AND password = ?", req.Username, req.Password).
		First(&player).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// [CWE-321] 使用硬编码的 "secret123" 签发 JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":      player.ID,
		"username": player.Username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token 生成失败"})
		return
	}

	// [CWE-601] 直接跳转到客户端传入的 redirect 参数，不校验域名
	if req.Redirect != "" {
		c.Redirect(http.StatusFound, req.Redirect)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   tokenStr,
	})
}
