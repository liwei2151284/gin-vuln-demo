package handler

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const maxSingleWithdraw = 5000.0
const maxDailyWithdraw = 50000.0

// WithdrawSafe POST /api/withdraw/safe
func WithdrawSafe(c *gin.Context) {
	var req WithdrawRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [SAFE] 修复原因：CWE-639 — 从 JWT 提取当前用户 UID，强制与请求中 player_id 一致
	uid, ok := parseJWTUID(c.GetHeader("Authorization"))
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "请先登录"})
		return
	}
	if uid != req.PlayerID {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权操作他人账户"})
		return
	}

	// [SAFE] 修复原因：CWE-770 — 单次金额上限
	if req.Amount <= 0 || req.Amount > maxSingleWithdraw {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("单次提现金额需在 (0, %.0f] 元之间", maxSingleWithdraw),
		})
		return
	}

	// [SAFE] 修复原因：CWE-770 — 频率限制（每账号每分钟最多 3 次）
	rateKey := fmt.Sprintf("withdraw:%d", req.PlayerID)
	if !checkRate(&withdrawRateMap, rateKey, time.Minute, 3) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "提现过于频繁，请稍后再试"})
		return
	}

	// [SAFE] 修复原因：CWE-770 — 每日累计上限校验
	var dailyTotal float64
	today := time.Now().Format("2006-01-02")
	database.DB.Model(&model.Withdraw{}).
		Where("player_id = ? AND status = 'success' AND DATE(created_at) = ?", req.PlayerID, today).
		Select("COALESCE(SUM(amount), 0)").Scan(&dailyTotal)
	if dailyTotal+req.Amount > maxDailyWithdraw {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("今日已提现 %.2f 元，超出每日上限 %.0f 元", dailyTotal, maxDailyWithdraw),
		})
		return
	}

	var finalBalance float64
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		var player model.Player
		if err := tx.First(&player, req.PlayerID).Error; err != nil {
			return err
		}
		if player.Balance < req.Amount {
			return fmt.Errorf("余额不足")
		}
		if err := tx.Model(&player).Update("balance", player.Balance-req.Amount).Error; err != nil {
			return err
		}
		finalBalance = player.Balance - req.Amount
		return tx.Create(&model.Withdraw{
			PlayerID:    req.PlayerID,
			Amount:      req.Amount,
			BankAccount: req.BankAccount,
			Status:      "success",
		}).Error
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [SAFE] 修复原因：CWE-223 — 提现成功后写入结构化审计日志，含脱敏银行卡号
	maskedBank := "****"
	if len(req.BankAccount) >= 4 {
		maskedBank = "****" + req.BankAccount[len(req.BankAccount)-4:]
	}
	log.Printf("[WITHDRAW_AUDIT] player_id=%d amount=%.2f bank=%s ip=%s time=%s",
		req.PlayerID, req.Amount, maskedBank, c.ClientIP(),
		time.Now().Format(time.RFC3339))

	c.JSON(http.StatusOK, gin.H{
		"message": "提现成功",
		"balance": finalBalance,
	})
}

// WithdrawNotifySafe POST /api/withdraw/notify/safe
func WithdrawNotifySafe(c *gin.Context) {
	var req NotifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [SAFE] 修复原因：CWE-918 — 解析 URL 并限制协议，仅允许 https
	parsed, err := url.Parse(req.CallbackURL)
	if err != nil || parsed.Scheme != "https" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "callback_url 仅允许 https 协议"})
		return
	}

	// [SAFE] 修复原因：CWE-918 — DNS 解析后校验所有 IP，拒绝私有地址段
	addrs, err := net.LookupHost(parsed.Hostname())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名解析失败"})
		return
	}
	for _, addr := range addrs {
		if isPrivateAddr(addr) {
			c.JSON(http.StatusForbidden, gin.H{"error": "不允许回调到内网地址"})
			return
		}
	}

	resp, err := http.Get(req.CallbackURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "回调请求失败"})
		return
	}
	defer resp.Body.Close()
	// [SAFE] 修复原因：CWE-918 — 不将响应体回显给请求者，仅返回状态码
	io.Copy(io.Discard, resp.Body)

	c.JSON(http.StatusOK, gin.H{
		"message":     "回调已发送",
		"status_code": resp.StatusCode,
	})
}
