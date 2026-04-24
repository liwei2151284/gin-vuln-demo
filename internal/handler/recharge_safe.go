package handler

import (
	"log"
	"net/http"
	"os"
	"time"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
)

// [SAFE] 修复原因：CWE-798 — 从环境变量读取支付密钥，不硬编码在源码中
func safePaymentAPIKey() string {
	if k := os.Getenv("PAYMENT_API_KEY"); k != "" {
		return k
	}
	return "UNSET_CONFIGURE_VIA_ENV"
}

// RechargeSafe POST /api/recharge/safe
func RechargeSafe(c *gin.Context) {
	var req RechargeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [SAFE] 修复原因：CWE-209 — 玩家不存在时返回通用错误，不暴露堆栈或 SQL
	var player model.Player
	if err := database.DB.First(&player, req.PlayerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "操作失败，请稍后重试"})
		return
	}

	// [SAFE] 修复原因：CWE-532 — 日志仅记录脱敏字段，token 仅保留末 4 位，不记录 API Key 明文
	maskedToken := "****"
	if len(req.PaymentToken) >= 4 {
		maskedToken = "****" + req.PaymentToken[len(req.PaymentToken)-4:]
	}
	log.Printf("[RECHARGE_SAFE] player_id=%d amount=%.2f method=%s token=%s",
		req.PlayerID, req.Amount, req.PaymentMethod, maskedToken)
	// [SAFE] 修复原因：CWE-798 — API Key 通过函数获取，不直接出现在日志或源码常量中
	_ = safePaymentAPIKey() // 仅在调用网关时使用，不记录到日志

	currency := req.Currency
	if currency == "" {
		currency = "CNY"
	}
	record := model.Recharge{
		PlayerID:      req.PlayerID,
		Amount:        req.Amount,
		Currency:      currency,
		PaymentMethod: req.PaymentMethod,
		PaymentToken:  maskedToken, // 存储脱敏值
		Status:        "success",
	}
	database.DB.Create(&record)
	database.DB.Model(&player).Update("balance", player.Balance+req.Amount)

	c.JSON(http.StatusOK, gin.H{
		"message":     "充值成功",
		"recharge_id": record.ID,
		"balance":     player.Balance + req.Amount,
	})
}

// ExportSafe GET /api/recharge/export/safe
func ExportSafe(c *gin.Context) {
	filter := c.Query("filter")

	// [SAFE] 修复原因：CWE-117 — 对 filter 参数脱钩换行符，防止日志注入/伪造
	safeFilter := sanitizeLog(filter)
	log.Printf("[EXPORT_SAFE] filter=%s time=%s", safeFilter, time.Now().Format(time.RFC3339))

	var records []model.Recharge
	query := database.DB.Model(&model.Recharge{})
	if filter != "" {
		// [SAFE] 修复原因：使用参数化查询，filter 值不拼入 SQL
		query = query.Where("status = ?", filter)
	}
	query.Find(&records)

	c.JSON(http.StatusOK, gin.H{
		"total":   len(records),
		"records": records,
	})
}
