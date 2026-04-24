package handler

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
)

// [CWE-798] 第三方支付网关生产环境 API Key 硬编码在源码中
const paymentAPIKey = "sk_live_4xK9mNpQrT2wVbYcZdEfGhJu"
const paymentEndpoint = "https://pay.example-gateway.com/v1/charge"

type RechargeRequest struct {
	PlayerID      uint    `json:"player_id"      binding:"required"`
	Amount        float64 `json:"amount"         binding:"required"`
	Currency      string  `json:"currency"`
	PaymentMethod string  `json:"payment_method" binding:"required"`
	PaymentToken  string  `json:"payment_token"  binding:"required"`
}

// Recharge POST /api/recharge
func Recharge(c *gin.Context) {
	var req RechargeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [CWE-532] 将含支付凭证的原始请求数据直接写入日志，明文泄露 payment_token 与 API Key
	log.Printf("[RECHARGE] player_id=%d amount=%.2f currency=%s method=%s payment_token=%s api_key=%s",
		req.PlayerID, req.Amount, req.Currency, req.PaymentMethod, req.PaymentToken, paymentAPIKey)

	// [CWE-209] 查询玩家不捕获异常，数据库报错（含表名、SQL 结构）直接返回给前端
	var player model.Player
	if err := database.DB.First(&player, req.PlayerID).Error; err != nil {
		stackTrace := string(debug.Stack())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":       err.Error(),
			"stack_trace": stackTrace,
			"db_query":    fmt.Sprintf("SELECT * FROM players WHERE id = %d LIMIT 1", req.PlayerID),
		})
		return
	}

	// [CWE-798] 使用硬编码密钥调用第三方支付网关
	fmt.Printf("[PAYMENT] endpoint=%s api_key=%s token=%s amount=%.2f\n",
		paymentEndpoint, paymentAPIKey, req.PaymentToken, req.Amount)

	currency := req.Currency
	if currency == "" {
		currency = "CNY"
	}

	record := model.Recharge{
		PlayerID:      req.PlayerID,
		Amount:        req.Amount,
		Currency:      currency,
		PaymentMethod: req.PaymentMethod,
		PaymentToken:  req.PaymentToken,
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

// Export GET /api/recharge/export
func Export(c *gin.Context) {
	filter := c.Query("filter")

	// [CWE-117] filter 参数未做任何脱钩，\n 可注入额外伪造日志行
	log.Printf("[EXPORT] filter=%s time=%s", filter, time.Now().Format(time.RFC3339))

	var records []model.Recharge
	query := database.DB.Model(&model.Recharge{})
	if filter != "" {
		query = query.Where("status = ?", filter)
	}
	query.Find(&records)

	c.JSON(http.StatusOK, gin.H{
		"total":   len(records),
		"records": records,
	})
}
