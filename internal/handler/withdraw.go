package handler

import (
	"fmt"
	"io"
	"net/http"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
)

type WithdrawRequest struct {
	PlayerID    uint    `json:"player_id"    binding:"required"`
	Amount      float64 `json:"amount"       binding:"required"`
	BankAccount string  `json:"bank_account" binding:"required"`
}

type NotifyRequest struct {
	CallbackURL string `json:"callback_url" binding:"required"`
	WithdrawID  uint   `json:"withdraw_id"`
}

// Withdraw POST /api/withdraw
func Withdraw(c *gin.Context) {
	var req WithdrawRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [CWE-639] 仅凭请求体的 player_id 操作，不验证是否为当前 JWT 持有者
	// 任意用户可替换 player_id 对他人账户发起提现
	var player model.Player
	if err := database.DB.First(&player, req.PlayerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "玩家不存在"})
		return
	}

	// [CWE-770] 不校验提现频率，不设单次/每日金额上限，可无限频率大额提现
	if player.Balance < req.Amount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "余额不足"})
		return
	}

	database.DB.Model(&player).Update("balance", player.Balance-req.Amount)

	record := model.Withdraw{
		PlayerID:    req.PlayerID,
		Amount:      req.Amount,
		BankAccount: req.BankAccount,
		Status:      "success",
	}
	database.DB.Create(&record)

	// [CWE-223] 提现成功后不写任何日志，操作无法被审计追溯
	// 无 log.Printf / fmt.Println，金额变动对运营完全不可见

	c.JSON(http.StatusOK, gin.H{
		"message":     "提现成功",
		"withdraw_id": record.ID,
		"amount":      req.Amount,
		"balance":     player.Balance - req.Amount,
	})
}

// WithdrawNotify POST /api/withdraw/notify
func WithdrawNotify(c *gin.Context) {
	var req NotifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [CWE-918] 直接使用用户传入的 callback_url 发起 HTTP 请求（SSRF）
	// 不限制协议（file://、gopher:// 等）和目标地址
	// 可访问内网服务：169.254.169.254（云元数据）、localhost 等
	resp, err := http.Get(req.CallbackURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":        "回调请求失败",
			"callback_url": req.CallbackURL,
			"detail":       err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// 将内网响应体直接返回给攻击者
	c.JSON(http.StatusOK, gin.H{
		"message":      "回调已发送",
		"callback_url": req.CallbackURL,
		"status_code":  resp.StatusCode,
		"response":     fmt.Sprintf("%s", body),
	})
}
