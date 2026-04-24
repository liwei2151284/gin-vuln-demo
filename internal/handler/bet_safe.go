package handler

import (
	"net/http"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const maxBetAmount = 10000.0

// BetSafe POST /api/bet/safe
func BetSafe(c *gin.Context) {
	var req BetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [SAFE] 修复原因：CWE-20 — 校验金额必须为正数且不超过单次上限
	if req.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "下注金额必须大于 0"})
		return
	}
	if req.Amount > maxBetAmount {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "单次下注不超过 10000 元",
		})
		return
	}

	var finalBalance float64

	// [SAFE] 修复原因：CWE-20 — 余额扣减与记录写入包裹在同一事务，保证原子性
	err := database.DB.Transaction(func(tx *gorm.DB) error {
		var player model.Player
		// 行锁防止并发超额
		if err := tx.Set("gorm:query_option", "FOR UPDATE").
			First(&player, req.PlayerID).Error; err != nil {
			return err
		}
		if player.Balance < req.Amount {
			return gorm.ErrRecordNotFound // 复用错误触发余额不足提示
		}
		if err := tx.Model(&player).Update("balance", player.Balance-req.Amount).Error; err != nil {
			return err
		}
		finalBalance = player.Balance - req.Amount
		return tx.Create(&model.Bet{
			PlayerID: req.PlayerID,
			Amount:   req.Amount,
			GameType: req.GameType,
			Result:   "pending",
		}).Error
	})

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusBadRequest, gin.H{"error": "余额不足或玩家不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "下注失败，请重试"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "下注成功",
		"balance": finalBalance,
	})
}

// LeaderboardSafe GET /api/leaderboard/safe
func LeaderboardSafe(c *gin.Context) {
	name := c.Query("name")

	// [SAFE] 修复原因：CWE-89 — 使用 GORM 参数绑定，name 作为参数传入，不拼接 SQL
	var entries []model.LeaderboardEntry
	database.DB.Where("name = ?", name).
		Order("score DESC").
		Find(&entries)

	c.JSON(http.StatusOK, gin.H{
		"total":   len(entries),
		"entries": entries,
	})
}

// LeaderboardWriteSafe POST /leaderboard/safe
func LeaderboardWriteSafe(c *gin.Context) {
	// [SAFE] 修复原因：CWE-352 — 校验 Origin 头，拒绝非白名单来源的跨站请求
	origin := c.GetHeader("Origin")
	if !isOriginAllowed(origin) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "跨站请求被拒绝，Origin 不在允许列表中",
		})
		return
	}

	var req LeaderboardWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	entry := model.LeaderboardEntry{
		PlayerID: req.PlayerID,
		Name:     req.Name,
		Score:    req.Score,
	}
	database.DB.Create(&entry)

	c.JSON(http.StatusOK, gin.H{
		"message": "排行榜写入成功",
		"id":      entry.ID,
	})
}
