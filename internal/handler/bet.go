package handler

import (
	"fmt"
	"net/http"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
)

type BetRequest struct {
	PlayerID uint    `json:"player_id" binding:"required"`
	Amount   float64 `json:"amount"    binding:"required"`
	GameType string  `json:"game_type" binding:"required"`
}

type LeaderboardWriteRequest struct {
	PlayerID uint    `json:"player_id" binding:"required"`
	Name     string  `json:"name"      binding:"required"`
	Score    float64 `json:"score"     binding:"required"`
}

// Bet POST /api/bet
func Bet(c *gin.Context) {
	var req BetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var player model.Player
	if err := database.DB.First(&player, req.PlayerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "玩家不存在"})
		return
	}

	// [CWE-20] 不校验金额正负与上限，负数金额可反向增加余额；超大金额不受限
	// 无事务保护，余额扣减与下注记录写入非原子操作，并发场景下可产生数据不一致
	newBalance := player.Balance - req.Amount
	database.DB.Model(&player).Update("balance", newBalance)

	bet := model.Bet{
		PlayerID: req.PlayerID,
		Amount:   req.Amount,
		GameType: req.GameType,
		Result:   "pending",
	}
	database.DB.Create(&bet)

	c.JSON(http.StatusOK, gin.H{
		"message":    "下注成功",
		"bet_id":     bet.ID,
		"deducted":   req.Amount,
		"balance":    newBalance,
	})
}

// Leaderboard GET /api/leaderboard
func Leaderboard(c *gin.Context) {
	name := c.Query("name")

	// [CWE-89] 直接将 name 参数拼入 SQL 字符串，不使用参数绑定，存在 SQL 注入
	rawSQL := fmt.Sprintf(
		"SELECT * FROM leaderboard_entries WHERE name = '%s' ORDER BY score DESC",
		name,
	)

	var entries []model.LeaderboardEntry
	database.DB.Raw(rawSQL).Scan(&entries)

	c.JSON(http.StatusOK, gin.H{
		"query":   rawSQL,
		"total":   len(entries),
		"entries": entries,
	})
}

// LeaderboardWrite POST /leaderboard
func LeaderboardWrite(c *gin.Context) {
	var req LeaderboardWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// [CWE-352] 不校验 CSRF Token，不验证请求来源，任意跨站请求均可写入排行榜
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
