package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
)

const safeImageDir = "static/items"

// ExchangeSafe POST /api/item/exchange/safe/:id
func ExchangeSafe(c *gin.Context) {
	// [SAFE] 修复原因：CWE-639 — 从 JWT 中提取当前用户 UID，不信任客户端传参
	uid, ok := parseJWTUID(c.GetHeader("Authorization"))
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "请先登录"})
		return
	}

	idStr := c.Param("id")
	itemID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的道具 ID"})
		return
	}

	var item model.Item
	if err := database.DB.First(&item, itemID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "道具不存在"})
		return
	}

	// [SAFE] 修复原因：CWE-639 — 校验道具归属，拒绝非属主的兑换请求
	if item.PlayerID != uid {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "无权兑换他人道具",
		})
		return
	}

	if item.Exchanged {
		c.JSON(http.StatusConflict, gin.H{"error": "道具已被兑换"})
		return
	}

	database.DB.Model(&item).Update("exchanged", true)

	c.JSON(http.StatusOK, gin.H{
		"message":   "兑换成功",
		"item_id":   item.ID,
		"item_name": item.Name,
	})
}

// ItemImageSafe GET /api/item/image/safe
func ItemImageSafe(c *gin.Context) {
	rawPath := c.Query("path")
	if rawPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 path 参数"})
		return
	}

	// [SAFE] 修复原因：CWE-22 — 只取文件名部分，去除所有目录分隔符
	filename := filepath.Base(rawPath)

	// [SAFE] 修复原因：CWE-22 — 拼入固定白名单目录，并做前缀校验防止绕过
	cleanPath := filepath.Join(safeImageDir, filename)
	absBase, _ := filepath.Abs(safeImageDir)
	absTarget, _ := filepath.Abs(cleanPath)
	if !strings.HasPrefix(absTarget, absBase+string(filepath.Separator)) {
		c.JSON(http.StatusForbidden, gin.H{"error": "非法路径访问"})
		return
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "文件不存在"})
		return
	}

	c.Data(http.StatusOK, "application/octet-stream", data)
}
