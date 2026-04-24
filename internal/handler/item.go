package handler

import (
	"net/http"
	"os"
	"strconv"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
)

// Exchange POST /api/item/exchange/:id
func Exchange(c *gin.Context) {
	idStr := c.Param("id")
	itemID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的道具 ID"})
		return
	}

	// [CWE-639] 仅凭路由 id 查询道具并兑换
	// 不校验该道具是否属于当前登录用户，任意用户可兑换他人道具（IDOR）
	var item model.Item
	if err := database.DB.First(&item, itemID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "道具不存在"})
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
		"owner_id":  item.PlayerID,
	})
}

// ItemImage GET /api/item/image
func ItemImage(c *gin.Context) {
	path := c.Query("path")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 path 参数"})
		return
	}

	// [CWE-22] 路径直接来自用户输入，不做任何过滤或规范化
	// 可传入 ../../.env、../../etc/passwd 等进行路径穿越
	data, err := os.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "文件读取失败", "path": path})
		return
	}

	c.Data(http.StatusOK, "application/octet-stream", data)
}
