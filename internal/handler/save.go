package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
)

const uploadDir = "uploads/saves"

// SaveData gob 反序列化目标结构（CWE-502）
type SaveData struct {
	PlayerID uint
	Level    int
	Score    int64
	Items    []string
	Extra    interface{} // interface{} 允许任意类型注入
}

// SaveXML xml 解析结构（CWE-611）
type SaveXML struct {
	XMLName  xml.Name `xml:"save"`
	PlayerID string   `xml:"player_id"`
	Level    string   `xml:"level"`
	Score    string   `xml:"score"`
	Note     string   `xml:"note"`
}

// Upload POST /api/save/upload
func Upload(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未找到上传文件"})
		return
	}
	defer file.Close()

	// [CWE-434] 不校验文件扩展名和 MIME 类型，直接保存到公开目录
	// .php/.sh/.exe 等可执行文件均可上传
	filename := header.Filename
	savePath := filepath.Join(uploadDir, filename)

	dst, err := os.Create(savePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "文件保存失败"})
		return
	}
	defer dst.Close()
	size, _ := io.Copy(dst, file)

	// [CWE-78] filename 来自客户端 header.Filename，未调用 filepath.Base 净化
	// 直接拼入 shell 命令，未使用 exec.Command 参数化，可注入任意命令
	cmd := fmt.Sprintf("md5sum %s/%s", uploadDir, filename)
	out, err := exec.Command("sh", "-c", cmd).Output()
	md5result := ""
	if err == nil {
		md5result = string(out)
	}

	playerID := c.PostForm("player_id")
	record := model.GameSave{
		Filename: filename,
		FilePath: savePath,
		FileSize: size,
	}
	if playerID != "" {
		fmt.Sscanf(playerID, "%d", &record.PlayerID)
	}
	database.DB.Create(&record)

	c.JSON(http.StatusOK, gin.H{
		"message":  "上传成功",
		"filename": filename,
		"path":     savePath,
		"md5":      md5result,
		"size":     size,
	})
}

// Parse POST /api/save/parse
func Parse(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体为空"})
		return
	}

	// [CWE-502] base64 解码后直接用 encoding/gob 反序列化，不限制类型
	// 攻击者可构造恶意 gob 字节流触发任意类型实例化
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		// 也接受原始 gob 字节（不强制 base64）
		decoded = body
	}

	var data SaveData
	dec := gob.NewDecoder(bytes.NewReader(decoded))
	if err := dec.Decode(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "反序列化失败",
			"detail": err.Error(), // [CWE-209] 内部错误直接暴露
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "解析成功",
		"player_id": data.PlayerID,
		"level":     data.Level,
		"score":     data.Score,
		"items":     data.Items,
	})
}

// Import POST /api/save/import
func Import(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体为空"})
		return
	}

	// [CWE-611] xml.Unmarshal 不禁用外部实体，直接解析用户传入的 XML
	// 可通过 <!ENTITY xxe SYSTEM "file:///etc/passwd"> 读取任意本地文件
	var save SaveXML
	if err := xml.Unmarshal(body, &save); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "XML 解析失败",
			"detail": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "存档导入成功",
		"player_id": save.PlayerID,
		"level":     save.Level,
		"score":     save.Score,
		"note":      save.Note,
	})
}
