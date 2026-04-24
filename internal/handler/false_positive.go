package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/model"

	"github.com/gin-gonic/gin"
)

// ── 模块一：玩家注册登录 ────────────────────────────────────────────────────────

// FPPlayerInfo GET /fp/player/safe
// [FALSE-POSITIVE] 触发特征: reflect 包调用 → 工具标记 CWE-470（外部控制的类选择）
// 实际安全: reflect.TypeOf 操作固定编译期类型 model.Player{}，无用户输入参与任何反射路径
func FPPlayerInfo(c *gin.Context) {
	// [FALSE-POSITIVE] 触发特征: reflect.TypeOf / reflect.ValueOf | 实际安全: 操作固定类型，参数非用户控制
	t := reflect.TypeOf(model.Player{})
	fields := make([]string, t.NumField())
	for i := range fields {
		f := t.Field(i)
		fields[i] = fmt.Sprintf("%s %s", f.Name, f.Type)
	}
	c.JSON(http.StatusOK, gin.H{
		"model":  t.Name(),
		"fields": fields,
		"note":   "reflect 操作编译期固定类型，无用户输入参与，工具误报 CWE-470",
	})
}

// ── 模块二：充值支付 ────────────────────────────────────────────────────────────

// FPRechargeStats GET /fp/recharge/safe
// [FALSE-POSITIVE] 触发特征: fmt.Sprintf 拼接含 SQL 关键字的字符串 → gosec G201（SQL注入）
// 实际安全: Sprintf 的两个参数均为字符串字面量常量，不含任何用户输入，数据流无外部污染源
func FPRechargeStats(c *gin.Context) {
	// [FALSE-POSITIVE] 触发特征: fmt.Sprintf 构造 SQL | 实际安全: 两个参数均为字面量，非用户输入
	table := "recharges"
	status := "pending"
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE status = '%s'", table, status)
	var count int64
	database.DB.Raw(query).Scan(&count)
	c.JSON(http.StatusOK, gin.H{
		"pending_count": count,
		"query_used":    query,
		"note":          "fmt.Sprintf 两个插值均为字面量常量，gosec G201 误报 CWE-89",
	})
}

// ── 模块三：游戏下注 ────────────────────────────────────────────────────────────

// FPBetSummary GET /fp/bet/safe
// [FALSE-POSITIVE] 触发特征: database.DB.Exec/Raw 裸 SQL 调用 → 工具标记 CWE-89
// 实际安全: SQL 字符串为 const 字面量，编译期确定，无任何运行时变量或用户参数拼入
func FPBetSummary(c *gin.Context) {
	// [FALSE-POSITIVE] 触发特征: DB.Raw 裸SQL | 实际安全: SQL 为编译期 const，无用户输入
	const fixedSQL = "SELECT game_type, COUNT(*) AS cnt, SUM(amount) AS total FROM bets GROUP BY game_type"
	type BetRow struct {
		GameType string  `json:"game_type"`
		Cnt      int64   `json:"cnt"`
		Total    float64 `json:"total"`
	}
	var rows []BetRow
	database.DB.Raw(fixedSQL).Scan(&rows)
	c.JSON(http.StatusOK, gin.H{
		"stats": rows,
		"note":  "DB.Raw 参数为 const 字面量，无用户输入，工具误报 CWE-89",
	})
}

// ── 模块四：道具兑换 ────────────────────────────────────────────────────────────

// FPItemReadme GET /fp/item/safe
// [FALSE-POSITIVE] 触发特征: os.ReadFile(path) → gosec G304（路径穿越）
// 实际安全: path 为编译期字符串常量，不接受任何请求参数，无动态路径拼接
func FPItemReadme(c *gin.Context) {
	// [FALSE-POSITIVE] 触发特征: os.ReadFile | 实际安全: 路径为 const 字面量，非用户输入
	const fixedPath = "static/items/readme.txt"
	data, err := os.ReadFile(fixedPath)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"path":    fixedPath,
			"content": nil,
			"note":    "os.ReadFile 路径为 const 常量，文件不存在但不存在穿越风险，工具误报 CWE-22",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"path":    fixedPath,
		"content": string(data),
		"note":    "os.ReadFile 路径为 const 字面量，非用户输入，工具误报 CWE-22",
	})
}

// ── 模块五：提现功能 ────────────────────────────────────────────────────────────

// FPWithdrawHealthCheck GET /fp/withdraw/safe
// [FALSE-POSITIVE] 触发特征: http.Get(url) 变量传入 → gosec G107（SSRF）
// 实际安全: url 为 const 字符串常量，编译期固定，数据流中不存在任何用户可控输入节点
func FPWithdrawHealthCheck(c *gin.Context) {
	// [FALSE-POSITIVE] 触发特征: http.Get(variable) | 实际安全: URL 为 const 常量，无用户输入
	const healthURL = "https://httpbin.org/status/200"
	resp, err := http.Get(healthURL) //nolint:gosec // G107 false positive: URL is a compile-time constant
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"reachable": false,
			"url":       healthURL,
			"note":      "http.Get URL 为 const 常量，网络不可达但无 SSRF 风险，工具误报 CWE-918",
		})
		return
	}
	defer resp.Body.Close()
	c.JSON(http.StatusOK, gin.H{
		"reachable":   true,
		"status_code": resp.StatusCode,
		"url":         healthURL,
		"note":        "http.Get URL 为 const 字面量，非用户输入，工具误报 CWE-918",
	})
}

// ── 模块六：游戏存档上传 ────────────────────────────────────────────────────────

// FPSaveSystemInfo GET /fp/save/safe
// [FALSE-POSITIVE] 触发特征: exec.Command + xml.Unmarshal → gosec G204（命令注入）+ CWE-611（XXE）
// 实际安全: exec 的命令名与全部参数均为字面量常量；xml.Unmarshal 的输入为服务端硬编码字符串，无外部数据流
func FPSaveSystemInfo(c *gin.Context) {
	// [FALSE-POSITIVE] 触发特征: exec.Command | 实际安全: 命令和参数均为字面量常量，无用户输入
	out, _ := exec.Command("uname", "-s").Output() //nolint:gosec // G204 false positive: all args are literals

	// [FALSE-POSITIVE] 触发特征: xml.Unmarshal(input) | 实际安全: input 为服务端 const，无用户输入路径
	const fixedXML = `<save><player_id>0</player_id><level>0</level><score>0</score><note>health-check</note></save>`
	var save SaveXML
	_ = xml.Unmarshal([]byte(fixedXML), &save) //nolint:gosec // G402 false positive: input is a compile-time constant

	c.JSON(http.StatusOK, gin.H{
		"os_kernel": strings.TrimSpace(string(out)),
		"xml_parse": gin.H{
			"player_id": save.PlayerID,
			"note":      save.Note,
		},
		"note": "exec.Command/xml.Unmarshal 所有参数为编译期常量，无用户输入，工具误报 CWE-78/CWE-611",
	})
}
