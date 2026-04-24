package main

import (
	"log"

	"gin-vuln-demo/internal/database"
	"gin-vuln-demo/internal/handler"

	"github.com/gin-gonic/gin"
)

func main() {
	if err := database.Init(); err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}

	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	api := r.Group("/api")
	{
		api.POST("/register", handler.Register)
		api.POST("/login", handler.Login)
		api.POST("/recharge", handler.Recharge)
		api.GET("/recharge/export", handler.Export)
		api.POST("/bet", handler.Bet)
		api.GET("/leaderboard", handler.Leaderboard)
		api.POST("/item/exchange/:id", handler.Exchange)
		api.GET("/item/image", handler.ItemImage)
		api.POST("/withdraw", handler.Withdraw)
		api.POST("/withdraw/notify", handler.WithdrawNotify)
		api.POST("/save/upload", handler.Upload)
		api.POST("/save/parse", handler.Parse)
		api.POST("/save/import", handler.Import)
	}

	// [CWE-352] 排行榜写入单独挂载在根路径，无任何 CSRF 防护
	r.POST("/leaderboard", handler.LeaderboardWrite)

	// ── /safe 修复版路由（独立分组，不影响漏洞版本）────────────────────────────
	safe := r.Group("/safe")
	{
		// 模块一：玩家注册登录
		safe.POST("/register", handler.RegisterSafe)
		safe.POST("/login", handler.LoginSafe)

		// 模块二：充值支付
		safe.POST("/recharge", handler.RechargeSafe)
		safe.GET("/recharge/export", handler.ExportSafe)

		// 模块三：游戏下注
		safe.POST("/bet", handler.BetSafe)
		safe.GET("/leaderboard", handler.LeaderboardSafe)

		// 模块四：道具兑换
		safe.POST("/item/exchange/:id", handler.ExchangeSafe)
		safe.GET("/item/image", handler.ItemImageSafe)

		// 模块五：提现功能
		safe.POST("/withdraw", handler.WithdrawSafe)
		safe.POST("/withdraw/notify", handler.WithdrawNotifySafe)

		// 模块六：游戏存档上传
		safe.POST("/save/upload", handler.UploadSafe)
		safe.POST("/save/parse", handler.ParseSafe)
		safe.POST("/save/import", handler.ImportSafe)
	}

	// 模块三 CSRF 修复版（对应 POST /leaderboard 漏洞版）
	r.POST("/leaderboard/safe", handler.LeaderboardWriteSafe)

	// ── /fp 工具误报型假阳演示路由 ─────────────────────────────────────────────
	fp := r.Group("/fp")
	{
		// 模块一：reflect.TypeOf 固定类型 → 工具误报 CWE-470
		fp.GET("/player/safe", handler.FPPlayerInfo)
		// 模块二：fmt.Sprintf 拼接固定字面量 SQL → 工具误报 CWE-89
		fp.GET("/recharge/safe", handler.FPRechargeStats)
		// 模块三：DB.Raw const SQL → 工具误报 CWE-89
		fp.GET("/bet/safe", handler.FPBetSummary)
		// 模块四：os.ReadFile 固定常量路径 → 工具误报 CWE-22
		fp.GET("/item/safe", handler.FPItemReadme)
		// 模块五：http.Get 固定常量 URL → 工具误报 CWE-918
		fp.GET("/withdraw/safe", handler.FPWithdrawHealthCheck)
		// 模块六：exec.Command + xml.Unmarshal 固定常量参数 → 工具误报 CWE-78/CWE-611
		fp.GET("/save/safe", handler.FPSaveSystemInfo)
	}

	r.Run()
}
