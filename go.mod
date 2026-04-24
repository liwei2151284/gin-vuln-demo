module gin-vuln-demo

// [SCA场景六] Go 版本 EOL：go 1.21 于 2023-12 进入维护期末段
// toolchain go1.21.0 为有已知漏洞的工具链版本（go1.21.1 才修复）
// go 指令 = 本模块要求的最低语言版本
// toolchain 指令 = 推荐使用的工具链版本（Go 1.21 引入，两者语义分离）
// SCA 需同时检查两个字段，不能只看 go 指令
go 1.21

toolchain go1.21.0

require (
	// ── 场景三：测试包流入生产 ───────────────────────────────────────────
	// testify 为测试专用包，此处引入 go.mod require（非 require-dev）
	// 在 internal/helper/debug_helper.go（非 _test.go）中被 import
	github.com/stretchr/testify v1.11.1
	golang.org/x/net v0.52.0 // indirect
)

require (
	github.com/bytedance/gopkg v0.1.4 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.1 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/gin-contrib/sse v1.1.1 // indirect
	github.com/gin-gonic/gin v1.12.0
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.2 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.1 // indirect
	golang.org/x/arch v0.26.0 // indirect
	golang.org/x/crypto v0.50.0
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.31.1
)

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/ghodss/yaml v1.0.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.4.1
	github.com/russross/blackfriday v1.6.0
	gopkg.in/yaml.v2 v2.2.2
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// ── 场景七：版本约束宽松（replace 本地目录，go.sum 不记录哈希）──────────────
replace github.com/gorilla/mux => ./packages/local-router
