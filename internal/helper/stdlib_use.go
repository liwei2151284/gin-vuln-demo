// [SCA场景九] stdlib CVE 可见性
// net/http 是 Go 标准库，不出现在 go.mod 的 require 中。
// stdlib 的 CVE 由 Go 工具链版本决定，与依赖图数据库完全分离：
//   go 1.18 → CVE-2022-27664（net/http HTTP/2 DoS，< go1.18.6）
//   go 1.18 → CVE-2022-41717（net/http 内存耗尽，< go1.18.7）
// 此函数调用 net/http，使 SCA 工具可通过调用图分析关联到上述 CVE。
package helper

import (
	"fmt"
	"net/http"
)

// StdlibHTTPVersion 显式调用 net/http，关联 stdlib CVE（故意预埋）
func StdlibHTTPVersion() string {
	return fmt.Sprintf("net/http server via go toolchain %s", http.StatusText(200))
}
