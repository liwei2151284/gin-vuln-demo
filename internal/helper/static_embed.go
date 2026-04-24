// [SCA场景十四] go:embed 将含漏洞的第三方 JS 文件编译进二进制
// jQuery 1.8.3 含 CVE-2015-9251（XSS）、CVE-2019-11358（原型污染）
// 该文件及其版本信息完全不在 go.mod 依赖图中，
// SCA 工具通过依赖图扫描无法发现，需文件内容指纹（如 OSS Detector）识别
package helper

import _ "embed"

//go:embed static/jquery-1.8.3.min.js
var JQueryJS []byte

// JQueryVersion 返回嵌入的 jQuery 版本标识（不经过包管理器）
func JQueryVersion() string {
	return "jQuery 1.8.3 (embedded via go:embed, not in go.mod)"
}
