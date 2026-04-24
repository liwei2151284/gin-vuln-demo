// [SCA场景二] 废弃包：github.com/russross/blackfriday v1.6.0
// 仓库已被作者 archived，官方建议使用 v2（github.com/russross/blackfriday/v2）
// 无直接 CVE，但属于无人维护包，存在未修复安全风险的隐患
package helper

import "github.com/russross/blackfriday"

// RenderMarkdown 使用已 archived 的 blackfriday v1（故意预埋）
func RenderMarkdown(input []byte) []byte {
	return blackfriday.MarkdownCommon(input)
}
