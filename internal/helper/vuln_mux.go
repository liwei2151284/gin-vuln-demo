// [SCA场景七] 版本约束宽松：replace 本地路径完全脱离版本管控
// go.mod 中 replace github.com/gorilla/mux => ./packages/local-router
// 本地路径替换绕过 go.sum 哈希校验，包内容可任意修改而不被检测
// go mod verify 对本地路径替换无效，SCA 工具无法比对校验和
package helper

import "github.com/gorilla/mux"

// LocalRouter 使用本地 replace 路径替换的 gorilla/mux（故意预埋）
func LocalRouter() *mux.Router {
	return mux.NewRouter()
}
