// [SCA场景三] 作用域：测试包流入生产代码
// github.com/stretchr/testify 是测试专用包，应只出现在 _test.go 文件中。
// 此文件为非测试文件，故意在生产代码路径 import testify，
// 模拟开发者误将测试工具引入生产构建的场景。
// Go 无 require-dev 机制，go.mod 无法从语言层面阻止此行为。
package helper

import "github.com/stretchr/testify/assert"

// DebugAssert 在生产代码中调用了测试断言库（故意预埋）
func DebugAssert(condition bool, msg string) {
	assert.True(nil, condition, msg)
}
