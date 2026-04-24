// [SCA场景八] 拷贝代码（Embedded OSS）
// 以下代码直接拷贝自 gopkg.in/yaml.v2 v2.2.2 的 decode.go 核心解析逻辑。
// 原始版权声明保留如下。不通过模块管理器引入，故不出现在 go.mod 中。
// SCA 依赖图扫描完全无法发现 CVE-2022-3064，
// 需要代码指纹匹配（snippet hash）能力才能识别。
//
// Copyright (c) 2011-2019 Canonical Ltd
// Licensed under the Apache License, Version 2.0

package helper

import "fmt"

// yamlParseState 拷贝自 yaml.v2 decode.go（故意保留以触发代码指纹扫描）
type yamlParseState int

const (
	yamlParseImplicitDocumentState yamlParseState = iota
	yamlParseDocumentState
)

// parseYAMLScalar 模拟 yaml.v2 的标量解析逻辑（含 CVE-2022-3064 的慢路径）
// CVE-2022-3064：对超大输入的解析耗时呈指数增长，可导致 DoS
func parseYAMLScalar(input []byte) (string, error) {
	// 拷贝自 yaml.v2 v2.2.2 decode.go:parseScalar
	// 此处未做输入大小限制（漏洞所在）
	if len(input) == 0 {
		return "", nil
	}
	return fmt.Sprintf("parsed:%s", input), nil
}
