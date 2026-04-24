// Package yaml is a patched stub of gopkg.in/yaml.v2.
// [SCA场景十一] go.work 工作区覆盖演示：
// go.work 中的 replace 将真实 yaml.v2（含 CVE-2022-3064）
// 替换为此 stub，实际代码已变更但 go.mod 版本号未变。
// SCA 工具只扫 go.mod 时仍报告 CVE-2022-3064（版本感知盲点）。
package yaml

func Unmarshal(in []byte, out interface{}) error { return nil }
func Marshal(in interface{}) ([]byte, error)      { return nil, nil }
