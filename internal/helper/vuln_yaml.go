// [SCA场景一] 直接依赖 CVE：gopkg.in/yaml.v2 v2.2.2
// CVE-2022-3064：yaml.Unmarshal 对超大输入的解析耗时呈指数增长，可导致 DoS
// 此文件确保 yaml.v2 被实际引用，go mod tidy 不会将其移除
package helper

import "gopkg.in/yaml.v2"

// ParseYAMLConfig 使用存在 CVE-2022-3064 的 yaml.v2 v2.2.2（故意预埋）
func ParseYAMLConfig(data []byte) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := yaml.Unmarshal(data, &out)
	return out, err
}
