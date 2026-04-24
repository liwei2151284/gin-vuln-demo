// [SCA场景五] 间接依赖 CVE：通过 ghodss/yaml 传递引入 yaml.v2 v2.2.2
// ghodss/yaml 是 JSON↔YAML 转换工具，其传递依赖 gopkg.in/yaml.v2 v2.2.2
// CVE-2022-3064 的来源在间接依赖层，不直接出现在此包的 require 中
// [与 PHP 差异] go.mod 以 // indirect 显式标记，PHP 只出现在 composer.lock
package helper

import "github.com/ghodss/yaml"

// ConvertJSONToYAML 通过 ghodss/yaml 间接触发 yaml.v2 CVE-2022-3064 风险路径
func ConvertJSONToYAML(jsonData []byte) ([]byte, error) {
	return yaml.JSONToYAML(jsonData)
}
