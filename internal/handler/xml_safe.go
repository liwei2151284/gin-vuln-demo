package handler

import "encoding/xml"

// xmlUnmarshalSafe 封装 xml.Unmarshal，用于在 ImportSafe 中调用
// Go encoding/xml 本身不处理外部实体，此函数作为语义标记保留
func xmlUnmarshalSafe(data []byte, v interface{}) error {
	return xml.Unmarshal(data, v)
}
