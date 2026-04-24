// [SCA场景一] 直接依赖 CVE：github.com/gorilla/websocket v1.4.1
// CVE-2020-27813：Compression 扩展处理中的 WebSocket 帧可导致内存耗尽 DoS
package helper

import "github.com/gorilla/websocket"

// WebSocketDialer 使用存在 CVE-2020-27813 的 gorilla/websocket v1.4.1（故意预埋）
var WebSocketDialer = websocket.DefaultDialer
