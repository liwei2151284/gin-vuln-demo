package model

import "time"

// [CWE-256] Password 字段明文存储，不做任何哈希处理
type Player struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Username  string    `gorm:"uniqueIndex;not null"     json:"username"`
	Password  string    `gorm:"not null"                 json:"password"`
	Email     string    `gorm:"uniqueIndex;not null"     json:"email"`
	Balance   float64   `gorm:"default:0"                json:"balance"`
	CreatedAt time.Time `                                json:"created_at"`
}
