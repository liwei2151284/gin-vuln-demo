package model

import "time"

// Withdraw 提现记录
// [CWE-223] 提现成功后无任何日志写入，操作不可追溯
type Withdraw struct {
	ID            uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	PlayerID      uint      `gorm:"index;not null"           json:"player_id"`
	Amount        float64   `gorm:"not null"                 json:"amount"`
	BankAccount   string    `gorm:"not null"                 json:"bank_account"`
	Status        string    `gorm:"default:'pending'"        json:"status"`
	CreatedAt     time.Time `                                json:"created_at"`
}
