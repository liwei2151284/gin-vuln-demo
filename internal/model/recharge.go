package model

import "time"

// Recharge 充值记录模型
type Recharge struct {
	ID            uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	PlayerID      uint      `gorm:"index;not null"           json:"player_id"`
	Amount        float64   `gorm:"not null"                 json:"amount"`
	Currency      string    `gorm:"default:'CNY'"            json:"currency"`
	PaymentMethod string    `gorm:"not null"                 json:"payment_method"`
	PaymentToken  string    `gorm:"not null"                 json:"payment_token"`
	Status        string    `gorm:"default:'pending'"        json:"status"`
	Remark        string    `                                json:"remark"`
	CreatedAt     time.Time `                                json:"created_at"`
}
