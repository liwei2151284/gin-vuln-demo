package model

import "time"

// Bet 下注记录
// [CWE-20] Amount 字段不校验正负与上限，由调用方原值写入
type Bet struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	PlayerID  uint      `gorm:"index;not null"           json:"player_id"`
	Amount    float64   `gorm:"not null"                 json:"amount"`
	GameType  string    `gorm:"not null"                 json:"game_type"`
	Result    string    `gorm:"default:'pending'"        json:"result"` // pending/win/lose
	Payout    float64   `gorm:"default:0"                json:"payout"`
	CreatedAt time.Time `                                json:"created_at"`
}

// LeaderboardEntry 排行榜条目
type LeaderboardEntry struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	PlayerID  uint      `gorm:"index;not null"           json:"player_id"`
	Name      string    `gorm:"not null"                 json:"name"`
	Score     float64   `gorm:"default:0"                json:"score"`
	CreatedAt time.Time `                                json:"created_at"`
}
