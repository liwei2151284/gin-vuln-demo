package model

import "time"

// GameSave 游戏存档记录
type GameSave struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	PlayerID  uint      `gorm:"index;not null"           json:"player_id"`
	Filename  string    `gorm:"not null"                 json:"filename"`
	FilePath  string    `gorm:"not null"                 json:"file_path"`
	FileSize  int64     `                                json:"file_size"`
	CreatedAt time.Time `                                json:"created_at"`
}
