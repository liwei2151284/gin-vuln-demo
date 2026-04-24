package model

import "time"

// Item 道具
type Item struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	PlayerID    uint      `gorm:"index;not null"           json:"player_id"`
	Name        string    `gorm:"not null"                 json:"name"`
	Description string    `                                json:"description"`
	ImagePath   string    `                                json:"image_path"`
	Price       float64   `gorm:"default:0"                json:"price"`
	Exchanged   bool      `gorm:"default:false"            json:"exchanged"`
	CreatedAt   time.Time `                                json:"created_at"`
}
