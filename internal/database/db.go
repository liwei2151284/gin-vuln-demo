package database

import (
	"gin-vuln-demo/internal/model"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Init() error {
	var err error
	DB, err = gorm.Open(sqlite.Open("game.db"), &gorm.Config{})
	if err != nil {
		return err
	}
	return DB.AutoMigrate(&model.Player{}, &model.Recharge{}, &model.Bet{}, &model.LeaderboardEntry{}, &model.Item{}, &model.Withdraw{}, &model.GameSave{})
}
