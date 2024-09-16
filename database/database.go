package database

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"time"
)

type UserAuth struct {
	Guid           string `gorm:"primaryKey"`
	Mail           string
	RefreshTokenID *int
	Ipaddress      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	RefreshToken   RefreshToken `gorm:"foreignKey:RefreshTokenID;references:ID"`
}

type RefreshToken struct {
	ID           int `gorm:"primaryKey"`
	RefreshToken string
	Active       bool
}

var DB *gorm.DB

func InitDatabase(user, pass, dbname, host, port string) error {
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s password=%s port=%s", host, user, dbname, pass, port)
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	} else {
		migrateError := DB.AutoMigrate(&UserAuth{}, &RefreshToken{})
		if migrateError != nil {
			return migrateError
		}
		return nil
	}
}
