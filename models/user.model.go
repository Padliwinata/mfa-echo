package models

import (
	uuid "github.com/satori/go.uuid"
)

type User struct {
	ID       uuid.UUID `gorm:"type:uuid;primary_key;" json:"id"`
	Key      string    `json:"key"`
	Name     string    `gorm:"type:varchar(255);not null" json:"name"`
	Email    string    `gorm:"uniqueIndex;not null" json:"email"`
	Password string    `gorm:"not null" json:"password"`

	Otp_enabled  bool `gorm:"default:false;" json:"otp_enabled"`
	Otp_verified bool `gorm:"default:false;" json:"otp_verified"`

	Otp_secret   string `json:"otp_secret"`
	Otp_auth_url string `json:"otp_auth_url"`
}

func (user *User) BeforeCreate() error {
	user.ID = uuid.NewV4()

	return nil
}

type RegisterUserInput struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" bindinig:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginUserInput struct {
	Email    string `json:"email" bindinig:"required"`
	Password string `json:"password" binding:"required"`
}

type OTPInput struct {
	UserId string `json:"user_id"`
	Token  string `json:"token"`
}
