package models

import "time"

type User struct {
	ID uint `json:"id" gorm:"primary_key"`
	Name string `json:"name"`
	Email string `json:"email"`
	Password time.Time `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
