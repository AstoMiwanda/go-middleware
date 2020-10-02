package main

import (
	"github.com/dgrijalva/jwt-go"
)

// Claims struct for store payload jwt token
type Claims struct {
	Name    string `json:"name"`
	APIName string `json:"api_name"`
	IP      string `json:"ip"`
	NIK     string `json:"nik"`
	jwt.StandardClaims
}

// SecretKey struct
type SecretKey struct {
	Name    string `json:"nama_aplikasi"`
	APIName string `json:"nama_api"`
	IP      string `json:"ip"`
	Key     string `json:"secret_key"`
}

// Token struct
type Token struct {
	Token    string `json:"token"`
	IsMobile bool   `json:"mobile"`
}

// Reply struktur
type Reply struct {
	Error *Error      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

// Error struct is Error Model for response
type Error struct {
	Code    int         `gorm:"not null" json:"error_code"`
	Message string      `gorm:"not null" json:"error_message"`
	Data    interface{} `json:"data"`
}
