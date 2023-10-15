package main

import (
	"net/http"

	"github.com/enirox/go-authy/controllers"
	"github.com/enirox/go-authy/models"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	handlers := controllers.New()

	server := &http.Server{
		Addr: "0.0.0.0:8008",
		Handler: handlers,
	}

	models.ConnectDatabase()

	server.ListenAndServe()
}
