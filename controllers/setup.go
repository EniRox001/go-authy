package controllers

import (
	"net/http"

	"github.com/gorilla/mux"
)

func New() http.Handler {
	router := mux.NewRouter()

	router.HandleFunc("/api/register", CreateUser).Methods("POST")
	router.HandleFunc("/api/login", LoginUser).Methods("POST")
	router.HandleFunc("/api/user/{id}", UpdateUser).Methods("PUT")
	router.HandleFunc("/api/user/{id}", GetUser).Methods("GET")
	router.HandleFunc("/api/change-password", ChangePassword).Methods("POST")
	router.HandleFunc("/api/logout", LogoutUser).Methods("POST")
	router.HandleFunc("/api/reset-password", ResetPassword).Methods("POST")
	router.HandleFunc("/api/refresh-token", RefreshToken).Methods("POST")
	router.HandleFunc("/api/user/{id}", DeleteUser).Methods("DELETE")
	router.HandleFunc("/api/users", GetUsers).Methods("GET")

	return router
}
