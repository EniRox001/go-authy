package controllers

import (
	"net/http"

	"github.com/enirox/go-authy/utils"
	"github.com/gorilla/mux"
)

func New() http.Handler {
	router := mux.NewRouter()

	// Completed Routes
	router.HandleFunc("/api/register", CreateUser).Methods("POST")
	router.HandleFunc("/api/user/{id}", GetUser).Methods("GET")
	router.HandleFunc("/api/user/{id}", UpdateUser).Methods("PATCH")
	router.HandleFunc("/api/reset-password", ResetPassword).Methods("POST")
	router.HandleFunc("/api/verify-otp", VerifyOTP).Methods("POST")
	router.HandleFunc("/api/change-password", ChangePassword).Methods("POST")
	router.HandleFunc("/api/login", LoginUser).Methods("POST")
	router.Handle("/api/logout", utils.Authenticate(http.HandlerFunc(LogoutUser))).Methods("POST")
	router.Handle("/api/refresh-token", utils.Authenticate(http.HandlerFunc(RefreshToken))).Methods("POST")
	router.Handle("/api/delete", utils.Authenticate(http.HandlerFunc(DeleteUser))).Methods("DELETE")
	router.HandleFunc("/api/user/{id}", DeleteUserByID).Methods("DELETE")
	router.HandleFunc("/api/users", GetUsers).Methods("GET")

	return router
}
