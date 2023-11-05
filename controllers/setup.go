package controllers

import (
	"net/http"

	"github.com/gorilla/mux"
)

//Sameple API Design

// func New() http.Handler {
// 	router := mux.NewRouter()
//
// 	router.HandleFunc("/api/register", CreateUser).Methods("POST")
// 	router.HandleFunc("/api/login", LoginUser).Methods("POST")
// 	router.HandleFunc("/api/user/{id}", UpdateUser).Methods("PATCH")
// 	router.HandleFunc("/api/user/{id}", GetUser).Methods("GET")
// 	router.HandleFunc("/api/reset-password", ResetPassword).Methods("POST")
// 	router.HandleFunc("/api/change-password", ChangePassword).Methods("POST")
// 	router.HandleFunc("/api/logout", LogoutUser).Methods("POST")
// 	router.HandleFunc("/api/refresh-token", RefreshToken).Methods("POST")
// 	router.HandleFunc("/api/user/{id}", DeleteUser).Methods("DELETE")
// 	router.HandleFunc("/api/users", GetUsers).Methods("GET")
//
// 	return router
// }

func New() http.Handler {
	router := mux.NewRouter()

	// Completed
	router.HandleFunc("/api/register", CreateUser).Methods("POST")
	router.HandleFunc("/api/user/{id}", GetUser).Methods("GET")
	router.HandleFunc("/api/user/{id}", UpdateUser).Methods("PATCH")
	router.HandleFunc("/api/reset-password", ResetPassword).Methods("POST")
	router.HandleFunc("/api/verify-otp", VerifyOTP).Methods("POST")
	router.HandleFunc("/api/change-password", ChangePassword).Methods("POST")

	// In Progess
	router.HandleFunc("/api/login", LoginUser).Methods("POST")
	router.HandleFunc("/api/logout", LogoutUser).Methods("POST")


	//Pending
	router.HandleFunc("/api/refresh-token", RefreshToken).Methods("POST")
	router.HandleFunc("/api/user/{id}", DeleteUser).Methods("DELETE")
	router.HandleFunc("/api/users", GetUsers).Methods("GET")

	return router
}
