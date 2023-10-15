package controllers

import (
	"fmt"
	"net/http"
)

func CreateUser(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT CREATE USER POST REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func LoginUser(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT LOGIN USER POST REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func UpdateUser(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT UPDATE USER POST REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func GetUser(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT GET USER GET REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func ChangePassword(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT CHANGE PASSWORD POST REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func LogoutUser(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT LOGOUT USER POST REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func ResetPassword(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT RESET PASSWORD POST REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func RefreshToken(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT REFRESH TOKEN POST REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func DeleteUser(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT DELETE USER REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

func GetUsers(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT GET USERS GET REQUEST HERE
	fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
}

