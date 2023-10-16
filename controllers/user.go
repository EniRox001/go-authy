package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/enirox/go-authy/models"
	"github.com/enirox/go-authy/utils"
	"github.com/go-playground/validator"
	"github.com/gorilla/mux"
)

var validate *validator.Validate

type UserReq struct {
	FirstName string `json:"first_name" validate:"required"`
	LastName string `json:"last_name" validate:"required"`
	Email string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type Res struct {
	Status string `json:"status"`
	Message string `json:"message"`
	Data interface{} `json:"data"`
}

type UserRes struct {
	FirstName string `json:"first_name"`
	LastName string `json:"last_name"`
	Email string `json:"email"`
}

func CreateUser(w http.ResponseWriter, r *http.Request ){
	var input UserReq 

	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &input)

	validate = validator.New()
	err := validate.Struct(input)

	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Validation Error")
		return
	}

	validEmail := !utils.CheckEmail(input.Email)

	if validEmail == false {
		utils.RespondWithError(w, http.StatusUnauthorized, "Email address is invalid")
		return
	}

	if checkUser := models.DB.Where("email = ?", input.Email).First(&models.User{}).Error; checkUser == nil {
		utils.RespondWithError(w, http.StatusConflict, "This email address already exists")
		return
	}

	if len(input.Password) < 8 {
		utils.RespondWithError(w, http.StatusUnauthorized, "Password is too short")
		return
	}

	hashedPassword, err := utils.HashPassword(input.Password)

	if err != nil {
		utils.RespondWithError(w, http.StatusForbidden, "An error occured")
		return
	}

	user := &models.User{
		FirstName: input.FirstName,
		LastName: input.LastName,
		Email: input.Email,
		Password: hashedPassword,
	}

	models.DB.Create(user)

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(Res{
		Status: "success",
		Message: "User registration successful",
		Data: UserRes{
			FirstName: user.FirstName,
			LastName: user.LastName,
			Email: user.Email,
		},
	})

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
	w.Header().Set("Content-Type", "application/json")

	id := mux.Vars(r)["id"]
	var user models.User

	if err := models.DB.Where("id = ?", id).First(&user).Error; err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	json.NewEncoder(w).Encode(user)
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

