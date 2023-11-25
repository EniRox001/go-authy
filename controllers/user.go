package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	// "time"

	"github.com/enirox/go-authy/models"
	"github.com/enirox/go-authy/utils"
	"github.com/go-playground/validator"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var validate *validator.Validate

type UserReq struct {
	FirstName string `json:"first_name" validate:"required"`
	LastName string `json:"last_name" validate:"required"`
	Email string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type UserLoginReq struct {
	Email string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type UserUpdateReq struct {
	FirstName string `json:"first_name" validate:"required"`
	LastName string `json:"last_name" validate:"required"`
	Email string `json:"email" validate:"required"`
}

type UserResetReq struct {
	Email string `json:"email" validate:"required"`
}

type ChangePasswordReq struct {
	Password string `json:"password" validate:"required"`
}

type VerifyOTPReq struct {
	OTP string `json:"otp" validate:"required"`
}

type Res struct {
	Status string `json:"status"`
	Message string `json:"message"`
	Data interface{} `json:"data"`
}

type AuthRes struct {
	Status string `json:"status"`
	Message string `json:"message"`
	Data interface{} `json:"data"`
	Token string `json:"token"`
}

type MessageRes struct {
	Status string `json:"status"`
	Message string `json:"message"`
}

type UserRes struct {
	FirstName string `json:"first_name"`
	LastName string `json:"last_name"`
	Email string `json:"email"`
}

var otp string
var otpResetEmail string
var canChangePassword = false

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
	w.Header().Set("Content-Type", "application/json")

	var input UserLoginReq

	var user models.User

	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &input)

	validate = validator.New()
	err := validate.Struct(input)

	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Validations error")
		return
	}

	if err := models.DB.Where("email = ?", input.Email).First(&user).Error; err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	errf := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password))

	if errf != nil && errf == bcrypt.ErrMismatchedHashAndPassword {
		utils.RespondWithError(w, http.StatusUnauthorized, "Password is invalid")
		return
	}

	token, err := utils.GenerateToken(int(user.ID))

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Internal server error")
	}

	json.NewEncoder(w).Encode(AuthRes{
		Status: "success",
		Message: "user logged in successfully",
		Data: UserRes{
			FirstName: user.FirstName,
			LastName: user.LastName,
			Email: user.Email,
		},
		Token: token,
	})
}

func UpdateUser(w http.ResponseWriter, r *http.Request ){
	w.Header().Set("Content-Type", "application/json")

	id := mux.Vars(r)["id"]
	var user models.User

	if err := models.DB.Where("id = ?", id).First(&user).Error; err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	var input UserUpdateReq

	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &input)

	validate = validator.New()
	err := validate.Struct(input)

	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Validation error")
		return
	}
 
	user.FirstName = input.FirstName
	user.LastName = input.LastName
	user.Email = input.Email

	models.DB.Save(user)

	json.NewEncoder(w).Encode(Res{
		Status: "success",
		Message: "user updated successfully",
		Data: user,
	})
}

func GetUser(w http.ResponseWriter, r *http.Request ){
	w.Header().Set("Content-Type", "application/json")

	id := mux.Vars(r)["id"]
	var user models.User

	if err := models.DB.Where("id = ?", id).First(&user).Error; err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	json.NewEncoder(w).Encode(Res{
		Status: "success",
		Message: "User account retrieved successfully",
		Data: UserRes{
			FirstName: user.FirstName,
			LastName: user.LastName,
			Email: user.Email,
		},
	})
}

func ResetPassword(w http.ResponseWriter, r *http.Request ){
	var input UserResetReq

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

	otp = utils.GenerateOTP(6)
	otpResetEmail = input.Email

	utils.SendEmail(os.Getenv("ADMIN_EMAIL"), "GoAuth", input.Email, "Reset Password OTP for Your Account", os.Getenv("ADMIN_PASSWORD"), "<div><p><strong>Subject: Reset Password OTP for Your Account</strong></p><p>Dear User,</p><p>We have received a request to reset the password for your account at GoAuth. To ensure the security of your account, we have generated a one-time password (OTP) for you to complete the password reset process.</p><p>Your OTP code is: <strong>" + otp + "</strong></p><p>Please use this code within the next 30 minutes to reset your password. If you did not request this password reset or believe this email was sent in error, please contact our support team immediately at goAuthy@gmail.com or +234 8108080358.</p><p>Thank you for choosing GoAuth for your online needs. We are committed to keeping your account secure and your data protected.</p><p>Sincerely,</p><p>GoAuth<br>+234 8108080358</p></div>",)

	json.NewEncoder(w).Encode(MessageRes{
		Status: "success",
		Message: "Reset Passowrd OTP sent successfully",
	})

	}

func VerifyOTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var input VerifyOTPReq

	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &input)

	validate = validator.New()
	err := validate.Struct(input)

	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Validation Error")
		return
	}

	isValidOTP := input.OTP == otp

	if !isValidOTP {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid OTP")
		return
	}

	canChangePassword = true

	json.NewEncoder(w).Encode(MessageRes{
		Status: "success",
		Message: "OTP Verified successfully",
	})
}
	

func ChangePassword(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")

	var input ChangePasswordReq
	var user models.User

	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &input)

	validate = validator.New()
	err := validate.Struct(input)

	if !canChangePassword {
		utils.RespondWithError(w, http.StatusBadRequest, "OTP not verified")
		return
	}

	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Validation Error")
		return
	}

	if err := models.DB.Where("email = ?", otpResetEmail).First(&user).Error; err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found")
		return
	}

	hashedPassword, _:= utils.HashPassword(input.Password)

	user.Password = hashedPassword

	models.DB.Save(user)

	canChangePassword = false

	json.NewEncoder(w).Encode(MessageRes{
		Status: "success",
		Message: "Password Changed successfully",
	})
}

func LogoutUser(w http.ResponseWriter, r *http.Request ){
	// IMPLEMENT LOGOUT USER POST REQUEST HERE
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
