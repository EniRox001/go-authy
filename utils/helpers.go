package utils

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jordan-wright/email"
	"golang.org/x/crypto/bcrypt"
)

func RespondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func CheckEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err != nil
}

func GenerateOTP(max int) string {
	var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b)
}

func SendEmail(from, fromName, to, subject, authPassword, body string) {
	e := email.NewEmail()
	e.From = fromName + " <" + from + ">"
	e.To = []string{to}
	e.Subject = subject
	e.HTML = []byte(body)
	// e.Send("smtp.gmail.com:587", smtp.PlainAuth("", "enirox001@gmail.com", "colz rcfr scol bxkp", "smtp.gmail.com"))
	e.SendWithTLS("smtp.gmail.com:465", smtp.PlainAuth("", from, authPassword, "smtp.gmail.com"), &tls.Config{ServerName: "smtp.gmail.com"})
}

func GenerateToken(userID int) (string, error) {
	secret := os.Getenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24).Unix(),
		"iat": time.Now().Unix(),
		"user_id": userID,
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
			return 
		}

		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok {
			RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		}

		userID := claims["user_id"].(float64)

		ctx := context.WithValue(r.Context(), "userID", userID)

		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
