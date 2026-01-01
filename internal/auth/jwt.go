package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			Subject:   userID.String(),
		},
	)
	s, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return s, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims
	parsed, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) { return []byte(tokenSecret), nil })
	if err != nil {
		return uuid.UUID{}, err
	}
	subj, err := parsed.Claims.GetSubject()
	return uuid.Parse(subj)
}

func GetBearerToken(headers http.Header) (string, error) {
	h := headers.Get("Authorization")
	if len(h) == 0 {
		return "", errors.New("Authorization not found")
	}
	return strings.Replace(h, "Bearer ", "", 1), nil
}
