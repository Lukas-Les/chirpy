package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	secret := "secret"
	expiresIn := time.Minute

	tokenStr, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}
	if tokenStr == "" {
		t.Fatalf("MakeJWT returned empty token string")
	}

	parsed, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(tk *jwt.Token) (any, error) {
		if tk.Method != jwt.SigningMethodHS256 {
			t.Fatalf("unexpected signing method: %v", tk.Method)
		}
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok || !parsed.Valid {
		t.Fatalf("token claims invalid")
	}

	if claims.Issuer != "chirpy" {
		t.Errorf("expected issuer %q, got %q", "chirpy", claims.Issuer)
	}
	if claims.Subject != userID.String() {
		t.Errorf("expected subject %q, got %q", userID.String(), claims.Subject)
	}
	if claims.ExpiresAt == nil {
		t.Fatalf("ExpiresAt is nil")
	}

	now := time.Now()
	exp := claims.ExpiresAt.Time

	if exp.Before(now) {
		t.Errorf("token already expired: exp=%v, now=%v", exp, now)
	}
	if exp.After(now.Add(expiresIn + 5*time.Second)) {
		t.Errorf("token expiration too far in future: exp=%v, now+%v", exp, expiresIn)
	}
}
