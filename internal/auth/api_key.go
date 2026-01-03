package auth

import (
	"errors"
	"net/http"
	"strings"
)

func GetAPIKey(headers http.Header) (string, error) {
	keyStr := headers.Get("Authorization")
	if keyStr == "" {
		return "", errors.New("no key found")
	}
	return strings.Replace(keyStr, "ApiKey ", "", 1), nil
}
