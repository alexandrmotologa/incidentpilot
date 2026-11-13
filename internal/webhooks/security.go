package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

func VerifyPagerDutySignature(body []byte, sigHeader, secret string) bool {
	if secret == "" {
		return true
	}
	if sigHeader == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedHex := hex.EncodeToString(mac.Sum(nil))

	parts := strings.Split(sigHeader, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, "v1=") {
			provided := strings.TrimPrefix(trimmed, "v1=")
			if hmac.Equal([]byte(provided), []byte(expectedHex)) {
				return true
			}
		}
	}
	return false
}

func VerifySentrySignature(body []byte, sigHeader, clientSecret string) bool {
	if clientSecret == "" {
		return true
	}
	if sigHeader == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(strings.TrimSpace(sigHeader)), []byte(expected))
}

func VerifyBearerToken(authHeader, expectedToken string) bool {
	if expectedToken == "" {
		return true
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	return hmac.Equal([]byte(token), []byte(expectedToken))
}

func VerifyDatadogToken(tokenHeader, expectedToken string) bool {
	if expectedToken == "" {
		return true
	}
	return hmac.Equal([]byte(tokenHeader), []byte(expectedToken))
}

func VerifySlackSignature(body []byte, tsHeader, sigHeader, secret string, maxAgeSeconds int64) bool {
	if secret == "" {
		return true
	}
	if tsHeader == "" || sigHeader == "" {
		return false
	}

	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}

	if math.Abs(float64(time.Now().Unix()-ts)) > float64(maxAgeSeconds) {
		return false
	}

	basestring := fmt.Sprintf("v0:%s:%s", tsHeader, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(basestring))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sigHeader), []byte(expected))
}
