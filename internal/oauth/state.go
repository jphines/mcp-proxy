// Package oauth implements PKCE OAuth 2.0 enrollment for per-user service credentials.
package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// StateClaims is the verified payload extracted from an OAuth state parameter.
type StateClaims struct {
	Subject   string    `json:"sub"`
	ServiceID string    `json:"svc"`
	Verifier  string    `json:"verifier"` // PKCE code verifier
	ExpiresAt time.Time `json:"exp"`
}

const stateExpiry = 10 * time.Minute

// SignState encodes and HMAC-signs the state payload.
// Returns a base64url-encoded string safe for use as an OAuth state parameter.
func SignState(secret []byte, subject, serviceID, verifier string) (string, error) {
	claims := StateClaims{
		Subject:   subject,
		ServiceID: serviceID,
		Verifier:  verifier,
		ExpiresAt: time.Now().Add(stateExpiry),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding state claims: %w", err)
	}

	mac := computeMAC(secret, payload)

	// Format: base64url(payload) + "." + base64url(mac)
	encoded := base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac)
	return encoded, nil
}

// VerifyState validates the HMAC signature and expiry of a state parameter.
// Returns the decoded claims on success.
func VerifyState(secret []byte, stateParam string) (*StateClaims, error) {
	// Split at the last dot to get payload and MAC.
	dotIdx := lastDot(stateParam)
	if dotIdx < 0 {
		return nil, errors.New("oauth: invalid state format")
	}

	payloadEnc := stateParam[:dotIdx]
	macEnc := stateParam[dotIdx+1:]

	payload, err := base64.RawURLEncoding.DecodeString(payloadEnc)
	if err != nil {
		return nil, fmt.Errorf("oauth: decoding state payload: %w", err)
	}
	mac, err := base64.RawURLEncoding.DecodeString(macEnc)
	if err != nil {
		return nil, fmt.Errorf("oauth: decoding state MAC: %w", err)
	}

	expected := computeMAC(secret, payload)
	if !hmac.Equal(mac, expected) {
		return nil, errors.New("oauth: state signature invalid")
	}

	var claims StateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("oauth: decoding state claims: %w", err)
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, errors.New("oauth: state parameter expired")
	}

	return &claims, nil
}

func computeMAC(secret, payload []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	return h.Sum(nil)
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}
