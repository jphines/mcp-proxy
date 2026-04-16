// Command demo-jwt is a minimal JWT issuer for the docker-compose demo
// environment. It generates an RSA-2048 key pair on startup and exposes:
//
//   - GET /.well-known/jwks.json  — JWKS for OKTA_ISSUER verification
//   - GET /token                  — issue a signed JWT
//   - GET /health                 — liveness probe
//
// Environment variables:
//
//	LISTEN_ADDR     — address:port to bind (default ":9999")
//	DEMO_ISSUER     — JWT issuer claim / URL prefix for JWKS (default "http://demo-jwt:9999")
//	DEMO_AUDIENCE   — JWT audience claim (default "api://mcp-proxy-demo")
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	privateJWK jwk.Key
	publicJWK  jwk.Key
	issuerURL  string
	audienceID string
)

func main() {
	addr := envOr("LISTEN_ADDR", ":9999")
	issuerURL = envOr("DEMO_ISSUER", "http://demo-jwt:9999")
	audienceID = envOr("DEMO_AUDIENCE", "api://mcp-proxy-demo")

	// Generate RSA-2048 key pair.
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo-jwt: key generation failed: %v\n", err)
		os.Exit(1)
	}

	privateJWK, err = jwk.FromRaw(rawKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo-jwt: jwk from raw: %v\n", err)
		os.Exit(1)
	}
	if err := privateJWK.Set(jwk.KeyIDKey, "demo-key-1"); err != nil {
		fmt.Fprintf(os.Stderr, "demo-jwt: set kid: %v\n", err)
		os.Exit(1)
	}
	if err := privateJWK.Set(jwk.AlgorithmKey, jwa.RS256.String()); err != nil {
		fmt.Fprintf(os.Stderr, "demo-jwt: set alg: %v\n", err)
		os.Exit(1)
	}

	publicJWK, err = privateJWK.PublicKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo-jwt: extract public key: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", handleJWKS)
	mux.HandleFunc("GET /token", handleToken)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	fmt.Fprintf(os.Stderr, "demo-jwt listening on %s (issuer: %s)\n", addr, issuerURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "demo-jwt: %v\n", err)
		os.Exit(1)
	}
}

// handleJWKS serves the public key set for JWT verification.
// The proxy fetches this at startup and on cache miss.
func handleJWKS(w http.ResponseWriter, _ *http.Request) {
	set := jwk.NewSet()
	if err := set.AddKey(publicJWK); err != nil {
		http.Error(w, "building key set: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(set); err != nil {
		// Already written header; nothing useful we can do.
		_ = err
	}
}

// handleToken issues a signed JWT for the requested identity.
//
// Query parameters:
//
//	user    — subject / email (default: demo-user@example.com)
//	groups  — comma-separated group names (default: everyone)
//	type    — identity type: human | agent | service (default: human)
//	ttl     — token lifetime as a Go duration string, e.g. 1h, 24h, 7d (default: 1h, max: 30d)
func handleToken(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	user := q.Get("user")
	if user == "" {
		user = "demo-user@example.com"
	}

	// Parse groups.
	groups := []string{"everyone"}
	if raw := q.Get("groups"); raw != "" {
		for _, g := range strings.Split(raw, ",") {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
	}

	// Identity type: the proxy reads the "x-identity-type" claim.
	identityType := q.Get("type")
	if identityType == "" {
		identityType = "human"
	}

	// Parse TTL; default 1h, cap at 30 days.
	ttl := time.Hour
	if raw := q.Get("ttl"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			http.Error(w, "invalid ttl: "+err.Error(), http.StatusBadRequest)
			return
		}
		const maxTTL = 30 * 24 * time.Hour
		if parsed > maxTTL {
			parsed = maxTTL
		}
		if parsed > 0 {
			ttl = parsed
		}
	}

	now := time.Now().UTC()
	tok, err := jwt.NewBuilder().
		Issuer(issuerURL).
		Audience([]string{audienceID}).
		Subject(user).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(ttl)).
		Claim("groups", groups).
		Claim("x-identity-type", identityType).
		Build()
	if err != nil {
		http.Error(w, "building token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privateJWK))
	if err != nil {
		http.Error(w, "signing token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": string(signed),
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
		"user":         user,
		"groups":       groups,
		"type":         identityType,
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
