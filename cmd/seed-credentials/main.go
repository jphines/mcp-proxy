// Command seed-credentials seeds a single org-scope credential into the
// PostgreSQL credential store. It is used as a one-shot docker-compose
// init service to populate the Google OAuth client secret before the proxy starts.
//
// Required environment variables:
//
//	DATABASE_URL              — PostgreSQL connection string
//	CREDENTIAL_ENCRYPTION_KEY — must match the proxy's CREDENTIAL_ENCRYPTION_KEY
//	CREDENTIAL_SERVICE_ID     — the service ID key, e.g. "google/oauth-client-secret"
//	CREDENTIAL_SECRET_VALUE   — the secret to store
//
// Optional:
//
//	CREDENTIAL_TYPE           — credential type label (default: api_key)
//
// Exit codes:
//
//	0 — credential stored (or already present with same value)
//	1 — fatal error
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jphines/mcp-proxy/gateway"
	credstore "github.com/jphines/mcp-proxy/internal/credential/store"
)

func main() {
	ctx := context.Background()

	dbURL := requireEnv("DATABASE_URL")
	encKey := requireEnv("CREDENTIAL_ENCRYPTION_KEY")
	serviceID := requireEnv("CREDENTIAL_SERVICE_ID")
	secretValue := requireEnv("CREDENTIAL_SECRET_VALUE")

	credType := os.Getenv("CREDENTIAL_TYPE")
	if credType == "" {
		credType = string(gateway.CredTypeAPIKey)
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		fatal("connecting to PostgreSQL: %v", err)
	}
	defer pool.Close()

	store, err := credstore.NewPostgres(pool, []byte(encKey), 30*time.Second)
	if err != nil {
		fatal("could not initialise credential store: %v", err)
	}

	scope := gateway.CredentialScope{
		Level:     gateway.ScopeOrg,
		ServiceID: serviceID,
	}
	cred := &gateway.Credential{
		Type:  gateway.CredentialType(credType),
		Value: []byte(secretValue),
	}

	// Retry up to 15s in case migrations haven't completed yet.
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			fmt.Fprintf(os.Stderr, "seed-credentials: retrying (attempt %d/5)...\n", attempt+1)
			time.Sleep(3 * time.Second)
		}
		err = store.Store(ctx, scope, cred)
		if err == nil {
			break
		}
		fmt.Fprintf(os.Stderr, "seed-credentials: store attempt %d failed: %v\n", attempt+1, err)
	}
	if err != nil {
		fatal("storing credential %q: %v", serviceID, err)
	}

	fmt.Printf("seed-credentials: stored %q (type=%s, scope=org)\n", serviceID, credType)
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fatal("required environment variable %s is not set", key)
	}
	return v
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "seed-credentials: "+format+"\n", args...)
	os.Exit(1)
}
