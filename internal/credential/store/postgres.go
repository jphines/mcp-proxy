package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jphines/mcp-proxy/gateway"
)

// postgresStore implements gateway.CredentialStore backed by PostgreSQL.
// Credentials are stored as AES-256-GCM ciphertext (nonce prepended to ciphertext)
// in the payload BYTEA column. Resolved credentials are also held in the same
// AES-256-GCM in-memory cache used by the Secrets Manager store.
type postgresStore struct {
	pool  *pgxpool.Pool
	block cipher.Block // AES-256 derived from the at-rest encryption key
	cache *encryptedCache
}

// NewPostgres constructs a CredentialStore backed by PostgreSQL.
// encryptionKey is used to derive the AES-256 at-rest key (SHA-256 of the key bytes).
// ttl is the hard ceiling for in-memory decrypted credentials (must be ≤ 30s).
func NewPostgres(pool *pgxpool.Pool, encryptionKey []byte, ttl time.Duration) (gateway.CredentialStore, error) {
	if ttl > 30*time.Second {
		return nil, fmt.Errorf("credential cache TTL must not exceed 30s (security requirement)")
	}

	// Derive a 32-byte key so the caller does not need to provide exactly 32 bytes.
	sum := sha256.Sum256(encryptionKey)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	cache, err := newEncryptedCache(ttl)
	if err != nil {
		return nil, err
	}

	return &postgresStore{pool: pool, block: block, cache: cache}, nil
}

// Resolve returns the best available credential for the given identity and service.
// Lookup order: session → agent → org. When identity is nil, only org-scope is checked.
func (s *postgresStore) Resolve(ctx context.Context, identity *gateway.Identity, serviceID string) (*gateway.Credential, error) {
	scopes := scopesFor(identity, serviceID)

	for _, scope := range scopes {
		cred, err := s.resolveScope(ctx, scope)
		if err == nil {
			return cred, nil
		}
		if !errors.Is(err, gateway.ErrCredentialNotFound) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("%w: no credential for service %q", gateway.ErrCredentialNotFound, serviceID)
}

func (s *postgresStore) resolveScope(ctx context.Context, scope gateway.CredentialScope) (*gateway.Credential, error) {
	key := cacheKey(string(scope.Level), scope.OwnerID, scope.ServiceID)

	// Check the in-memory encrypted cache first.
	if plaintext, ok := s.cache.get(key); ok {
		return decodeCredential(plaintext)
	}

	// Query the database.
	ownerID := scope.OwnerID
	row := s.pool.QueryRow(ctx,
		`SELECT payload FROM credentials WHERE scope_level=$1 AND owner_id=$2 AND service_id=$3
		 AND (expires_at IS NULL OR expires_at > NOW())`,
		string(scope.Level), ownerID, scope.ServiceID,
	)

	var ciphertext []byte
	if err := row.Scan(&ciphertext); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s/%s/%s", gateway.ErrCredentialNotFound,
				scope.Level, scope.OwnerID, scope.ServiceID)
		}
		return nil, fmt.Errorf("querying credential: %w", err)
	}

	plaintext, err := s.decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypting credential: %w", err)
	}

	// Cache the plaintext bytes.
	if cacheErr := s.cache.set(key, plaintext); cacheErr != nil {
		_ = cacheErr // non-fatal
	}

	return decodeCredential(plaintext)
}

// Store encrypts and persists a credential to PostgreSQL.
func (s *postgresStore) Store(ctx context.Context, scope gateway.CredentialScope, cred *gateway.Credential) error {
	payload := secretPayload{
		Type:      string(cred.Type),
		Value:     string(cred.Value),
		ExpiresAt: cred.ExpiresAt,
		Metadata:  cred.Metadata,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling credential: %w", err)
	}

	ciphertext, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypting credential: %w", err)
	}

	ownerID := scope.OwnerID
	_, err = s.pool.Exec(ctx,
		`INSERT INTO credentials (scope_level, owner_id, service_id, payload, updated_at, expires_at)
		 VALUES ($1, $2, $3, $4, NOW(), $5)
		 ON CONFLICT (scope_level, owner_id, service_id) DO UPDATE
		   SET payload=EXCLUDED.payload, updated_at=NOW(), expires_at=EXCLUDED.expires_at`,
		string(scope.Level), ownerID, scope.ServiceID, ciphertext, cred.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("storing credential: %w", err)
	}

	// Invalidate cache.
	key := cacheKey(string(scope.Level), scope.OwnerID, scope.ServiceID)
	s.cache.delete(key)
	return nil
}

// Revoke deletes a stored credential from PostgreSQL and the cache.
func (s *postgresStore) Revoke(ctx context.Context, scope gateway.CredentialScope) error {
	ownerID := scope.OwnerID
	_, err := s.pool.Exec(ctx,
		`DELETE FROM credentials WHERE scope_level=$1 AND owner_id=$2 AND service_id=$3`,
		string(scope.Level), ownerID, scope.ServiceID,
	)
	if err != nil {
		return fmt.Errorf("revoking credential: %w", err)
	}

	key := cacheKey(string(scope.Level), scope.OwnerID, scope.ServiceID)
	s.cache.delete(key)
	return nil
}

// Rotate bypasses the cache and fetches the latest value from PostgreSQL.
func (s *postgresStore) Rotate(ctx context.Context, scope gateway.CredentialScope) (*gateway.Credential, error) {
	key := cacheKey(string(scope.Level), scope.OwnerID, scope.ServiceID)
	s.cache.delete(key)
	return s.resolveScope(ctx, scope)
}

// List returns the credential scopes visible to the given identity.
func (s *postgresStore) List(ctx context.Context, identity *gateway.Identity) ([]gateway.CredentialScope, error) {
	var rows pgx.Rows
	var err error

	if identity == nil {
		rows, err = s.pool.Query(ctx,
			`SELECT scope_level, owner_id, service_id FROM credentials WHERE scope_level='org' ORDER BY service_id`)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT scope_level, owner_id, service_id FROM credentials
			 WHERE owner_id=$1 OR scope_level='org' ORDER BY scope_level, service_id`,
			identity.Subject)
	}
	if err != nil {
		return nil, fmt.Errorf("listing credentials: %w", err)
	}
	defer rows.Close()

	var scopes []gateway.CredentialScope
	for rows.Next() {
		var level, ownerID, serviceID string
		if err := rows.Scan(&level, &ownerID, &serviceID); err != nil {
			return nil, fmt.Errorf("scanning credential row: %w", err)
		}
		scopes = append(scopes, gateway.CredentialScope{
			Level:     gateway.ScopeLevel(level),
			OwnerID:   ownerID,
			ServiceID: serviceID,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating credentials: %w", err)
	}
	return scopes, nil
}

// --- encryption helpers ---

// encrypt applies AES-256-GCM and returns nonce || ciphertext.
func (s *postgresStore) encrypt(plaintext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(s.block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// decrypt splits the nonce and decrypts AES-256-GCM ciphertext.
func (s *postgresStore) decrypt(data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(s.block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM open: %w", err)
	}
	return plaintext, nil
}

var _ gateway.CredentialStore = (*postgresStore)(nil)
