package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/jphines/mcp-proxy/gateway"
)

// secretsManagerStore implements gateway.CredentialStore backed by AWS Secrets Manager.
// Resolved credentials are encrypted in an in-memory cache with a hard 30-second TTL.
//
// ARN convention: mcp-proxy/{scopeLevel}/{ownerID}/{serviceID}
// For org-scope: mcp-proxy/org/-/{serviceID}
type secretsManagerStore struct {
	client *secretsmanager.Client
	cache  *encryptedCache
}

// secretPayload is the JSON structure stored in Secrets Manager.
type secretPayload struct {
	Type      string            `json:"type"`
	Value     string            `json:"value"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// New constructs a CredentialStore backed by AWS Secrets Manager.
// ttl is the hard ceiling for in-memory decrypted credentials (must be ≤ 30s).
func New(client *secretsmanager.Client, ttl time.Duration) (gateway.CredentialStore, error) {
	if ttl > 30*time.Second {
		return nil, fmt.Errorf("credential cache TTL must not exceed 30s (security requirement)")
	}
	cache, err := newEncryptedCache(ttl)
	if err != nil {
		return nil, err
	}
	return &secretsManagerStore{client: client, cache: cache}, nil
}

// Resolve returns the best available credential for the given identity and service.
// Lookup order: session → agent → org. When identity is nil, only org-scope is checked
// (used for resolving the proxy's own OAuth client secrets).
func (s *secretsManagerStore) Resolve(ctx context.Context, identity *gateway.Identity, serviceID string) (*gateway.Credential, error) {
	scopes := scopesFor(identity, serviceID)

	for _, scope := range scopes {
		cred, err := s.resolveScope(ctx, scope)
		if err == nil {
			return cred, nil
		}
		if !isNotFound(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("%w: no credential for service %q", gateway.ErrCredentialNotFound, serviceID)
}

func (s *secretsManagerStore) resolveScope(ctx context.Context, scope gateway.CredentialScope) (*gateway.Credential, error) {
	key := cacheKey(string(scope.Level), scope.OwnerID, scope.ServiceID)

	// Check the in-memory encrypted cache first.
	if plaintext, ok := s.cache.get(key); ok {
		return decodeCredential(plaintext)
	}

	// Fetch from Secrets Manager.
	arn := arnFor(scope)
	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(arn),
	})
	if err != nil {
		return nil, err
	}

	raw := []byte(aws.ToString(out.SecretString))

	// Cache the raw bytes encrypted in memory.
	if cacheErr := s.cache.set(key, raw); cacheErr != nil {
		// Non-fatal: proceed without cache.
		_ = cacheErr
	}

	return decodeCredential(raw)
}

// Store encrypts and persists a credential to Secrets Manager.
func (s *secretsManagerStore) Store(ctx context.Context, scope gateway.CredentialScope, cred *gateway.Credential) error {
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

	arn := arnFor(scope)
	secretStr := string(data)

	// Try update first; create if not found.
	_, err = s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(arn),
		SecretString: aws.String(secretStr),
	})
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) {
		_, err = s.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(arn),
			SecretString: aws.String(secretStr),
		})
	}
	if err != nil {
		return fmt.Errorf("storing credential at %s: %w", arn, err)
	}

	// Invalidate cache.
	key := cacheKey(string(scope.Level), scope.OwnerID, scope.ServiceID)
	s.cache.delete(key)
	return nil
}

// Revoke deletes a stored credential from Secrets Manager and the cache.
func (s *secretsManagerStore) Revoke(ctx context.Context, scope gateway.CredentialScope) error {
	arn := arnFor(scope)
	_, err := s.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(arn),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	var notFound *types.ResourceNotFoundException
	if err != nil && !errors.As(err, &notFound) {
		return fmt.Errorf("revoking credential at %s: %w", arn, err)
	}

	key := cacheKey(string(scope.Level), scope.OwnerID, scope.ServiceID)
	s.cache.delete(key)
	return nil
}

// Rotate fetches the latest value from Secrets Manager (bypassing cache) and returns
// a fresh credential. Used to refresh OAuth access tokens stored as refresh tokens.
func (s *secretsManagerStore) Rotate(ctx context.Context, scope gateway.CredentialScope) (*gateway.Credential, error) {
	// Invalidate cache to force a fresh fetch.
	key := cacheKey(string(scope.Level), scope.OwnerID, scope.ServiceID)
	s.cache.delete(key)
	return s.resolveScope(ctx, scope)
}

// List returns the credential scopes visible to the given identity.
// Performs a prefix scan on the ARN namespace.
func (s *secretsManagerStore) List(ctx context.Context, identity *gateway.Identity) ([]gateway.CredentialScope, error) {
	prefix := "mcp-proxy/"
	if identity != nil {
		prefix = fmt.Sprintf("mcp-proxy/session/%s/", identity.Subject)
	}

	var scopes []gateway.CredentialScope
	paginator := secretsmanager.NewListSecretsPaginator(s.client, &secretsmanager.ListSecretsInput{
		Filters: []types.Filter{{
			Key:    types.FilterNameStringTypeName,
			Values: []string{prefix},
		}},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing credentials: %w", err)
		}
		for _, secret := range page.SecretList {
			if scope, ok := parseARN(aws.ToString(secret.Name)); ok {
				scopes = append(scopes, scope)
			}
		}
	}
	return scopes, nil
}

// --- helpers ---

func arnFor(scope gateway.CredentialScope) string {
	ownerID := scope.OwnerID
	if ownerID == "" {
		ownerID = "-"
	}
	return fmt.Sprintf("mcp-proxy/%s/%s/%s", scope.Level, ownerID, scope.ServiceID)
}

func scopesFor(identity *gateway.Identity, serviceID string) []gateway.CredentialScope {
	if identity == nil {
		return []gateway.CredentialScope{
			{Level: gateway.ScopeOrg, ServiceID: serviceID},
		}
	}
	return []gateway.CredentialScope{
		{Level: gateway.ScopeSession, OwnerID: identity.Subject, ServiceID: serviceID},
		{Level: gateway.ScopeAgent, OwnerID: identity.Subject, ServiceID: serviceID},
		{Level: gateway.ScopeOrg, ServiceID: serviceID},
	}
}

func parseARN(name string) (gateway.CredentialScope, bool) {
	// Expected: mcp-proxy/{level}/{ownerID}/{serviceID}
	var level, ownerID, serviceID string
	if _, err := fmt.Sscanf(name, "mcp-proxy/%s", &level); err != nil {
		return gateway.CredentialScope{}, false
	}
	parts := splitN(name, "/", 4)
	if len(parts) != 4 {
		return gateway.CredentialScope{}, false
	}
	level = parts[1]
	ownerID = parts[2]
	serviceID = parts[3]
	if ownerID == "-" {
		ownerID = ""
	}
	return gateway.CredentialScope{
		Level:     gateway.ScopeLevel(level),
		OwnerID:   ownerID,
		ServiceID: serviceID,
	}, true
}

func splitN(s, sep string, n int) []string {
	var parts []string
	for len(parts) < n-1 {
		idx := indexOf(s, sep)
		if idx < 0 {
			break
		}
		parts = append(parts, s[:idx])
		s = s[idx+len(sep):]
	}
	parts = append(parts, s)
	return parts
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func isNotFound(err error) bool {
	var notFound *types.ResourceNotFoundException
	return errors.As(err, &notFound)
}

func decodeCredential(data []byte) (*gateway.Credential, error) {
	var payload secretPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decoding credential payload: %w", err)
	}
	return &gateway.Credential{
		Type:      gateway.CredentialType(payload.Type),
		Value:     []byte(payload.Value),
		ExpiresAt: payload.ExpiresAt,
		Metadata:  payload.Metadata,
	}, nil
}

var _ gateway.CredentialStore = (*secretsManagerStore)(nil)
