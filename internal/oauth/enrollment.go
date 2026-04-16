package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/oauth2"

	"github.com/jphines/mcp-proxy/gateway"
)

// Enrollment implements gateway.OAuthEnrollment.
// It orchestrates the PKCE authorization code flow, token storage, and refresh.
type Enrollment struct {
	store    gateway.CredentialStore
	registry gateway.ServerRegistry
	cache    *TokenCache
	secret   []byte // HMAC secret for state signing
	baseURL  string // proxy base URL (e.g. "https://mcp-proxy.ro.com")

	// pendingVerifiers stores PKCE code verifiers keyed by state string
	// while the engineer completes the browser flow. Entries are cleaned up
	// in HandleCallback and via TTL enforcement in VerifyState.
	pendingMu sync.Mutex
	pending   map[string]string // state → verifier
}

// EnrollmentOptions configures an Enrollment.
type EnrollmentOptions struct {
	CredentialStore gateway.CredentialStore
	ServerRegistry  gateway.ServerRegistry
	TokenCache      *TokenCache
	HMACSecret      []byte
	ProxyBaseURL    string
}

// NewEnrollment creates an Enrollment with the provided options.
func NewEnrollment(opts EnrollmentOptions) *Enrollment {
	return &Enrollment{
		store:    opts.CredentialStore,
		registry: opts.ServerRegistry,
		cache:    opts.TokenCache,
		secret:   opts.HMACSecret,
		baseURL:  opts.ProxyBaseURL,
		pending:  make(map[string]string),
	}
}

// InitiateFlow generates a PKCE-protected authorization URL for the given identity
// and service. The engineer opens this URL in a browser to grant consent.
func (e *Enrollment) InitiateFlow(ctx context.Context, identity *gateway.Identity, serviceID string) (string, error) {
	srv, err := e.registry.Get(ctx, serviceID)
	if err != nil {
		return "", fmt.Errorf("oauth: looking up server %q: %w", serviceID, err)
	}
	if srv.OAuthProvider == nil {
		return "", fmt.Errorf("oauth: server %q is not configured for OAuth", serviceID)
	}

	verifier := oauth2.GenerateVerifier()
	state, err := SignState(e.secret, identity.Subject, serviceID, verifier)
	if err != nil {
		return "", fmt.Errorf("oauth: signing state: %w", err)
	}

	e.pendingMu.Lock()
	e.pending[state] = verifier
	e.pendingMu.Unlock()

	cfg := e.oauthConfig(ctx, srv)
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	return authURL, nil
}

// HandleCallback processes the OAuth callback after the engineer grants consent.
func (e *Enrollment) HandleCallback(ctx context.Context, code, stateParam string) error {
	claims, err := VerifyState(e.secret, stateParam)
	if err != nil {
		return fmt.Errorf("oauth: invalid state: %w", err)
	}

	e.pendingMu.Lock()
	verifier, ok := e.pending[stateParam]
	if ok {
		delete(e.pending, stateParam)
	}
	e.pendingMu.Unlock()

	if !ok {
		// State was valid (MAC + expiry) but not in our pending map.
		// This can happen on restart; proceed using the verifier from the state claims.
		verifier = claims.Verifier
	}

	srv, err := e.registry.Get(ctx, claims.ServiceID)
	if err != nil {
		return fmt.Errorf("oauth: looking up server %q: %w", claims.ServiceID, err)
	}

	cfg := e.oauthConfig(ctx, srv)
	token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return fmt.Errorf("oauth: exchanging code for token: %w", err)
	}

	// Persist the refresh token to the credential store at session scope.
	scope := gateway.CredentialScope{
		Level:     gateway.ScopeSession,
		OwnerID:   claims.Subject,
		ServiceID: claims.ServiceID,
	}
	cred := &gateway.Credential{
		Type:  gateway.CredTypeOAuthRefresh,
		Value: []byte(token.RefreshToken),
	}
	if err := e.store.Store(ctx, scope, cred); err != nil {
		return fmt.Errorf("oauth: storing refresh token: %w", err)
	}

	// Cache the full token (access + refresh) for immediate use.
	e.cache.Set(claims.Subject, claims.ServiceID, token)
	return nil
}

// IsEnrolled reports whether the identity has a valid enrollment for serviceID.
func (e *Enrollment) IsEnrolled(ctx context.Context, identity *gateway.Identity, serviceID string) (bool, error) {
	// Check in-memory cache first.
	if _, ok := e.cache.Get(identity.Subject, serviceID); ok {
		return true, nil
	}

	// Check the credential store for a refresh token.
	cred, err := e.store.Resolve(ctx, identity, serviceID)
	if err != nil {
		if errors.Is(err, gateway.ErrCredentialNotFound) {
			return false, nil
		}
		return false, err
	}
	defer cred.Zero()

	return cred.Type == gateway.CredTypeOAuthRefresh, nil
}

// AccessToken returns a valid access token for the given identity and service.
// Checks the in-memory token cache first; if expired or absent, exchanges the
// stored refresh token for a new access token and updates the cache.
func (e *Enrollment) AccessToken(ctx context.Context, identity *gateway.Identity, serviceID string) (*gateway.Credential, error) {
	// Fast path: valid cached access token.
	if tok, ok := e.cache.Get(identity.Subject, serviceID); ok {
		return &gateway.Credential{
			Type:  gateway.CredTypeOAuthAccess,
			Value: []byte(tok.AccessToken),
		}, nil
	}

	// Slow path: exchange refresh token.
	refreshCred, err := e.store.Resolve(ctx, identity, serviceID)
	if err != nil {
		if errors.Is(err, gateway.ErrCredentialNotFound) {
			srv, lookupErr := e.registry.Get(ctx, serviceID)
			name := serviceID
			enrollURL := e.baseURL + "/oauth/enroll/" + serviceID
			if lookupErr == nil {
				name = srv.Name
			}
			return nil, &gateway.EnrollmentRequiredError{
				ServiceID:   serviceID,
				ServiceName: name,
				EnrollURL:   enrollURL,
			}
		}
		return nil, fmt.Errorf("oauth: resolving refresh token: %w", err)
	}
	defer refreshCred.Zero()

	if refreshCred.Type != gateway.CredTypeOAuthRefresh {
		return nil, fmt.Errorf("oauth: unexpected credential type %q for %s", refreshCred.Type, serviceID)
	}

	srv, err := e.registry.Get(ctx, serviceID)
	if err != nil {
		return nil, fmt.Errorf("oauth: looking up server %q: %w", serviceID, err)
	}

	cfg := e.oauthConfig(ctx, srv)
	src := cfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: string(refreshCred.Value),
	})
	tok, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("oauth: refreshing access token for %s: %w", serviceID, err)
	}

	// Update the cache with the fresh token.
	e.cache.Set(identity.Subject, serviceID, tok)

	// Persist the (potentially rotated) refresh token back to the store.
	if tok.RefreshToken != "" && tok.RefreshToken != string(refreshCred.Value) {
		scope := gateway.CredentialScope{
			Level:     gateway.ScopeSession,
			OwnerID:   identity.Subject,
			ServiceID: serviceID,
		}
		newRefreshCred := &gateway.Credential{
			Type:  gateway.CredTypeOAuthRefresh,
			Value: []byte(tok.RefreshToken),
		}
		if storeErr := e.store.Store(ctx, scope, newRefreshCred); storeErr != nil {
			// Non-fatal: the old refresh token may still work next time.
			_ = storeErr
		}
	}

	return &gateway.Credential{
		Type:  gateway.CredTypeOAuthAccess,
		Value: []byte(tok.AccessToken),
	}, nil
}

// Revoke removes the stored enrollment for the given identity and service.
func (e *Enrollment) Revoke(ctx context.Context, identity *gateway.Identity, serviceID string) error {
	// Remove from the in-memory cache.
	e.cache.Delete(identity.Subject, serviceID)

	// Attempt to call the provider's revoke endpoint.
	srv, err := e.registry.Get(ctx, serviceID)
	if err == nil && srv.OAuthProvider != nil && srv.OAuthProvider.RevokeURL != "" {
		tok, _ := e.cache.Get(identity.Subject, serviceID)
		if tok != nil {
			_ = revokeToken(ctx, srv.OAuthProvider.RevokeURL, tok.AccessToken)
		}
	}

	// Remove from vault.
	scope := gateway.CredentialScope{
		Level:     gateway.ScopeSession,
		OwnerID:   identity.Subject,
		ServiceID: serviceID,
	}
	return e.store.Revoke(ctx, scope)
}

// oauthConfig builds an oauth2.Config for the given server.
// The client secret is resolved from the credential store at org scope.
func (e *Enrollment) oauthConfig(ctx context.Context, srv *gateway.ServerConfig) *oauth2.Config {
	clientSecret := ""
	if srv.OAuthProvider != nil {
		// Resolve the client secret at org scope (nil identity = org-scope lookup).
		cred, err := e.store.Resolve(ctx, nil, srv.OAuthProvider.ClientSecretRef)
		if err == nil {
			clientSecret = string(cred.Value)
			defer cred.Zero()
		}
	}

	return &oauth2.Config{
		ClientID:     srv.OAuthProvider.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  srv.OAuthProvider.AuthURL,
			TokenURL: srv.OAuthProvider.TokenURL,
		},
		RedirectURL: e.baseURL + "/oauth/callback",
		Scopes:      srv.OAuthProvider.Scopes,
	}
}

// revokeToken sends a token revocation request to the provider's revoke URL.
func revokeToken(ctx context.Context, revokeURL, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revokeURL, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Set("token", token)
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// TokenCache returns the in-memory token cache (exposed for testing).
func (e *Enrollment) TokenCache() *TokenCache { return e.cache }

var _ gateway.OAuthEnrollment = (*Enrollment)(nil)
