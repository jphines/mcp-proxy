// Package config loads and validates the proxy's runtime configuration.
// Infrastructure settings come from environment variables; policy and server
// registrations come from YAML files in ConfigDir.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// AppConfig holds all runtime configuration for the proxy.
type AppConfig struct {
	// OktaIssuer is the Okta tenant issuer URL used to validate JWTs.
	// Required. Example: "https://ro.okta.com/oauth2/default"
	OktaIssuer string

	// OktaAudience is the expected JWT audience claim.
	// Required. Example: "api://mcp-proxy"
	OktaAudience string

	// DatabaseURL is the PostgreSQL connection string.
	// Required. Example: "postgres://user:pass@host:5432/mcpproxy?sslmode=require"
	DatabaseURL string

	// AWSRegion is the primary AWS region for Secrets Manager and CloudWatch.
	// Required. Example: "us-east-1"
	AWSRegion string

	// ConfigDir is the directory containing servers.yaml and policy.yaml.
	// Required. Example: "/etc/mcp-proxy"
	ConfigDir string

	// ProxyBaseURL is the public base URL of this proxy instance (used for OAuth callbacks).
	// Required. Example: "https://mcp-proxy.ro.com"
	ProxyBaseURL string

	// Workspace identifies the deployment environment.
	// Required. One of: "production", "staging", "dev"
	Workspace string

	// StateHMACSecret is the HMAC-SHA256 key for signing OAuth enrollment state params.
	// Required. Must be at least 32 bytes (64 hex chars).
	StateHMACSecret string

	// SlackWebhookURL is the incoming webhook URL for HITL approval notifications.
	// Required.
	SlackWebhookURL string

	// SlackSigningSecret is used to verify Slack interactive component callbacks.
	// Required.
	SlackSigningSecret string

	// TLSCertFile is the path to the TLS certificate file.
	// Optional; if unset the server listens on plain HTTP (development only).
	TLSCertFile string

	// TLSKeyFile is the path to the TLS private key file.
	// Optional; must be set if TLSCertFile is set.
	TLSKeyFile string

	// ListenAddr is the address:port the HTTP server binds to.
	// Default: ":8443"
	ListenAddr string

	// InstanceID is a unique identifier for this proxy instance.
	// Used as the genesis seed for the per-instance audit hash chain.
	// Defaults to the hostname if unset.
	InstanceID string

	// CredentialCacheTTL is the maximum time a decrypted credential may live in memory.
	// Default: 30 seconds. Hard ceiling enforced regardless of token expiry.
	CredentialCacheTTL time.Duration

	// ToolCatalogCacheTTL is how long the aggregated tool catalog is cached.
	// Default: 30 seconds.
	ToolCatalogCacheTTL time.Duration

	// ApprovalTimeout is the default HITL approval timeout when not specified by policy.
	// Default: 5 minutes.
	ApprovalTimeout time.Duration

	// ShutdownTimeout is the maximum time to wait for in-flight requests during shutdown.
	// Default: 30 seconds.
	ShutdownTimeout time.Duration
}

// LoadFromEnv reads AppConfig from environment variables.
// Returns an error that aggregates all missing/invalid fields (not just the first).
func LoadFromEnv() (*AppConfig, error) {
	cfg := &AppConfig{
		ListenAddr:          getEnvDefault("LISTEN_ADDR", ":8443"),
		CredentialCacheTTL:  30 * time.Second,
		ToolCatalogCacheTTL: 30 * time.Second,
		ApprovalTimeout:     5 * time.Minute,
		ShutdownTimeout:     30 * time.Second,
	}

	var errs []error

	cfg.OktaIssuer = os.Getenv("OKTA_ISSUER")
	cfg.OktaAudience = os.Getenv("OKTA_AUDIENCE")
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	cfg.AWSRegion = os.Getenv("AWS_REGION")
	cfg.ConfigDir = os.Getenv("CONFIG_DIR")
	cfg.ProxyBaseURL = os.Getenv("PROXY_BASE_URL")
	cfg.Workspace = os.Getenv("WORKSPACE")
	cfg.StateHMACSecret = os.Getenv("STATE_HMAC_SECRET")
	cfg.SlackWebhookURL = os.Getenv("SLACK_WEBHOOK_URL")
	cfg.SlackSigningSecret = os.Getenv("SLACK_SIGNING_SECRET")
	cfg.TLSCertFile = os.Getenv("TLS_CERT_FILE")
	cfg.TLSKeyFile = os.Getenv("TLS_KEY_FILE")
	cfg.InstanceID = os.Getenv("INSTANCE_ID")

	// Override duration defaults from environment.
	if v := os.Getenv("CREDENTIAL_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.CredentialCacheTTL = d
		} else {
			errs = append(errs, fmt.Errorf("CREDENTIAL_CACHE_TTL: %w", err))
		}
	}
	if v := os.Getenv("TOOL_CATALOG_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ToolCatalogCacheTTL = d
		} else {
			errs = append(errs, fmt.Errorf("TOOL_CATALOG_CACHE_TTL: %w", err))
		}
	}
	if v := os.Getenv("APPROVAL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ApprovalTimeout = d
		} else {
			errs = append(errs, fmt.Errorf("APPROVAL_TIMEOUT: %w", err))
		}
	}
	if v := os.Getenv("SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ShutdownTimeout = d
		} else {
			errs = append(errs, fmt.Errorf("SHUTDOWN_TIMEOUT: %w", err))
		}
	}

	// Default InstanceID to hostname.
	if cfg.InstanceID == "" {
		if h, err := os.Hostname(); err == nil {
			cfg.InstanceID = h
		}
	}

	errs = append(errs, validateAppConfig(cfg)...)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

func validateAppConfig(cfg *AppConfig) []error {
	var errs []error

	required := []struct {
		name  string
		value string
	}{
		{"OKTA_ISSUER", cfg.OktaIssuer},
		{"OKTA_AUDIENCE", cfg.OktaAudience},
		{"DATABASE_URL", cfg.DatabaseURL},
		{"AWS_REGION", cfg.AWSRegion},
		{"CONFIG_DIR", cfg.ConfigDir},
		{"PROXY_BASE_URL", cfg.ProxyBaseURL},
		{"WORKSPACE", cfg.Workspace},
		{"STATE_HMAC_SECRET", cfg.StateHMACSecret},
		{"SLACK_WEBHOOK_URL", cfg.SlackWebhookURL},
		{"SLACK_SIGNING_SECRET", cfg.SlackSigningSecret},
	}
	for _, r := range required {
		if r.value == "" {
			errs = append(errs, fmt.Errorf("required env var %s is not set", r.name))
		}
	}

	if cfg.OktaIssuer != "" {
		if _, err := url.ParseRequestURI(cfg.OktaIssuer); err != nil {
			errs = append(errs, fmt.Errorf("OKTA_ISSUER is not a valid URL: %w", err))
		}
	}
	if cfg.ProxyBaseURL != "" {
		if _, err := url.ParseRequestURI(cfg.ProxyBaseURL); err != nil {
			errs = append(errs, fmt.Errorf("PROXY_BASE_URL is not a valid URL: %w", err))
		}
	}

	validWorkspaces := map[string]bool{"production": true, "staging": true, "dev": true}
	if cfg.Workspace != "" && !validWorkspaces[cfg.Workspace] {
		errs = append(errs, fmt.Errorf("WORKSPACE must be one of production/staging/dev, got %q", cfg.Workspace))
	}

	if len(cfg.StateHMACSecret) > 0 && len(cfg.StateHMACSecret) < 32 {
		errs = append(errs, fmt.Errorf("STATE_HMAC_SECRET must be at least 32 characters"))
	}

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile == "" {
		errs = append(errs, fmt.Errorf("TLS_KEY_FILE must be set when TLS_CERT_FILE is set"))
	}
	if cfg.TLSKeyFile != "" && cfg.TLSCertFile == "" {
		errs = append(errs, fmt.Errorf("TLS_CERT_FILE must be set when TLS_KEY_FILE is set"))
	}

	if cfg.CredentialCacheTTL > 30*time.Second {
		errs = append(errs, fmt.Errorf("CREDENTIAL_CACHE_TTL must not exceed 30s (security requirement)"))
	}

	if !strings.Contains(cfg.ListenAddr, ":") {
		errs = append(errs, fmt.Errorf("LISTEN_ADDR must be in host:port format, got %q", cfg.ListenAddr))
	}

	return errs
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// getEnvInt reads an integer environment variable with a default.
// Used by callers that need numeric config values.
func getEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// suppress unused warning for getEnvInt during incremental build.
var _ = getEnvInt
