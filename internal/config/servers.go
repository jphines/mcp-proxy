package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var serverIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// ServersFile is the top-level YAML schema for servers.yaml.
type ServersFile struct {
	Servers []ServerEntry `yaml:"servers"`
}

// ServerEntry is the YAML representation of a single downstream server registration.
type ServerEntry struct {
	ID            string                 `yaml:"id"`
	Name          string                 `yaml:"name"`
	Transport     TransportEntry         `yaml:"transport"`
	DataTier      int                    `yaml:"data_tier"`
	AuthStrategy  string                 `yaml:"auth_strategy"`
	CredentialRef string                 `yaml:"credential_ref"`
	OAuthProvider *OAuthProviderEntry    `yaml:"oauth_provider,omitempty"`
	AuthInjection AuthInjectionEntry     `yaml:"auth_injection"`
	AllowedGroups []string               `yaml:"allowed_groups"`
	Enabled       *bool                  `yaml:"enabled"`
	CircuitBreaker CircuitBreakerEntry   `yaml:"circuit_breaker"`
	Tags          map[string]string      `yaml:"tags"`
}

// TransportEntry is the YAML representation of a transport configuration.
type TransportEntry struct {
	Type    string            `yaml:"type"`
	URL     string            `yaml:"url"`
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Headers map[string]string `yaml:"headers"`
}

// OAuthProviderEntry is the YAML representation of an OAuth provider configuration.
type OAuthProviderEntry struct {
	AuthURL         string   `yaml:"auth_url"`
	TokenURL        string   `yaml:"token_url"`
	RevokeURL       string   `yaml:"revoke_url"`
	ClientID        string   `yaml:"client_id"`
	ClientSecretRef string   `yaml:"client_secret_ref"`
	Scopes          []string `yaml:"scopes"`
	PKCERequired    bool     `yaml:"pkce_required"`
}

// AuthInjectionEntry is the YAML representation of auth injection configuration.
type AuthInjectionEntry struct {
	Method     string `yaml:"method"`
	Header     string `yaml:"header"`
	Prefix     string `yaml:"prefix"`
	EnvVar     string `yaml:"env_var"`
	QueryParam string `yaml:"query_param"`
}

// CircuitBreakerEntry is the YAML representation of circuit breaker configuration.
type CircuitBreakerEntry struct {
	FailureThreshold int    `yaml:"failure_threshold"`
	ResetTimeout     string `yaml:"reset_timeout"`
	HalfOpenMax      int    `yaml:"half_open_max"`
}

var validTransportTypes = map[string]bool{
	"stdio":           true,
	"http_sse":        true,
	"streamable_http": true,
}

var validAuthStrategies = map[string]bool{
	"oauth":  true,
	"xaa":    true,
	"static": true,
	"sts":    true,
}

var validInjectionMethods = map[string]bool{
	"header_bearer": true,
	"header_custom": true,
	"query_param":   true,
	"env_var":       true,
}

// LoadServers reads and validates servers.yaml from the given path.
// Returns a validated ServersFile or an error aggregating all validation failures.
func LoadServers(path string) (*ServersFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading servers file: %w", err)
	}

	var sf ServersFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parsing servers YAML: %w", err)
	}

	if err := validateServersFile(&sf); err != nil {
		return nil, err
	}
	return &sf, nil
}

func validateServersFile(sf *ServersFile) error {
	var errs []error
	seen := map[string]bool{}

	for i, s := range sf.Servers {
		prefix := fmt.Sprintf("servers[%d] (id=%q)", i, s.ID)

		if s.ID == "" {
			errs = append(errs, fmt.Errorf("%s: id is required", prefix))
		} else if !serverIDPattern.MatchString(s.ID) {
			errs = append(errs, fmt.Errorf("%s: id must match [a-z0-9-]+", prefix))
		} else if seen[s.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate server id", prefix))
		} else {
			seen[s.ID] = true
		}

		if s.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", prefix))
		}

		if !validTransportTypes[s.Transport.Type] {
			errs = append(errs, fmt.Errorf("%s: transport.type must be one of %v, got %q",
				prefix, sortedKeys(validTransportTypes), s.Transport.Type))
		}
		if s.Transport.Type == "stdio" && s.Transport.Command == "" {
			errs = append(errs, fmt.Errorf("%s: transport.command is required for stdio transport", prefix))
		}
		if (s.Transport.Type == "http_sse" || s.Transport.Type == "streamable_http") && s.Transport.URL == "" {
			errs = append(errs, fmt.Errorf("%s: transport.url is required for HTTP transports", prefix))
		}

		if !validAuthStrategies[s.AuthStrategy] {
			errs = append(errs, fmt.Errorf("%s: auth_strategy must be one of %v, got %q",
				prefix, sortedKeys(validAuthStrategies), s.AuthStrategy))
		}
		if s.AuthStrategy == "oauth" {
			if s.OAuthProvider == nil {
				errs = append(errs, fmt.Errorf("%s: oauth_provider is required for oauth auth_strategy", prefix))
			} else {
				errs = append(errs, validateOAuthProvider(prefix, s.OAuthProvider)...)
			}
		}
		if s.AuthStrategy == "static" && s.CredentialRef == "" {
			errs = append(errs, fmt.Errorf("%s: credential_ref is required for static auth_strategy", prefix))
		}

		if s.AuthInjection.Method != "" && !validInjectionMethods[s.AuthInjection.Method] {
			errs = append(errs, fmt.Errorf("%s: auth_injection.method must be one of %v, got %q",
				prefix, sortedKeys(validInjectionMethods), s.AuthInjection.Method))
		}

		if s.DataTier < 0 || s.DataTier > 5 {
			errs = append(errs, fmt.Errorf("%s: data_tier must be 0-5, got %d", prefix, s.DataTier))
		}
	}

	if len(errs) > 0 {
		return joinErrors("servers.yaml validation failed", errs)
	}
	return nil
}

func validateOAuthProvider(prefix string, p *OAuthProviderEntry) []error {
	var errs []error
	if p.AuthURL == "" {
		errs = append(errs, fmt.Errorf("%s: oauth_provider.auth_url is required", prefix))
	}
	if p.TokenURL == "" {
		errs = append(errs, fmt.Errorf("%s: oauth_provider.token_url is required", prefix))
	}
	if p.ClientID == "" {
		errs = append(errs, fmt.Errorf("%s: oauth_provider.client_id is required", prefix))
	}
	if p.ClientSecretRef == "" {
		errs = append(errs, fmt.Errorf("%s: oauth_provider.client_secret_ref is required", prefix))
	}
	if len(p.Scopes) == 0 {
		errs = append(errs, fmt.Errorf("%s: oauth_provider.scopes must have at least one entry", prefix))
	}
	return errs
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple stable sort by string comparison.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

func joinErrors(msg string, errs []error) error {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = "  - " + e.Error()
	}
	return fmt.Errorf("%s:\n%s", msg, strings.Join(msgs, "\n"))
}
