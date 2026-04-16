// Package credential provides credential resolution strategies for the MCP proxy.
// This file implements the STS AssumeRoleWithWebIdentity strategy.
package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/jphines/mcp-proxy/gateway"
)

// STSClient is the subset of the STS API used by the resolver.
// Defined as an interface for testability.
type STSClient interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// STSResolver exchanges a caller's validated JWT for temporary AWS credentials
// via STS AssumeRoleWithWebIdentity. The downstream server can then use these
// credentials to call AWS APIs.
type STSResolver struct {
	client STSClient
}

// NewSTSResolver creates a resolver backed by the given STS client.
func NewSTSResolver(client STSClient) *STSResolver {
	return &STSResolver{client: client}
}

// Resolve calls AssumeRoleWithWebIdentity using the caller's raw JWT token
// and the server's STS configuration. Returns a Credential containing the
// temporary AWS credentials as a JSON-encoded value.
func (r *STSResolver) Resolve(ctx context.Context, identity *gateway.Identity, server *gateway.ServerConfig) (*gateway.Credential, error) {
	if identity == nil {
		return nil, fmt.Errorf("credential: STS strategy requires an authenticated identity")
	}
	if identity.RawToken == "" {
		return nil, fmt.Errorf("credential: STS strategy requires identity.RawToken")
	}
	if server.STSConfig == nil {
		return nil, fmt.Errorf("credential: server %s has STS strategy but no sts_config", server.ID)
	}

	cfg := server.STSConfig

	sessionName := cfg.SessionNamePrefix + sanitizeSessionName(identity.Subject)
	if len(sessionName) > 64 {
		sessionName = sessionName[:64]
	}

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(cfg.RoleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(identity.RawToken),
	}
	if cfg.DurationSeconds > 0 {
		input.DurationSeconds = aws.Int32(cfg.DurationSeconds)
	}

	out, err := r.client.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("credential: STS AssumeRoleWithWebIdentity for %s: %w", server.ID, err)
	}

	if out.Credentials == nil {
		return nil, fmt.Errorf("credential: STS returned nil credentials for %s", server.ID)
	}

	// Encode the temporary credentials as JSON for transport via the credential pipeline.
	tempCreds := awsTempCredentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
	data, err := json.Marshal(tempCreds)
	if err != nil {
		return nil, fmt.Errorf("credential: marshalling STS credentials: %w", err)
	}

	expiry := aws.ToTime(out.Credentials.Expiration)
	return &gateway.Credential{
		Type:      gateway.CredTypeIAMRole,
		Value:     data,
		ExpiresAt: &expiry,
		Metadata: map[string]string{
			"assumed_role_arn": aws.ToString(out.AssumedRoleUser.Arn),
			"role_arn":         cfg.RoleARN,
		},
	}, nil
}

// awsTempCredentials is the JSON structure stored in Credential.Value for STS credentials.
type awsTempCredentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration,omitempty"`
}

// sanitizeSessionName replaces characters not allowed in IAM role session names.
// Allowed: [a-zA-Z0-9=,.@-]
func sanitizeSessionName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '=' || c == ',' || c == '.' || c == '@' || c == '-' {
			out = append(out, c)
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}
