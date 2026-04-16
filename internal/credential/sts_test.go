package credential_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/credential"
)

// mockSTSClient implements credential.STSClient for testing.
type mockSTSClient struct {
	out *sts.AssumeRoleWithWebIdentityOutput
	err error
}

func (m *mockSTSClient) AssumeRoleWithWebIdentity(_ context.Context, _ *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return m.out, m.err
}

func TestSTSResolver_Success(t *testing.T) {
	t.Parallel()

	expiry := time.Now().Add(15 * time.Minute)
	client := &mockSTSClient{
		out: &sts.AssumeRoleWithWebIdentityOutput{
			Credentials: &ststypes.Credentials{
				AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				SessionToken:    aws.String("FwoGZXIvYXdzEA..."),
				Expiration:      aws.Time(expiry),
			},
			AssumedRoleUser: &ststypes.AssumedRoleUser{
				Arn: aws.String("arn:aws:sts::123456789012:assumed-role/MyRole/mcp-proxy-alice"),
			},
		},
	}

	resolver := credential.NewSTSResolver(client)
	identity := &gateway.Identity{
		Subject:  "alice@example.com",
		RawToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
	}
	server := &gateway.ServerConfig{
		ID:       "aws-svc",
		Strategy: gateway.AuthStrategySTS,
		STSConfig: &gateway.STSConfig{
			RoleARN:           "arn:aws:iam::123456789012:role/MyRole",
			SessionNamePrefix: "mcp-proxy-",
			DurationSeconds:   900,
		},
	}

	cred, err := resolver.Resolve(context.Background(), identity, server)
	require.NoError(t, err)
	assert.Equal(t, gateway.CredTypeIAMRole, cred.Type)
	assert.NotNil(t, cred.ExpiresAt)
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", cred.Metadata["role_arn"])
	assert.Equal(t, "arn:aws:sts::123456789012:assumed-role/MyRole/mcp-proxy-alice", cred.Metadata["assumed_role_arn"])

	// Verify the credential value is JSON-encoded temporary credentials.
	var tempCreds struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token"`
	}
	require.NoError(t, json.Unmarshal(cred.Value, &tempCreds))
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", tempCreds.AccessKeyID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", tempCreds.SecretAccessKey)
	assert.Equal(t, "FwoGZXIvYXdzEA...", tempCreds.SessionToken)
}

func TestSTSResolver_NilIdentity(t *testing.T) {
	t.Parallel()
	resolver := credential.NewSTSResolver(&mockSTSClient{})
	server := &gateway.ServerConfig{
		ID:       "aws-svc",
		Strategy: gateway.AuthStrategySTS,
		STSConfig: &gateway.STSConfig{
			RoleARN: "arn:aws:iam::123456789012:role/MyRole",
		},
	}

	_, err := resolver.Resolve(context.Background(), nil, server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires an authenticated identity")
}

func TestSTSResolver_MissingRawToken(t *testing.T) {
	t.Parallel()
	resolver := credential.NewSTSResolver(&mockSTSClient{})
	identity := &gateway.Identity{Subject: "alice"}
	server := &gateway.ServerConfig{
		ID:       "aws-svc",
		Strategy: gateway.AuthStrategySTS,
		STSConfig: &gateway.STSConfig{
			RoleARN: "arn:aws:iam::123456789012:role/MyRole",
		},
	}

	_, err := resolver.Resolve(context.Background(), identity, server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RawToken")
}

func TestSTSResolver_NilSTSConfig(t *testing.T) {
	t.Parallel()
	resolver := credential.NewSTSResolver(&mockSTSClient{})
	identity := &gateway.Identity{Subject: "alice", RawToken: "tok"}
	server := &gateway.ServerConfig{
		ID:       "aws-svc",
		Strategy: gateway.AuthStrategySTS,
	}

	_, err := resolver.Resolve(context.Background(), identity, server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no sts_config")
}

func TestSTSResolver_STSError(t *testing.T) {
	t.Parallel()
	client := &mockSTSClient{err: assert.AnError}
	resolver := credential.NewSTSResolver(client)
	identity := &gateway.Identity{Subject: "alice", RawToken: "tok"}
	server := &gateway.ServerConfig{
		ID:       "aws-svc",
		Strategy: gateway.AuthStrategySTS,
		STSConfig: &gateway.STSConfig{
			RoleARN:           "arn:aws:iam::123456789012:role/MyRole",
			SessionNamePrefix: "mcp-proxy-",
		},
	}

	_, err := resolver.Resolve(context.Background(), identity, server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AssumeRoleWithWebIdentity")
}

func TestSTSResolver_SessionNameSanitization(t *testing.T) {
	t.Parallel()

	expiry := time.Now().Add(15 * time.Minute)
	var capturedInput *sts.AssumeRoleWithWebIdentityInput
	client := &capturingSTSClient{
		out: &sts.AssumeRoleWithWebIdentityOutput{
			Credentials: &ststypes.Credentials{
				AccessKeyId:     aws.String("AKIA"),
				SecretAccessKey: aws.String("secret"),
				SessionToken:    aws.String("token"),
				Expiration:      aws.Time(expiry),
			},
			AssumedRoleUser: &ststypes.AssumedRoleUser{
				Arn: aws.String("arn:aws:sts::123:assumed-role/R/s"),
			},
		},
		capture: func(in *sts.AssumeRoleWithWebIdentityInput) { capturedInput = in },
	}

	resolver := credential.NewSTSResolver(client)
	identity := &gateway.Identity{
		Subject:  "user+special chars!@example.com",
		RawToken: "tok",
	}
	server := &gateway.ServerConfig{
		ID:       "svc",
		Strategy: gateway.AuthStrategySTS,
		STSConfig: &gateway.STSConfig{
			RoleARN:           "arn:aws:iam::123:role/R",
			SessionNamePrefix: "p-",
		},
	}

	_, err := resolver.Resolve(context.Background(), identity, server)
	require.NoError(t, err)

	// Check the session name was sanitized.
	sessionName := aws.ToString(capturedInput.RoleSessionName)
	assert.Equal(t, "p-user-special-chars-@example.com", sessionName)
}

// capturingSTSClient captures the input for assertion.
type capturingSTSClient struct {
	out     *sts.AssumeRoleWithWebIdentityOutput
	capture func(*sts.AssumeRoleWithWebIdentityInput)
}

func (c *capturingSTSClient) AssumeRoleWithWebIdentity(_ context.Context, in *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	c.capture(in)
	return c.out, nil
}
