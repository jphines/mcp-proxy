package credential_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/credential"
	"github.com/ro-eng/mcp-proxy/internal/mocks"
)

func newResolver(t *testing.T, store gateway.CredentialStore, enroll gateway.OAuthEnrollment) *credential.CompositeResolver {
	t.Helper()
	return credential.NewCompositeResolver(store, enroll, nil)
}

// --- OAuth strategy ---

func TestCompositeResolver_OAuth_CacheHit(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	identity := &gateway.Identity{Subject: "alice"}
	server := &gateway.ServerConfig{ID: "github", Strategy: gateway.AuthStrategyOAuth}
	expected := &gateway.Credential{Type: gateway.CredTypeOAuthAccess, Value: []byte("tok")}

	enroll.EXPECT().AccessToken(context.Background(), identity, "github").Return(expected, nil)

	r := newResolver(t, store, enroll)
	cred, err := r.Resolve(context.Background(), identity, server)
	require.NoError(t, err)
	assert.Equal(t, expected, cred)
}

func TestCompositeResolver_OAuth_EnrollmentRequired(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	identity := &gateway.Identity{Subject: "alice"}
	server := &gateway.ServerConfig{ID: "github", Strategy: gateway.AuthStrategyOAuth}

	enroll.EXPECT().AccessToken(context.Background(), identity, "github").
		Return(nil, &gateway.EnrollmentRequiredError{ServiceID: "github", EnrollURL: "https://proxy/oauth/enroll/github"})

	r := newResolver(t, store, enroll)
	_, err := r.Resolve(context.Background(), identity, server)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrEnrollmentRequired))
}

// --- Static strategy ---

func TestCompositeResolver_Static_ReturnsOrgCredential(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	server := &gateway.ServerConfig{
		ID:            "clinical",
		Strategy:      gateway.AuthStrategyStatic,
		CredentialRef: "proxy/clinical/api-key",
	}
	expected := &gateway.Credential{Type: gateway.CredTypeAPIKey, Value: []byte("api-key-value")}

	store.EXPECT().Resolve(context.Background(), (*gateway.Identity)(nil), "proxy/clinical/api-key").
		Return(expected, nil)

	r := newResolver(t, store, enroll)
	cred, err := r.Resolve(context.Background(), &gateway.Identity{Subject: "alice"}, server)
	require.NoError(t, err)
	assert.Equal(t, expected, cred)
}

func TestCompositeResolver_Static_NotFound(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	server := &gateway.ServerConfig{
		ID:            "clinical",
		Strategy:      gateway.AuthStrategyStatic,
		CredentialRef: "proxy/clinical/missing",
	}

	store.EXPECT().Resolve(context.Background(), (*gateway.Identity)(nil), "proxy/clinical/missing").
		Return(nil, gateway.ErrCredentialNotFound)

	r := newResolver(t, store, enroll)
	_, err := r.Resolve(context.Background(), &gateway.Identity{Subject: "alice"}, server)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrCredentialNotFound))
}

// --- XAA strategy ---

func TestCompositeResolver_XAA_ReturnsNotSupported(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	server := &gateway.ServerConfig{ID: "xaa-svc", Strategy: gateway.AuthStrategyXAA}
	r := newResolver(t, store, enroll)
	_, err := r.Resolve(context.Background(), &gateway.Identity{Subject: "alice"}, server)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrXAANotSupported))
}

// --- STS strategy ---

// stubSTSClient implements the unexported stsClient interface via structural typing.
type stubSTSClient struct {
	out *sts.AssumeRoleWithWebIdentityOutput
	err error
}

func (s *stubSTSClient) AssumeRoleWithWebIdentity(_ context.Context, _ *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return s.out, s.err
}

func TestCompositeResolver_STS_ReturnsTempCredential(t *testing.T) {
	t.Parallel()
	credStore := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	expiry := time.Now().Add(time.Hour)
	stub := &stubSTSClient{
		out: &sts.AssumeRoleWithWebIdentityOutput{
			Credentials: &stypes.Credentials{
				AccessKeyId:     aws.String("AKIA123"),
				SecretAccessKey: aws.String("secretXYZ"),
				SessionToken:    aws.String("sessToken"),
				Expiration:      &expiry,
			},
		},
	}

	identity := &gateway.Identity{Subject: "alice", RawToken: "jwt.token.here"}
	server := &gateway.ServerConfig{
		ID:            "aws-svc",
		Strategy:      gateway.AuthStrategySTS,
		CredentialRef: "arn:aws:iam::123456789:role/mcp-proxy-role",
	}

	r := credential.NewCompositeResolver(credStore, enroll, stub)
	cred, err := r.Resolve(context.Background(), identity, server)
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, gateway.CredTypeIAMRole, cred.Type)
	assert.Equal(t, "sessToken", string(cred.Value))
	assert.Equal(t, "AKIA123", cred.Metadata["access_key_id"])
	assert.Equal(t, "secretXYZ", cred.Metadata["secret_access_key"])
	assert.NotNil(t, cred.ExpiresAt)
}

func TestCompositeResolver_STS_NoClient_ReturnsError(t *testing.T) {
	t.Parallel()
	credStore := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	server := &gateway.ServerConfig{ID: "aws-svc", Strategy: gateway.AuthStrategySTS}
	// newResolver passes nil for stsClient
	r := newResolver(t, credStore, enroll)
	_, err := r.Resolve(context.Background(), &gateway.Identity{Subject: "alice"}, server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "STS client not configured")
}

func TestCompositeResolver_STS_NilIdentity_ReturnsError(t *testing.T) {
	t.Parallel()
	credStore := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	stub := &stubSTSClient{}
	server := &gateway.ServerConfig{ID: "aws-svc", Strategy: gateway.AuthStrategySTS}
	r := credential.NewCompositeResolver(credStore, enroll, stub)
	_, err := r.Resolve(context.Background(), nil, server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticated identity")
}

func TestCompositeResolver_STS_ProviderError_ReturnsError(t *testing.T) {
	t.Parallel()
	credStore := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	stub := &stubSTSClient{err: errors.New("STS unavailable")}
	identity := &gateway.Identity{Subject: "bob", RawToken: "tok"}
	server := &gateway.ServerConfig{
		ID:            "aws-svc",
		Strategy:      gateway.AuthStrategySTS,
		CredentialRef: "arn:aws:iam::123:role/test",
	}
	r := credential.NewCompositeResolver(credStore, enroll, stub)
	_, err := r.Resolve(context.Background(), identity, server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AssumeRoleWithWebIdentity")
}

// --- Unknown strategy ---

func TestCompositeResolver_UnknownStrategy_ReturnsError(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	server := &gateway.ServerConfig{ID: "svc", Strategy: "unknown"}
	r := newResolver(t, store, enroll)
	_, err := r.Resolve(context.Background(), &gateway.Identity{Subject: "alice"}, server)
	require.Error(t, err)
}
