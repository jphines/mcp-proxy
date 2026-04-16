package credential_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/credential"
	"github.com/jphines/mcp-proxy/internal/mocks"
)

// mockSTSClientForResolver returns minimal valid STS output for resolver tests.
type mockSTSClientForResolver struct{}

func (m *mockSTSClientForResolver) AssumeRoleWithWebIdentity(_ context.Context, _ *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	exp := time.Now().Add(15 * time.Minute)
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIA"),
			SecretAccessKey: aws.String("secret"),
			SessionToken:    aws.String("token"),
			Expiration:      aws.Time(exp),
		},
		AssumedRoleUser: &ststypes.AssumedRoleUser{
			Arn: aws.String("arn:aws:sts::123:assumed-role/R/s"),
		},
	}, nil
}

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

// --- STS strategy ---

func TestCompositeResolver_STS_Resolves(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	// The STS strategy delegates to the STSResolver, so we just need a minimal
	// mock STS client that returns valid credentials.
	stsClient := &mockSTSClientForResolver{}
	stsResolver := credential.NewSTSResolver(stsClient)

	identity := &gateway.Identity{Subject: "alice", RawToken: "jwt-token"}
	server := &gateway.ServerConfig{
		ID:       "aws-svc",
		Strategy: gateway.AuthStrategySTS,
		STSConfig: &gateway.STSConfig{
			RoleARN:           "arn:aws:iam::123:role/R",
			SessionNamePrefix: "mcp-",
		},
	}

	r := credential.NewCompositeResolver(store, enroll, stsResolver)
	cred, err := r.Resolve(context.Background(), identity, server)
	require.NoError(t, err)
	assert.Equal(t, gateway.CredTypeIAMRole, cred.Type)
}

func TestCompositeResolver_STS_NilResolver(t *testing.T) {
	t.Parallel()
	store := mocks.NewMockCredentialStore(t)
	enroll := mocks.NewMockOAuthEnrollment(t)

	server := &gateway.ServerConfig{
		ID:       "aws-svc",
		Strategy: gateway.AuthStrategySTS,
		STSConfig: &gateway.STSConfig{
			RoleARN: "arn:aws:iam::123:role/R",
		},
	}

	r := credential.NewCompositeResolver(store, enroll, nil)
	_, err := r.Resolve(context.Background(), &gateway.Identity{Subject: "alice", RawToken: "tok"}, server)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no STS client configured")
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
