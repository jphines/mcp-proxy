package registry_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/registry"
)

// noopListFn is a ToolListFunc that always returns an empty tool list.
func noopListFn(_ context.Context, _ *gateway.ServerConfig) ([]gateway.Tool, error) {
	return nil, nil
}

// errorListFn always returns an error.
func errorListFn(_ context.Context, _ *gateway.ServerConfig) ([]gateway.Tool, error) {
	return nil, errors.New("downstream unavailable")
}

// testRegistryPath returns the path to the shared test fixture.
var testServersYAML = filepath.Join("..", "..", "testdata", "servers", "test-servers.yaml")

func newTestRegistry(t *testing.T) *registry.YAMLRegistry {
	t.Helper()
	r, err := registry.New(testServersYAML, noopListFn)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return r
}

// --- Get ---

func TestYAMLRegistry_GetKnownServer(t *testing.T) {
	t.Parallel()
	r := newTestRegistry(t)

	srv, err := r.Get(context.Background(), "github")
	require.NoError(t, err)
	assert.Equal(t, "github", srv.ID)
	assert.Equal(t, "GitHub", srv.Name)
	assert.Equal(t, gateway.TransportStreamableHTTP, srv.Transport.Type)
	assert.Equal(t, gateway.AuthStrategyOAuth, srv.Strategy)
	assert.Equal(t, 2, srv.DataTier)
	assert.True(t, srv.Enabled)
	assert.NotNil(t, srv.OAuthProvider)
}

func TestYAMLRegistry_GetUnknownServer(t *testing.T) {
	t.Parallel()
	r := newTestRegistry(t)

	_, err := r.Get(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, gateway.ErrServerNotFound))
}

// --- List ---

func TestYAMLRegistry_ListAll(t *testing.T) {
	t.Parallel()
	r := newTestRegistry(t)

	servers, err := r.List(context.Background(), nil)
	require.NoError(t, err)
	// test-servers.yaml has 4 servers
	assert.Len(t, servers, 4)
}

func TestYAMLRegistry_ListFilterEnabled(t *testing.T) {
	t.Parallel()
	r := newTestRegistry(t)

	enabled := true
	servers, err := r.List(context.Background(), &gateway.ServerFilter{Enabled: &enabled})
	require.NoError(t, err)
	for _, s := range servers {
		assert.True(t, s.Enabled)
	}
}

func TestYAMLRegistry_ListFilterStrategy(t *testing.T) {
	t.Parallel()
	r := newTestRegistry(t)

	strat := gateway.AuthStrategyOAuth
	servers, err := r.List(context.Background(), &gateway.ServerFilter{Strategy: &strat})
	require.NoError(t, err)
	// github and jira use oauth
	assert.Len(t, servers, 2)
	for _, s := range servers {
		assert.Equal(t, gateway.AuthStrategyOAuth, s.Strategy)
	}
}

// --- ToolCatalog ---

func TestYAMLRegistry_ToolCatalogFiltersAllowedGroups(t *testing.T) {
	t.Parallel()

	// github: allowed_groups: [engineering]
	// clinical: allowed_groups: [clinical-engineering, data-science]
	// infrastructure: allowed_groups: [platform-engineering]
	// jira: no allowed_groups (all allowed)
	listFn := func(_ context.Context, srv *gateway.ServerConfig) ([]gateway.Tool, error) {
		return []gateway.Tool{
			{NamespacedName: srv.ID + "::tool1", ServerID: srv.ID, OriginalName: "tool1"},
		}, nil
	}

	r, err := registry.New(testServersYAML, listFn)
	require.NoError(t, err)
	defer r.Close()

	identity := &gateway.Identity{
		Subject: "user@test.com",
		Groups:  []string{"engineering"},
	}

	tools, err := r.ToolCatalog(context.Background(), identity)
	require.NoError(t, err)

	serverIDs := make(map[string]bool)
	for _, t := range tools {
		serverIDs[t.ServerID] = true
	}

	// engineering is in github's AllowedGroups; jira has no AllowedGroups (open)
	assert.True(t, serverIDs["github"], "engineering should see github tools")
	assert.True(t, serverIDs["jira"], "all users should see jira tools (no AllowedGroups)")
	assert.False(t, serverIDs["clinical"], "engineering should NOT see clinical tools")
	assert.False(t, serverIDs["infrastructure"], "engineering should NOT see infra tools")
}

func TestYAMLRegistry_ToolCatalogCachesResults(t *testing.T) {
	t.Parallel()

	callCount := 0
	listFn := func(_ context.Context, srv *gateway.ServerConfig) ([]gateway.Tool, error) {
		if srv.ID == "github" {
			callCount++
		}
		return []gateway.Tool{{NamespacedName: srv.ID + "::t", ServerID: srv.ID, OriginalName: "t"}}, nil
	}

	r, err := registry.New(testServersYAML, listFn)
	require.NoError(t, err)
	defer r.Close()

	identity := &gateway.Identity{Subject: "u", Groups: []string{"engineering"}}
	ctx := context.Background()

	_, err = r.ToolCatalog(ctx, identity)
	require.NoError(t, err)
	first := callCount

	_, err = r.ToolCatalog(ctx, identity)
	require.NoError(t, err)

	// Second call should be served from cache, not incremented.
	assert.Equal(t, first, callCount, "second ToolCatalog call should hit cache")
}

func TestYAMLRegistry_ToolCatalogDownstreamErrorSkipsServer(t *testing.T) {
	t.Parallel()

	listFn := func(_ context.Context, srv *gateway.ServerConfig) ([]gateway.Tool, error) {
		if srv.ID == "github" {
			return errorListFn(context.Background(), srv)
		}
		return []gateway.Tool{{NamespacedName: srv.ID + "::t", ServerID: srv.ID, OriginalName: "t"}}, nil
	}

	r, err := registry.New(testServersYAML, listFn)
	require.NoError(t, err)
	defer r.Close()

	identity := &gateway.Identity{Subject: "u", Groups: []string{"engineering"}}
	tools, err := r.ToolCatalog(context.Background(), identity)
	require.NoError(t, err, "a single server failure should not fail ToolCatalog")

	serverIDs := map[string]bool{}
	for _, t := range tools {
		serverIDs[t.ServerID] = true
	}
	assert.False(t, serverIDs["github"], "github should be absent due to fetch error")
	assert.True(t, serverIDs["jira"], "jira (open AllowedGroups) should still be present")
}

// --- Execute / circuit breaker ---

func TestYAMLRegistry_Execute_CallsFn(t *testing.T) {
	t.Parallel()
	r := newTestRegistry(t)

	called := false
	err := r.Execute(context.Background(), "github", func() error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
}

func TestYAMLRegistry_Execute_OpensCircuitAfterFailures(t *testing.T) {
	t.Parallel()
	r := newTestRegistry(t)

	sentinelErr := errors.New("downstream error")
	ctx := context.Background()

	// github has failure_threshold: 5 in the YAML.
	for i := 0; i < 5; i++ {
		_ = r.Execute(ctx, "github", func() error { return sentinelErr })
	}

	// Next call should return ErrCircuitOpen immediately without calling fn.
	fnCalled := false
	err := r.Execute(ctx, "github", func() error {
		fnCalled = true
		return nil
	})
	assert.True(t, errors.Is(err, gateway.ErrCircuitOpen), "expected ErrCircuitOpen, got %v", err)
	assert.False(t, fnCalled, "fn should not be called when circuit is open")
}

func TestYAMLRegistry_Execute_UnknownServerCallsDirectly(t *testing.T) {
	t.Parallel()
	r := newTestRegistry(t)

	called := false
	err := r.Execute(context.Background(), "unknown-server", func() error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
}

// --- hot-reload ---

func TestYAMLRegistry_HotReload(t *testing.T) {
	t.Parallel()

	// Write a minimal servers.yaml to a temp file.
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.yaml")

	writeServers := func(id, name string) {
		content := "servers:\n  - id: " + id + "\n    name: " + name + "\n    transport:\n      type: streamable_http\n      url: https://test.internal\n    data_tier: 1\n    auth_strategy: static\n    credential_ref: proxy/test/key\n    auth_injection:\n      method: header_bearer\n    enabled: true\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	}

	writeServers("alpha", "Alpha")
	r, err := registry.New(path, noopListFn)
	require.NoError(t, err)
	defer r.Close()

	// Verify initial load.
	_, err = r.Get(context.Background(), "alpha")
	require.NoError(t, err)

	// Rewrite the file with a different server.
	writeServers("beta", "Beta")

	// Give the watcher time to fire.
	require.Eventually(t, func() bool {
		_, err := r.Get(context.Background(), "beta")
		return err == nil
	}, 2*time.Second, 50*time.Millisecond, "hot-reload should pick up beta")

	// Old server should be gone.
	_, err = r.Get(context.Background(), "alpha")
	assert.True(t, errors.Is(err, gateway.ErrServerNotFound))
}
