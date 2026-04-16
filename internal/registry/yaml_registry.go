// Package registry implements gateway.ServerRegistry backed by a hot-reloadable
// servers.yaml file and per-server sony/gobreaker circuit breakers.
package registry

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/config"
)

// ToolListFunc is called by the tool catalog to retrieve the tools offered by a
// downstream MCP server. The implementation lives in internal/proxy/dispatch.go;
// pass a test stub during unit tests.
type ToolListFunc func(ctx context.Context, server *gateway.ServerConfig) ([]gateway.Tool, error)

// YAMLRegistry loads servers.yaml, exposes the gateway.ServerRegistry interface,
// and hot-reloads on file changes.
type YAMLRegistry struct {
	path     string
	listFn   ToolListFunc
	breakers *circuitBreakerMap
	catalog  *toolCache

	mu      sync.RWMutex
	servers map[string]*gateway.ServerConfig // keyed by ID

	watcher *fsnotify.Watcher
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// New loads servers.yaml from path, initialises circuit breakers, and starts
// the fsnotify hot-reload goroutine. Call Close() to stop watching.
// listFn is called (with a 30-second cache) to populate ToolCatalog results.
func New(path string, listFn ToolListFunc) (*YAMLRegistry, error) {
	r := &YAMLRegistry{
		path:     path,
		listFn:   listFn,
		breakers: newCircuitBreakerMap(),
		catalog:  newToolCache(30 * time.Second),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}

	if err := r.reload(); err != nil {
		return nil, err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("registry: creating file watcher: %w", err)
	}
	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("registry: watching %s: %w", path, err)
	}
	r.watcher = watcher

	go r.watchLoop()
	return r, nil
}

// Close stops the fsnotify goroutine and closes the watcher.
func (r *YAMLRegistry) Close() {
	close(r.stopCh)
	<-r.doneCh
	r.watcher.Close()
}

// Get returns the ServerConfig for id, or ErrServerNotFound.
func (r *YAMLRegistry) Get(_ context.Context, id string) (*gateway.ServerConfig, error) {
	r.mu.RLock()
	srv, ok := r.servers[id]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", gateway.ErrServerNotFound, id)
	}
	return srv, nil
}

// List returns all servers matching the optional filter.
func (r *YAMLRegistry) List(_ context.Context, filter *gateway.ServerFilter) ([]*gateway.ServerConfig, error) {
	r.mu.RLock()
	all := make([]*gateway.ServerConfig, 0, len(r.servers))
	for _, srv := range r.servers {
		all = append(all, srv)
	}
	r.mu.RUnlock()

	if filter == nil {
		return all, nil
	}

	var out []*gateway.ServerConfig
	for _, srv := range all {
		if filter.Enabled != nil && srv.Enabled != *filter.Enabled {
			continue
		}
		if filter.Strategy != nil && srv.Strategy != *filter.Strategy {
			continue
		}
		if filter.DataTier != nil && srv.DataTier > *filter.DataTier {
			continue
		}
		out = append(out, srv)
	}
	return out, nil
}

// ToolCatalog returns the aggregated, AllowedGroups-filtered tool catalog for identity.
// Results per server are cached for 30 seconds. A server whose tool fetch fails is
// skipped (stale cache or empty) rather than failing the whole catalog.
func (r *YAMLRegistry) ToolCatalog(ctx context.Context, identity *gateway.Identity) ([]gateway.Tool, error) {
	enabled := true
	servers, err := r.List(ctx, &gateway.ServerFilter{Enabled: &enabled})
	if err != nil {
		return nil, err
	}

	var (
		mu  sync.Mutex
		all []gateway.Tool
		wg  sync.WaitGroup
	)

	for _, srv := range servers {
		if !identityAllowed(identity, srv.AllowedGroups) {
			continue
		}
		srv := srv // capture loop variable
		wg.Add(1)
		go func() {
			defer wg.Done()

			tools, ok := r.catalog.get(srv.ID)
			if !ok {
				var fetchErr error
				tools, fetchErr = r.listFn(ctx, srv)
				if fetchErr != nil {
					slog.WarnContext(ctx, "registry: tool list fetch failed",
						slog.String("server_id", srv.ID),
						slog.String("error", fetchErr.Error()),
					)
					return
				}
				r.catalog.set(srv.ID, tools)
			}

			mu.Lock()
			all = append(all, tools...)
			mu.Unlock()
		}()
	}

	wg.Wait()
	return all, nil
}

// Execute calls fn within serverID's circuit breaker.
// Returns gateway.ErrCircuitOpen immediately if the breaker is open.
func (r *YAMLRegistry) Execute(_ context.Context, serverID string, fn func() error) error {
	return r.breakers.execute(serverID, fn)
}

// --- hot-reload ---

func (r *YAMLRegistry) watchLoop() {
	defer close(r.doneCh)
	for {
		select {
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if err := r.reload(); err != nil {
					slog.Error("registry: hot-reload failed — keeping existing servers",
						slog.String("error", err.Error()),
					)
				}
			}
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("registry: watcher error", slog.String("error", err.Error()))
		case <-r.stopCh:
			return
		}
	}
}

func (r *YAMLRegistry) reload() error {
	sf, err := config.LoadServers(r.path)
	if err != nil {
		return fmt.Errorf("registry: loading servers: %w", err)
	}

	servers := make(map[string]*gateway.ServerConfig, len(sf.Servers))
	for _, entry := range sf.Servers {
		srv := entryToConfig(entry)
		servers[srv.ID] = srv
		r.breakers.ensure(srv)
	}

	r.mu.Lock()
	r.servers = servers
	r.mu.Unlock()

	slog.Info("registry: loaded servers", slog.Int("count", len(servers)))
	return nil
}

// --- helpers ---

// identityAllowed returns true when allowedGroups is empty (all callers allowed)
// or when the identity belongs to at least one of the allowed groups.
func identityAllowed(identity *gateway.Identity, allowedGroups []string) bool {
	if len(allowedGroups) == 0 {
		return true
	}
	if identity == nil {
		return false
	}
	for _, ag := range allowedGroups {
		for _, ig := range identity.Groups {
			if ag == ig {
				return true
			}
		}
	}
	return false
}

// entryToConfig converts a config.ServerEntry to a gateway.ServerConfig.
func entryToConfig(e config.ServerEntry) *gateway.ServerConfig {
	srv := &gateway.ServerConfig{
		ID:            e.ID,
		Name:          e.Name,
		DataTier:      e.DataTier,
		Strategy:      gateway.AuthStrategy(e.AuthStrategy),
		CredentialRef: e.CredentialRef,
		AllowedGroups: e.AllowedGroups,
		Tags:          e.Tags,
		Transport: gateway.TransportConfig{
			Type:    gateway.TransportType(e.Transport.Type),
			URL:     e.Transport.URL,
			Command: e.Transport.Command,
			Args:    e.Transport.Args,
			Headers: e.Transport.Headers,
		},
		AuthInjection: gateway.AuthInjection{
			Method:     gateway.InjectionMethod(e.AuthInjection.Method),
			Header:     e.AuthInjection.Header,
			Prefix:     e.AuthInjection.Prefix,
			EnvVar:     e.AuthInjection.EnvVar,
			QueryParam: e.AuthInjection.QueryParam,
		},
		Enabled: e.Enabled == nil || *e.Enabled,
	}

	if e.OAuthProvider != nil {
		srv.OAuthProvider = &gateway.OAuthProvider{
			ServiceID:       e.ID,
			AuthURL:         e.OAuthProvider.AuthURL,
			TokenURL:        e.OAuthProvider.TokenURL,
			RevokeURL:       e.OAuthProvider.RevokeURL,
			ClientID:        e.OAuthProvider.ClientID,
			ClientSecretRef: e.OAuthProvider.ClientSecretRef,
			Scopes:          e.OAuthProvider.Scopes,
			PKCERequired:    e.OAuthProvider.PKCERequired,
		}
	}

	if e.STSConfig != nil {
		prefix := e.STSConfig.SessionNamePrefix
		if prefix == "" {
			prefix = "mcp-proxy-"
		}
		duration := e.STSConfig.DurationSeconds
		if duration == 0 {
			duration = 900
		}
		srv.STSConfig = &gateway.STSConfig{
			RoleARN:           e.STSConfig.RoleARN,
			SessionNamePrefix: prefix,
			DurationSeconds:   duration,
		}
	}

	if d, err := time.ParseDuration(e.CircuitBreaker.ResetTimeout); err == nil {
		srv.CircuitBreaker = gateway.CircuitBreakerConfig{
			FailureThreshold: e.CircuitBreaker.FailureThreshold,
			ResetTimeout:     d,
			HalfOpenMax:      e.CircuitBreaker.HalfOpenMax,
		}
	} else if e.CircuitBreaker.FailureThreshold > 0 {
		srv.CircuitBreaker = gateway.CircuitBreakerConfig{
			FailureThreshold: e.CircuitBreaker.FailureThreshold,
			ResetTimeout:     30 * time.Second,
			HalfOpenMax:      e.CircuitBreaker.HalfOpenMax,
		}
	}

	return srv
}

var _ gateway.ServerRegistry = (*YAMLRegistry)(nil)
