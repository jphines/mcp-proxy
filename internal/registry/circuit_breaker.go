package registry

import (
	"errors"
	"fmt"
	"sync"

	"github.com/sony/gobreaker"

	"github.com/jphines/mcp-proxy/gateway"
)

// circuitBreakerMap manages a per-server gobreaker.CircuitBreaker.
// Circuit breaker instances persist across hot-reloads so state is not lost
// when servers.yaml is reloaded.
type circuitBreakerMap struct {
	mu       sync.RWMutex
	breakers map[string]*gobreaker.CircuitBreaker
}

func newCircuitBreakerMap() *circuitBreakerMap {
	return &circuitBreakerMap{breakers: make(map[string]*gobreaker.CircuitBreaker)}
}

// ensure returns the circuit breaker for serverID, creating it if needed.
// If the server's settings have changed, the circuit breaker is replaced
// (resetting its state — acceptable since config changes are operator-driven).
func (m *circuitBreakerMap) ensure(srv *gateway.ServerConfig) {
	settings := breakerSettings(srv)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Only create if absent; settings changes reset state (intentional).
	if _, ok := m.breakers[srv.ID]; !ok {
		m.breakers[srv.ID] = gobreaker.NewCircuitBreaker(settings)
	}
}

// execute runs fn within the circuit breaker for serverID.
// Returns gateway.ErrCircuitOpen immediately if the circuit is open.
func (m *circuitBreakerMap) execute(serverID string, fn func() error) error {
	m.mu.RLock()
	cb, ok := m.breakers[serverID]
	m.mu.RUnlock()

	if !ok {
		// No circuit breaker configured for this server; call directly.
		return fn()
	}

	_, err := cb.Execute(func() (any, error) {
		return nil, fn()
	})
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		return fmt.Errorf("%w: %s", gateway.ErrCircuitOpen, serverID)
	}
	return err
}

// state returns the current gobreaker.State for serverID, defaulting to StateClosed.
func (m *circuitBreakerMap) state(serverID string) gobreaker.State {
	m.mu.RLock()
	cb, ok := m.breakers[serverID]
	m.mu.RUnlock()
	if !ok {
		return gobreaker.StateClosed
	}
	return cb.State()
}

// breakerSettings converts a ServerConfig's CircuitBreakerConfig into gobreaker.Settings.
func breakerSettings(srv *gateway.ServerConfig) gobreaker.Settings {
	cfg := srv.CircuitBreaker

	threshold := cfg.FailureThreshold
	if threshold <= 0 {
		threshold = 5 // default
	}
	maxRequests := uint32(cfg.HalfOpenMax)
	if maxRequests == 0 {
		maxRequests = 1
	}
	timeout := cfg.ResetTimeout
	if timeout == 0 {
		timeout = 30e9 // 30s default
	}

	return gobreaker.Settings{
		Name:        srv.ID,
		MaxRequests: maxRequests,
		Timeout:     timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= uint32(threshold)
		},
	}
}
