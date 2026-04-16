package proxy

import (
	"context"
	"fmt"

	"github.com/jphines/mcp-proxy/gateway"
)

// authMiddleware extracts the bearer token from the context (placed there by
// the HTTP middleware / GetServer) and validates it via the Authenticator.
func (p *Proxy) authMiddleware(ctx context.Context, tc *gateway.ToolCallContext, next gateway.MiddlewareFunc) {
	token, _ := ctx.Value(bearerTokenCtxKey).(string)
	if token == "" {
		tc.Err = fmt.Errorf("%w: missing bearer token", gateway.ErrUnauthenticated)
		return
	}

	identity, err := p.deps.Authenticator.Authenticate(ctx, token)
	if err != nil {
		tc.Err = err
		return
	}

	tc.Identity = identity
	next(ctx, tc)
}
