package proxy

import (
	"context"
	"time"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// credentialMiddleware resolves the downstream credential for the current call.
// It sets tc.Credential (the secret material) and tc.Injection (how to attach it),
// then defers cred.Zero() to wipe the secret from memory after the inner chain returns.
func (p *Proxy) credentialMiddleware(ctx context.Context, tc *gateway.ToolCallContext, next gateway.MiddlewareFunc) {
	start := time.Now()
	cred, err := p.deps.CredentialResolver.Resolve(ctx, tc.Identity, tc.ServerConfig)
	p.deps.MetricsCollector.CredentialResolutionDuration(
		tc.ServerID,
		string(tc.ServerConfig.Strategy),
		time.Since(start).Milliseconds(),
	)

	if err != nil {
		tc.Err = err
		return
	}
	defer cred.Zero()

	tc.Credential = cred
	injection := tc.ServerConfig.AuthInjection
	tc.Injection = &injection

	next(ctx, tc)
}
