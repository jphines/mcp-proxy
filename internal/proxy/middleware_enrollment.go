package proxy

import (
	"context"
	"fmt"

	"github.com/jphines/mcp-proxy/gateway"
)

// enrollmentMiddleware verifies that the calling identity has completed the OAuth
// enrollment flow for the target server. Only OAuth-strategy servers require this check.
// If enrollment is missing, InitiateFlow is called to generate the enrollment URL and
// an EnrollmentRequiredError is set on tc.Err.
func (p *Proxy) enrollmentMiddleware(ctx context.Context, tc *gateway.ToolCallContext, next gateway.MiddlewareFunc) {
	if tc.ServerConfig == nil || tc.ServerConfig.Strategy != gateway.AuthStrategyOAuth {
		next(ctx, tc)
		return
	}
	if tc.Identity == nil {
		tc.Err = fmt.Errorf("%w: missing identity for OAuth enrollment check", gateway.ErrUnauthenticated)
		return
	}

	enrolled, err := p.deps.OAuthEnrollment.IsEnrolled(ctx, tc.Identity, tc.ServerID)
	if err != nil {
		tc.Err = fmt.Errorf("enrollment check: %w", err)
		return
	}
	if !enrolled {
		p.deps.MetricsCollector.EnrollmentRequired(tc.ServerID)
		enrollURL, _ := p.deps.OAuthEnrollment.InitiateFlow(ctx, tc.Identity, tc.ServerID)
		tc.Err = &gateway.EnrollmentRequiredError{
			ServiceID:   tc.ServerID,
			ServiceName: tc.ServerConfig.Name,
			EnrollURL:   enrollURL,
		}
		return
	}

	next(ctx, tc)
}
