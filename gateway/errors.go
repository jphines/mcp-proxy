package gateway

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by gateway implementations.
var (
	// ErrUnauthenticated is returned when a token is missing, invalid, expired,
	// or cannot be validated against the JWKS endpoint.
	ErrUnauthenticated = errors.New("unauthenticated")

	// ErrCredentialNotFound is returned when no credential exists for the
	// requested identity and service at any scope level.
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrServerNotFound is returned when no server is registered with the given ID.
	ErrServerNotFound = errors.New("server not found")

	// ErrPolicyDenied is returned when a deny-action rule matches the tool call.
	ErrPolicyDenied = errors.New("denied by policy")

	// ErrApprovalRejected is returned when a HITL approver rejects the call.
	ErrApprovalRejected = errors.New("rejected by approver")

	// ErrApprovalTimedOut is returned when no HITL decision arrives before the timeout.
	ErrApprovalTimedOut = errors.New("approval request timed out")

	// ErrXAANotSupported is returned by the TokenExchanger stub in Phase 1.
	ErrXAANotSupported = errors.New("XAA token exchange not yet supported")

	// ErrCircuitOpen is returned when a server's circuit breaker is in the Open state.
	ErrCircuitOpen = errors.New("circuit breaker open")
)

// EnrollmentRequiredError is returned by CredentialResolver and EnrollmentMiddleware
// when the calling identity has not yet completed the OAuth enrollment flow for a service.
type EnrollmentRequiredError struct {
	// ServiceID is the downstream server's registration ID.
	ServiceID string
	// ServiceName is the human-readable service name.
	ServiceName string
	// EnrollURL is the URL the engineer must open to complete enrollment.
	EnrollURL string
}

func (e *EnrollmentRequiredError) Error() string {
	return fmt.Sprintf("OAuth enrollment required for service %q: visit %s", e.ServiceID, e.EnrollURL)
}

// Is implements errors.Is support so callers can check for EnrollmentRequiredError
// without type-asserting.
func (e *EnrollmentRequiredError) Is(target error) bool {
	_, ok := target.(*EnrollmentRequiredError)
	return ok
}

// ErrEnrollmentRequired is a sentinel value for use with errors.Is.
var ErrEnrollmentRequired = &EnrollmentRequiredError{}
