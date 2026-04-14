package gateway

//go:generate go run github.com/vektra/mockery/v2

// Dependencies bundles all gateway interface implementations together.
// cmd/mcp-proxy/main.go constructs this and passes it to proxy.New.
type Dependencies struct {
	Authenticator     Authenticator
	PolicyEngine      PolicyEngine
	CredentialStore   CredentialStore
	CredentialResolver CredentialResolver
	ServerRegistry    ServerRegistry
	AuditLogger       AuditLogger
	ApprovalService   ApprovalService
	OAuthEnrollment   OAuthEnrollment
	TokenExchanger    TokenExchanger
	MetricsCollector  MetricsCollector
}
