// Command mcp-proxy is the MCP governance proxy.
//
// It wires all internal components bottom-up, starts the HTTP server, and
// handles graceful shutdown on SIGTERM/SIGINT.
//
// Startup order:
//  1. Load and validate configuration from environment variables.
//  2. Connect to PostgreSQL; run migrations (hard failure — both audit and
//     credentials require the database).
//  3. Construct the audit hash chain seed via PostgreSQL.
//  4. Build all internal components (metrics, credential store, registry, policy, …).
//  5. Assemble gateway.Dependencies and create the Proxy.
//  6. Start the HTTP server (TLS if cert/key configured, plain HTTP otherwise).
//  7. Block until SIGTERM/SIGINT; drain in-flight requests, then shut down.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/approval"
	"github.com/jphines/mcp-proxy/internal/auth"
	pgaudit "github.com/jphines/mcp-proxy/internal/audit"
	"github.com/jphines/mcp-proxy/internal/config"
	"github.com/jphines/mcp-proxy/internal/credential"
	credstore "github.com/jphines/mcp-proxy/internal/credential/store"
	"github.com/jphines/mcp-proxy/internal/metrics"
	"github.com/jphines/mcp-proxy/internal/oauth"
	"github.com/jphines/mcp-proxy/internal/policy"
	"github.com/jphines/mcp-proxy/internal/proxy"
	"github.com/jphines/mcp-proxy/internal/registry"
	"github.com/jphines/mcp-proxy/internal/store"
)

func main() {
	// Structured logger to stderr; level from LOG_LEVEL env (default: info).
	logLevel := slog.LevelInfo
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		if err := logLevel.UnmarshalText([]byte(v)); err != nil {
			slog.Warn("invalid LOG_LEVEL; using info", slog.String("value", v))
		}
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	ctx := context.Background()
	if err := run(ctx); err != nil {
		slog.Error("startup failed", slog.String("error", err.Error()))
		os.Exit(2)
	}
}

func run(ctx context.Context) error {
	// ── 1. Configuration ─────────────────────────────────────────────────────
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("configuration error:\n%w", err)
	}
	slog.Info("configuration loaded",
		slog.String("workspace", cfg.Workspace),
		slog.String("listen_addr", cfg.ListenAddr),
		slog.String("instance_id", cfg.InstanceID),
	)

	// ── 2. PostgreSQL ─────────────────────────────────────────────────────────
	// Both audit logging and credential storage require PostgreSQL.
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	defer db.Close()

	// ── 3. Audit hash chain seed ──────────────────────────────────────────────
	genesisHash := randomHex(32)
	seedCtx, seedCancel := context.WithTimeout(ctx, 5*cfg.ShutdownTimeout/30)
	defer seedCancel()
	if stored, err := db.UpsertChainGenesis(seedCtx, cfg.InstanceID, genesisHash); err != nil {
		slog.Warn("could not persist genesis hash; using ephemeral seed",
			slog.String("error", err.Error()))
	} else {
		genesisHash = stored
	}

	// ── 4. Internal components ─────────────────────────────────────────────────

	// Metrics — register once; subsequent calls would panic.
	metricsCollector := metrics.New()

	// ── AWS SDK (lazy — only loaded when needed) ──────────────────────────────
	var awsCfg *aws.Config
	loadAWSConfig := func() (*aws.Config, error) {
		if awsCfg != nil {
			return awsCfg, nil
		}
		var opts []func(*awsconfig.LoadOptions) error
		if cfg.AWSRegion != "" {
			opts = append(opts, awsconfig.WithRegion(cfg.AWSRegion))
		}
		c, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("loading AWS SDK config: %w", err)
		}
		awsCfg = &c
		return awsCfg, nil
	}

	// Credential store — either PostgreSQL or AWS Secrets Manager.
	var credStore gateway.CredentialStore
	switch cfg.CredentialBackend {
	case "secretsmanager":
		ac, err := loadAWSConfig()
		if err != nil {
			return err
		}
		smClient := secretsmanager.NewFromConfig(*ac)
		credStore, err = credstore.New(smClient, cfg.CredentialCacheTTL)
		if err != nil {
			return fmt.Errorf("initialising Secrets Manager credential store: %w", err)
		}
		slog.Info("credential store: AWS Secrets Manager")
	default: // "postgres"
		credStore, err = credstore.NewPostgres(db.Pool(), []byte(cfg.CredentialEncryptionKey), cfg.CredentialCacheTTL)
		if err != nil {
			return fmt.Errorf("initialising credential store: %w", err)
		}
		slog.Info("credential store: PostgreSQL")
	}

	// OAuth token cache (5-minute GC interval).
	tokenCache := oauth.NewTokenCache(5 * cfg.ApprovalTimeout / 30)

	// Server registry — loaded from servers.yaml; hot-reloaded via fsnotify.
	serversYAML := cfg.ConfigDir + "/servers.yaml"
	reg, err := registry.New(serversYAML, proxy.NewToolLister())
	if err != nil {
		return fmt.Errorf("loading server registry from %s: %w", serversYAML, err)
	}
	defer reg.Close()

	// OAuth enrollment (depends on credStore + reg).
	enrollment := oauth.NewEnrollment(oauth.EnrollmentOptions{
		CredentialStore: credStore,
		ServerRegistry:  reg,
		TokenCache:      tokenCache,
		HMACSecret:      []byte(cfg.StateHMACSecret),
		ProxyBaseURL:    cfg.ProxyBaseURL,
	})

	// STS resolver (optional — constructed only if any server uses the STS strategy).
	var stsResolver *credential.STSResolver
	if needsSTS(reg) {
		ac, err := loadAWSConfig()
		if err != nil {
			return fmt.Errorf("STS strategy configured but AWS SDK failed: %w", err)
		}
		stsClient := sts.NewFromConfig(*ac)
		stsResolver = credential.NewSTSResolver(stsClient)
		slog.Info("STS credential resolver enabled")
	}

	// Credential resolver (composite: OAuth → static → STS → XAA stub).
	credResolver := credential.NewCompositeResolver(credStore, enrollment, stsResolver)

	// OIDC authenticator (Okta, Auth0, or any JWKS-compatible IdP).
	// When Auth0 is configured, override the groups claim key so the proxy
	// reads from the custom Auth0 Post-Login Action namespace claim.
	var authOpts []auth.AuthOption
	if cfg.Auth0GroupsClaim != "" {
		authOpts = append(authOpts, auth.WithGroupsClaim(cfg.Auth0GroupsClaim))
	}
	authenticator := auth.NewOktaAuthenticator(cfg.OktaIssuer, cfg.OktaAudience, authOpts...)
	authenticator.StartBackgroundRefresh(ctx)

	// CEL policy engine — fails at startup if any rule has a compile error.
	policyYAML := cfg.ConfigDir + "/policy.yaml"
	policyEngine, err := policy.NewEngine(policyYAML, cfg.Workspace, cfg.AWSRegion)
	if err != nil {
		return fmt.Errorf("loading policy from %s: %w", policyYAML, err)
	}

	// Slack approval service.
	slackSender := approval.NewSlackSender(cfg.SlackWebhookURL)
	approvalSvc := approval.NewService(slackSender)
	approvalHandler := approval.NewHandler(approvalSvc, cfg.SlackSigningSecret)

	// PostgreSQL audit logger.
	auditLogger := pgaudit.NewPostgresLogger(db, pgaudit.PostgresOptions{
		InstanceID:  cfg.InstanceID,
		Workspace:   cfg.Workspace,
		GenesisHash: genesisHash,
	})
	defer auditLogger.Close()

	// ── 5. Assemble gateway.Dependencies and create Proxy ─────────────────────
	deps := &gateway.Dependencies{
		Authenticator:      authenticator,
		PolicyEngine:       policyEngine,
		CredentialStore:    credStore,
		CredentialResolver: credResolver,
		ServerRegistry:     reg,
		AuditLogger:        auditLogger,
		ApprovalService:    approvalSvc,
		OAuthEnrollment:    enrollment,
		MetricsCollector:   metricsCollector,
	}

	p := proxy.New(deps, proxy.Options{
		ProxyBaseURL:  cfg.ProxyBaseURL,
		DemoJWTURL:    cfg.DemoJWTURL,
		Auth0Domain:   cfg.Auth0Domain,
		Auth0ClientID: cfg.Auth0ClientID,
		Auth0Audience: cfg.Auth0Audience,
	})

	// ── 6. HTTP server ─────────────────────────────────────────────────────────
	httpServer := p.NewHTTPServer(cfg.ListenAddr, approvalHandler)

	serverErr := make(chan error, 1)
	go func() {
		if cfg.TLSCertFile != "" {
			slog.Info("starting TLS server", slog.String("addr", cfg.ListenAddr))
			serverErr <- httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			slog.Warn("TLS not configured; starting plain HTTP server (development only)",
				slog.String("addr", cfg.ListenAddr))
			serverErr <- httpServer.ListenAndServe()
		}
	}()

	slog.Info("mcp-proxy ready",
		slog.String("workspace", cfg.Workspace),
		slog.String("addr", cfg.ListenAddr),
		slog.String("instance_id", cfg.InstanceID),
	)

	// ── 7. Graceful shutdown ───────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-quit:
		slog.Info("shutdown signal received", slog.String("signal", sig.String()))
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server error: %w", err)
		}
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutCancel()

	slog.Info("draining in-flight requests", slog.Duration("timeout", cfg.ShutdownTimeout))
	if err := httpServer.Shutdown(shutCtx); err != nil {
		slog.Error("graceful shutdown incomplete", slog.String("error", err.Error()))
		return fmt.Errorf("shutdown: %w", err)
	}

	slog.Info("shutdown complete")
	return nil
}

// needsSTS checks whether any registered server uses the STS auth strategy.
func needsSTS(reg gateway.ServerRegistry) bool {
	stsStrategy := gateway.AuthStrategySTS
	servers, err := reg.List(context.Background(), &gateway.ServerFilter{Strategy: &stsStrategy})
	if err != nil {
		return false
	}
	return len(servers) > 0
}

// randomHex returns n random bytes encoded as a hex string.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("mcp-proxy: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
