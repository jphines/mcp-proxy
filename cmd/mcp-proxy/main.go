// Command mcp-proxy is the MCP governance proxy.
//
// It wires all internal components bottom-up, starts the HTTP server, and
// handles graceful shutdown on SIGTERM/SIGINT.
//
// Startup order:
//  1. Load and validate configuration from environment variables.
//  2. Connect to PostgreSQL; run migrations (warn on failure, don't abort).
//  3. Initialise AWS SDK clients (Secrets Manager, STS, CloudWatch Logs).
//  4. Construct the audit hash chain seed via PostgreSQL (or random fallback).
//  5. Build all internal components (metrics, credential store, registry, policy, …).
//  6. Assemble gateway.Dependencies and create the Proxy.
//  7. Start the HTTP server (TLS if cert/key configured, plain HTTP otherwise).
//  8. Block until SIGTERM/SIGINT; drain in-flight requests, then shut down.
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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/approval"
	"github.com/ro-eng/mcp-proxy/internal/auth"
	"github.com/ro-eng/mcp-proxy/internal/config"
	"github.com/ro-eng/mcp-proxy/internal/credential"
	credstore "github.com/ro-eng/mcp-proxy/internal/credential/store"
	"github.com/ro-eng/mcp-proxy/internal/metrics"
	"github.com/ro-eng/mcp-proxy/internal/oauth"
	"github.com/ro-eng/mcp-proxy/internal/policy"
	"github.com/ro-eng/mcp-proxy/internal/proxy"
	"github.com/ro-eng/mcp-proxy/internal/registry"
	"github.com/ro-eng/mcp-proxy/internal/store"

	cwaudit "github.com/ro-eng/mcp-proxy/internal/audit"
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
	var db *store.DB
	if db, err = store.Open(ctx, cfg.DatabaseURL); err != nil {
		// Warn and continue: proxy degrades to CloudWatch-only audit.
		slog.Warn("PostgreSQL unavailable; audit will be CloudWatch-only",
			slog.String("error", err.Error()))
		db = nil
	} else {
		defer db.Close()
	}

	// ── 3. AWS clients ────────────────────────────────────────────────────────
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	smClient := secretsmanager.NewFromConfig(awsCfg)
	stsClient := awssts.NewFromConfig(awsCfg)
	cwClient := cloudwatchlogs.NewFromConfig(awsCfg)

	// Canary check: warn if Secrets Manager is unreachable (non-fatal).
	canaryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := smClient.ListSecrets(canaryCtx, &secretsmanager.ListSecretsInput{
		MaxResults: aws.Int32(1),
	}); err != nil {
		slog.Warn("Secrets Manager canary check failed; cached credentials still work",
			slog.String("error", err.Error()))
	}

	// ── 4. Audit hash chain seed ──────────────────────────────────────────────
	genesisHash := randomHex(32)
	if db != nil {
		seedCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		defer cancel2()
		stored, err := db.UpsertChainGenesis(seedCtx, cfg.InstanceID, genesisHash)
		if err != nil {
			slog.Warn("could not persist genesis hash; using ephemeral seed",
				slog.String("error", err.Error()))
		} else {
			genesisHash = stored
		}
	}

	// ── 5. Internal components ─────────────────────────────────────────────────

	// Metrics — register once; subsequent calls would panic.
	metricsCollector := metrics.New()

	// Credential store (Secrets Manager + AES-256-GCM cache).
	credStore, err := credstore.New(smClient, cfg.CredentialCacheTTL)
	if err != nil {
		return fmt.Errorf("initialising credential store: %w", err)
	}

	// OAuth token cache (5-minute GC interval).
	tokenCache := oauth.NewTokenCache(5 * time.Minute)

	// Server registry — loaded from servers.yaml; hot-reloaded via fsnotify.
	// NewToolLister is a standalone function; no circular dependency with Proxy.
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

	// Credential resolver (composite: OAuth → static → STS → XAA stub).
	credResolver := credential.NewCompositeResolver(credStore, enrollment, stsClient)

	// Okta authenticator + background JWKS refresh.
	authenticator := auth.NewOktaAuthenticator(cfg.OktaIssuer, cfg.OktaAudience)
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

	// CloudWatch audit logger.
	logStreamName := fmt.Sprintf("%s/%s", cfg.Workspace, cfg.InstanceID)
	auditLogger := cwaudit.NewCloudWatchLogger(cwClient, cwaudit.CloudWatchOptions{
		LogGroupName:  "mcp-proxy",
		LogStreamName: logStreamName,
		InstanceID:    cfg.InstanceID,
		Workspace:     cfg.Workspace,
		GenesisHash:   genesisHash,
		DB:            db,
	})
	defer auditLogger.Close()

	// ── 6. Assemble gateway.Dependencies and create Proxy ─────────────────────
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

	p := proxy.New(deps)

	// ── 7. HTTP server ─────────────────────────────────────────────────────────
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

	// ── 8. Graceful shutdown ───────────────────────────────────────────────────
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

// randomHex returns n random bytes encoded as a hex string.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("mcp-proxy: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
