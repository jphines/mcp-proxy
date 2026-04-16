BINARY     := mcp-proxy
MODULE     := github.com/jphines/mcp-proxy
BUILD_DIR  := bin
LDFLAGS    := -trimpath -ldflags="-s -w"
GOFLAGS    := CGO_ENABLED=0

.PHONY: all build test lint integration-test policy-test generate docker-build clean demo demo-down demo-logs login mcp-setup

all: build

build:
	$(GOFLAGS) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/mcp-proxy

test:
	go test -race -coverprofile=coverage.out -covermode=atomic ./internal/...
	@go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

generate:
	go generate ./...

policy-test:
	go test -v -run TestPolicyFixtures ./internal/policy/...

integration-test:
	go test -v -timeout 10m ./test/integration/...

docker-build:
	docker build -t $(BINARY):dev .

check-coverage: test
	@go run ./scripts/check-coverage -- coverage.out 80

clean:
	rm -rf $(BUILD_DIR) coverage.out

# Run the proxy locally (requires env vars)
run:
	go run ./cmd/mcp-proxy

# Validate policy YAML syntax only (no infra required)
validate-policy:
	go run ./cmd/policy-test -- --validate-only --policy config/policy.yaml

.PHONY: tidy
tidy:
	go mod tidy

# ── Demo environment ──────────────────────────────────────────────────────────

# Load .env.demo automatically if it exists (contains GOOGLE_CLIENT_ID / SECRET).
# Users can also pass vars inline: GOOGLE_CLIENT_ID=x GOOGLE_CLIENT_SECRET=y make demo
DEMO_ENV_FILE := .env.demo
COMPOSE_DEMO  := docker compose -f docker-compose.demo.yml $(if $(wildcard $(DEMO_ENV_FILE)),--env-file $(DEMO_ENV_FILE),)

## demo: Build and start the full docker-compose demo environment.
##       Dashboard → http://localhost:9090
##       Proxy MCP → http://localhost:8080/mcp
##       JWT issuer → http://localhost:9999/token
demo:
	$(COMPOSE_DEMO) up --build -d
	@echo ""
	@echo "  ✓  Demo started"
	@echo ""
	@echo "  Dashboard  →  http://localhost:9090"
	@echo "  Proxy MCP  →  http://localhost:8080/mcp"
	@echo "  JWT issuer →  http://localhost:9999/token"
	@echo ""
	@echo "  Get a token:"
	@echo "    curl 'http://localhost:9999/token?user=alice@example.com&groups=platform-eng,everyone'"
	@echo ""
	@if [ -f $(DEMO_ENV_FILE) ]; then \
		echo "  Google OAuth enroll (after proxy is ready):"; \
		echo "    http://localhost:8080/oauth/enroll/google?token=<YOUR_JWT>"; \
		echo ""; \
	fi
	@echo "  See DEMO.md for the full walkthrough."

## demo-logs: Tail logs from all demo services.
demo-logs:
	$(COMPOSE_DEMO) logs -f

## demo-down: Stop and remove demo containers and volumes.
demo-down:
	$(COMPOSE_DEMO) down -v

## login: Authenticate with the proxy via browser OAuth and register it in Claude Code.
##        Auto-detects the IdP mode from .env.demo (Auth0 or built-in demo AS).
##        Re-run any time your token expires or you bring up a fresh demo.
##
##        Demo-jwt mode (default): browser opens the proxy's own login form.
##        Auth0 mode (AUTH0_CLIENT_ID in .env.demo): browser opens Auth0 Universal Login.

# Resolve the OAuth client_id:
#   1. AUTH0_CLIENT_ID from environment
#   2. AUTH0_CLIENT_ID from .env.demo file
#   3. "mcp-proxy" (built-in demo AS default)
_LOGIN_CLIENT := $(or \
	$(AUTH0_CLIENT_ID), \
	$(shell grep -s '^AUTH0_CLIENT_ID=' $(DEMO_ENV_FILE) 2>/dev/null | cut -d= -f2), \
	mcp-proxy)

login:
	@echo "Registering mcp-proxy-demo in Claude Code (client: $(_LOGIN_CLIENT))..."
	@claude mcp remove --scope user mcp-proxy-demo 2>/dev/null || true
	claude mcp add --transport http \
		--client-id $(_LOGIN_CLIENT) \
		--scope user \
		mcp-proxy-demo \
		http://localhost:8080/mcp
	@echo ""
	@echo "  Done. Your browser should open to sign in."
	@echo "  Once authenticated, 'mcp-proxy-demo' is available in all Claude Code sessions."
	@echo ""
	@echo "  Available tool groups (server__tool naming):"
	@echo "    demo__*     — 6 demo tools (echo, add, greet, slow, file_hash, weather)"
	@echo "    google__*   — 7 Google tools (calendar + docs) — enroll first:"
	@echo "      http://localhost:8080/oauth/enroll/google"

## mcp-setup: (legacy) Fetch a 7-day JWT and register the proxy. Use 'make login' instead.
mcp-setup:
	@echo "Fetching 7-day demo JWT..."
	$(eval TOKEN := $(shell curl -sf 'http://localhost:9999/token?user=justin.p.hines@gmail.com&groups=platform-eng,everyone&ttl=168h' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'))
	@if [ -z "$(TOKEN)" ]; then echo "ERROR: demo-jwt is not running. Run 'make demo' first."; exit 1; fi
	@echo "Registering mcp-proxy-demo in Claude Code (user scope)..."
	@claude mcp remove --scope user mcp-proxy-demo 2>/dev/null || true
	claude mcp add --transport http \
		--header "Authorization: Bearer $(TOKEN)" \
		--scope user \
		mcp-proxy-demo \
		http://localhost:8080/mcp
	@echo ""
	@echo "  Done. Token expires in 7 days. Re-run 'make mcp-setup' to refresh."
