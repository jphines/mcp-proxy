BINARY     := mcp-proxy
MODULE     := github.com/ro-eng/mcp-proxy
BUILD_DIR  := bin
LDFLAGS    := -trimpath -ldflags="-s -w"
GOFLAGS    := CGO_ENABLED=0

.PHONY: all build test lint integration-test policy-test generate docker-build clean

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
