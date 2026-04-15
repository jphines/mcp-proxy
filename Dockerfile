FROM golang:1.23-alpine AS builder

WORKDIR /build

# Cache dependencies separately from source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o mcp-proxy \
    ./cmd/mcp-proxy

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/mcp-proxy /mcp-proxy

EXPOSE 8443

ENTRYPOINT ["/mcp-proxy"]
