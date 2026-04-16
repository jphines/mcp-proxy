package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/registry"
)

// callDownstream connects to the configured downstream MCP server, calls the
// named tool with the arguments in tc, and returns the result.
// Credential injection is performed per HTTP request via credInjectingTransport.
func (p *Proxy) callDownstream(ctx context.Context, tc *gateway.ToolCallContext) (*mcp.CallToolResult, int, error) {
	transport := tc.ServerConfig.Transport
	switch transport.Type {
	case gateway.TransportStreamableHTTP, gateway.TransportHTTPSSE:
		// supported
	default:
		return nil, 0, fmt.Errorf("dispatch: unsupported transport %q for server %q",
			transport.Type, tc.ServerID)
	}

	httpClient := buildHTTPClient(tc.Credential, tc.Injection, transport)

	clientTransport := &mcp.StreamableClientTransport{
		Endpoint:             transport.URL,
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}

	mcpClient := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-proxy",
		Version: "1.0.0",
	}, nil)

	session, err := mcpClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("dispatch: connect to %q: %w", tc.ServerID, err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      tc.ToolName,
		Arguments: tc.Arguments,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("dispatch: tool %q on %q: %w", tc.ToolName, tc.ServerID, err)
	}

	return result, http.StatusOK, nil
}

// NewToolLister returns a registry.ToolListFunc that fetches the tool list from
// a downstream MCP server. It is passed to registry.New() during wiring in main.go.
// No per-user credential is injected; this uses only the static headers in the
// server's TransportConfig (e.g., an org-level API key already in headers).
func NewToolLister() registry.ToolListFunc {
	return func(ctx context.Context, server *gateway.ServerConfig) ([]gateway.Tool, error) {
		switch server.Transport.Type {
		case gateway.TransportStreamableHTTP, gateway.TransportHTTPSSE:
			// supported
		default:
			return nil, fmt.Errorf("tool lister: unsupported transport %q for server %q",
				server.Transport.Type, server.ID)
		}

		httpClient := buildHTTPClient(nil, nil, server.Transport)

		clientTransport := &mcp.StreamableClientTransport{
			Endpoint:             server.Transport.URL,
			HTTPClient:           httpClient,
			DisableStandaloneSSE: true,
		}

		mcpClient := mcp.NewClient(&mcp.Implementation{
			Name:    "mcp-proxy-lister",
			Version: "1.0.0",
		}, nil)

		session, err := mcpClient.Connect(ctx, clientTransport, nil)
		if err != nil {
			return nil, fmt.Errorf("tool lister: connect to %q: %w", server.ID, err)
		}
		defer session.Close()

		var tools []gateway.Tool
		for tool, err := range session.Tools(ctx, nil) {
			if err != nil {
				return nil, fmt.Errorf("tool lister: listing %q: %w", server.ID, err)
			}
			tools = append(tools, gateway.Tool{
				NamespacedName: server.ID + "::" + tool.Name,
				ServerID:       server.ID,
				OriginalName:   tool.Name,
				Description:    tool.Description,
				InputSchema:    tool.InputSchema,
				Tier:           server.DataTier,
			})
		}

		return tools, nil
	}
}

// credInjectingTransport is an http.RoundTripper that applies static headers
// from the server config and dynamic credential injection per request.
type credInjectingTransport struct {
	base      http.RoundTripper
	cred      *gateway.Credential  // may be nil (tool-list calls)
	injection *gateway.AuthInjection // may be nil
	headers   map[string]string    // static headers from TransportConfig
}

func (t *credInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	if t.cred != nil && t.injection != nil {
		injectCredential(req, t.cred, t.injection)
	}
	return t.base.RoundTrip(req)
}

// injectCredential attaches the credential value to the request using the
// configured injection method.
func injectCredential(req *http.Request, cred *gateway.Credential, inj *gateway.AuthInjection) {
	val := string(cred.Value)
	switch inj.Method {
	case gateway.InjectionHeaderBearer:
		req.Header.Set("Authorization", "Bearer "+val)
	case gateway.InjectionHeaderCustom:
		req.Header.Set(inj.Header, inj.Prefix+val)
	case gateway.InjectionQueryParam:
		q := req.URL.Query()
		q.Set(inj.QueryParam, val)
		req.URL.RawQuery = q.Encode()
	}
}

// buildHTTPClient creates an HTTP client with credential injection and a 30-second timeout.
func buildHTTPClient(cred *gateway.Credential, inj *gateway.AuthInjection, transport gateway.TransportConfig) *http.Client {
	return &http.Client{
		Transport: &credInjectingTransport{
			base:      http.DefaultTransport,
			cred:      cred,
			injection: inj,
			headers:   transport.Headers,
		},
		Timeout: 30 * time.Second,
	}
}
