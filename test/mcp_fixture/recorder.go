// Package mcp_fixture provides an in-process MCP downstream server and call
// recorder for use in integration tests.
package mcp_fixture

import (
	"sync"
	"time"
)

// Call records a single tool invocation received by the fixture server.
type Call struct {
	// ToolName is the bare tool name (without server prefix).
	ToolName string
	// Arguments are the decoded tool call arguments. May be nil.
	Arguments map[string]any
	// ReceivedAt is when the fixture server handled the call.
	ReceivedAt time.Time
}

// Recorder accumulates tool calls for assertion in tests.
// All methods are safe for concurrent use.
type Recorder struct {
	mu    sync.Mutex
	calls []Call
}

// NewRecorder creates an empty Recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

// record appends a call. Called by each tool handler in the fixture server.
func (r *Recorder) record(toolName string, args map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, Call{
		ToolName:   toolName,
		Arguments:  args,
		ReceivedAt: time.Now().UTC(),
	})
}

// Calls returns a copy of all recorded calls in arrival order.
func (r *Recorder) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Call, len(r.calls))
	copy(out, r.calls)
	return out
}

// CallsFor returns all recorded calls for the given tool name.
func (r *Recorder) CallsFor(toolName string) []Call {
	all := r.Calls()
	var out []Call
	for _, c := range all {
		if c.ToolName == toolName {
			out = append(out, c)
		}
	}
	return out
}

// Len returns the total number of recorded calls.
func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// Reset clears all recorded calls.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = r.calls[:0]
}
