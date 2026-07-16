package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ToolHandler is a tool's execution step — the signature of Tool.Handler.
type ToolHandler func(ctx context.Context, args json.RawMessage) (ToolResult, error)

// ToolMiddleware wraps a ToolHandler. The first middleware registered is the
// outermost wrapper; the same compiled chain runs for synchronous and
// asynchronous (task) calls.
type ToolMiddleware func(next ToolHandler) ToolHandler

// ToolCallInfo is an immutable snapshot of the in-flight call, retrievable by
// middleware and handlers via ToolCallFrom.
type ToolCallInfo struct {
	Tool      string
	RequestID json.RawMessage
	Meta      json.RawMessage // the call's params._meta, if any
}

type toolCallKey struct{}

func withToolCall(ctx context.Context, info ToolCallInfo) context.Context {
	return context.WithValue(ctx, toolCallKey{}, info)
}

// ToolCallFrom returns the current call's snapshot, if any.
func ToolCallFrom(ctx context.Context) (ToolCallInfo, bool) {
	info, ok := ctx.Value(toolCallKey{}).(ToolCallInfo)
	return info, ok
}

// Use appends global middleware applied to every tool. Registration order is
// deterministic: the first call is the outermost wrapper.
func (s *Server) Use(mw ...ToolMiddleware) {
	s.mu.Lock()
	s.globalMW = append(s.globalMW, mw...)
	s.mu.Unlock()
}

// UseTool appends middleware applied only to the named tool, inside the global
// chain.
func (s *Server) UseTool(tool string, mw ...ToolMiddleware) {
	s.mu.Lock()
	if s.toolMW == nil {
		s.toolMW = map[string][]ToolMiddleware{}
	}
	s.toolMW[tool] = append(s.toolMW[tool], mw...)
	s.mu.Unlock()
}

// effectiveHandler composes global then per-tool middleware around the tool's
// handler. mws[0] (the first global registered) ends up outermost.
func (s *Server) effectiveHandler(t Tool) ToolHandler {
	s.mu.RLock()
	mws := make([]ToolMiddleware, 0, len(s.globalMW)+len(s.toolMW[t.Name]))
	mws = append(mws, s.globalMW...)
	mws = append(mws, s.toolMW[t.Name]...)
	s.mu.RUnlock()

	h := ToolHandler(t.Handler)
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// rawMeta extracts params._meta as raw JSON (nil if absent).
func rawMeta(params json.RawMessage) json.RawMessage {
	var p struct {
		Meta json.RawMessage `json:"_meta"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Meta
}

// --- built-in middleware ---

// RecoverPanics turns a handler panic into an error result, redacting the
// recovered value so a panic message can't leak into the model or logs.
func RecoverPanics() ToolMiddleware {
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args json.RawMessage) (res ToolResult, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("tool panicked (recovered)")
				}
			}()
			return next(ctx, args)
		}
	}
}

// Timeout bounds a call with a derived context. It is cooperative — the handler
// must honor ctx — and spawns no helper goroutine, so it cannot leak one.
func Timeout(d time.Duration) ToolMiddleware {
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args json.RawMessage) (ToolResult, error) {
			ctx, cancel := context.WithTimeout(ctx, d)
			defer cancel()
			return next(ctx, args)
		}
	}
}

// LimitConcurrency caps how many calls run this middleware's inner handler at
// once, waiting (context-aware) for a permit and always releasing it.
func LimitConcurrency(n int) ToolMiddleware {
	if n < 1 {
		n = 1
	}
	sem := make(chan struct{}, n)
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args json.RawMessage) (ToolResult, error) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return ToolResult{}, ctx.Err()
			}
			return next(ctx, args)
		}
	}
}
