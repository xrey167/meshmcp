package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

type httpHeaderKey struct{}

// WithHTTPHeaders attaches the request headers to a context so handlers can
// read gateway-stamped values (e.g. X-Meshmcp-Peer).
func WithHTTPHeaders(ctx context.Context, h http.Header) context.Context {
	return context.WithValue(ctx, httpHeaderKey{}, h)
}

// HTTPHeadersFrom returns the request headers attached to ctx, or nil.
func HTTPHeadersFrom(ctx context.Context) http.Header {
	h, _ := ctx.Value(httpHeaderKey{}).(http.Header)
	return h
}

// HTTPHandler serves the MCP server over a minimal Streamable-HTTP-style
// transport: each POST carries one JSON-RPC message and receives one JSON
// response. Notifications (no id) are accepted with 202 and no body. This is
// the subset of Streamable HTTP that meshmcp's http backend proxies.
func (s *Server) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req request
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, response{JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &rpcError{Code: codeParse, Message: "parse error"}})
			return
		}
		if len(req.ID) == 0 {
			s.handleNotification(req)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		// Notifications are no-ops over plain request/response HTTP.
		sess := &Session{}
		ctx := WithHTTPHeaders(WithSession(r.Context(), sess), r.Header)
		writeJSON(w, s.dispatch(ctx, req, sess))
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(b)
}
