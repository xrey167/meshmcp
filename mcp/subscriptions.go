package mcp

import "encoding/json"

// This implements the DRAFT MCP subscriptions/listen pattern: a long-lived
// server->client notification stream a client opens to receive list-changed
// and resource-updated notifications on one channel. It mirrors the wire model
// in protocol/subscriptions, kept local so this framework stays dependency-free.
//
// Flow: the client sends a `subscriptions/listen` request; the server registers
// the subscription, sends a `notifications/subscriptions/acknowledged` echoing
// the honored filter (with the subscription id in `_meta`), then streams the
// requested notifications (each tagged with the subscription id) until the
// stream ends — at which point the server answers the original listen request
// with a `{"resultType":"complete"}` result. The client ends it by cancelling
// the listen request (`notifications/cancelled`).
//
// The pattern is post-2025-06-18 draft, so the server serves it when a client
// uses it but does not advertise it in the stable initialize capabilities.

const (
	methodSubscriptionsListen = "subscriptions/listen"
	methodSubscriptionsAck    = "notifications/subscriptions/acknowledged"
	metaKeySubscriptionID     = "io.modelcontextprotocol/subscriptionId"
	subscriptionComplete      = "complete"

	// Caps on client-controlled allocation: a client opens subscriptions and
	// chooses how many resource URIs each carries, so both are bounded to keep
	// one connection from exhausting server memory.
	maxSubscriptions         = 256
	maxResourceSubsPerListen = 512
)

// SubscriptionFilter selects which notification types a subscription delivers.
// The server delivers only the types the client requested (it MUST NOT send
// unrequested types).
type SubscriptionFilter struct {
	ToolsListChanged      bool     `json:"toolsListChanged,omitempty"`
	PromptsListChanged    bool     `json:"promptsListChanged,omitempty"`
	ResourcesListChanged  bool     `json:"resourcesListChanged,omitempty"`
	ResourceSubscriptions []string `json:"resourceSubscriptions,omitempty"`
}

type subscription struct {
	id     json.RawMessage // the JSON-RPC id of the listen request == the subscription id
	sess   *Session
	filter SubscriptionFilter
	uris   map[string]bool // resource URIs this subscription tracks
}

// handleListen registers a subscription, acknowledges it, and holds the request
// open: the response is the terminal `complete` result sent when the stream ends.
func (s *Server) handleListen(req request, sess *Session) response {
	var p struct {
		Notifications SubscriptionFilter `json:"notifications"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return response{JSONRPC: "2.0", ID: req.ID,
				Error: &rpcError{Code: codeInvalidParams, Message: "invalid subscriptions/listen params: " + err.Error()}}
		}
	}
	if n := len(p.Notifications.ResourceSubscriptions); n > maxResourceSubsPerListen {
		return response{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: codeInvalidParams, Message: "too many resourceSubscriptions"}}
	}
	uris := make(map[string]bool, len(p.Notifications.ResourceSubscriptions))
	for _, u := range p.Notifications.ResourceSubscriptions {
		uris[u] = true
	}
	sub := &subscription{id: req.ID, sess: sess, filter: p.Notifications, uris: uris}
	idStr := string(req.ID)

	s.submu.Lock()
	if s.subs == nil {
		s.subs = map[string]*subscription{}
	}
	if _, dup := s.subs[idStr]; dup {
		s.submu.Unlock()
		return response{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: codeInvalidParams, Message: "duplicate subscription id"}}
	}
	if len(s.subs) >= maxSubscriptions {
		s.submu.Unlock()
		return response{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: codeInvalidParams, Message: "too many active subscriptions"}}
	}
	s.subs[idStr] = sub
	s.submu.Unlock()

	// The acknowledgment is the first message on the stream: it echoes the
	// honored filter and carries the subscription id in _meta.
	sess.Notify(methodSubscriptionsAck, map[string]any{
		"_meta":         map[string]any{metaKeySubscriptionID: idStr},
		"notifications": p.Notifications,
	})
	return response{skip: true} // keep the request open
}

// NotifyToolsChanged delivers notifications/tools/list_changed to every
// subscription that requested it.
func (s *Server) NotifyToolsChanged() {
	s.deliverListChanged(func(f SubscriptionFilter) bool { return f.ToolsListChanged }, "notifications/tools/list_changed")
}

// NotifyPromptsChanged delivers notifications/prompts/list_changed.
func (s *Server) NotifyPromptsChanged() {
	s.deliverListChanged(func(f SubscriptionFilter) bool { return f.PromptsListChanged }, "notifications/prompts/list_changed")
}

// NotifyResourcesChanged delivers notifications/resources/list_changed.
func (s *Server) NotifyResourcesChanged() {
	s.deliverListChanged(func(f SubscriptionFilter) bool { return f.ResourcesListChanged }, "notifications/resources/list_changed")
}

func (s *Server) deliverListChanged(want func(SubscriptionFilter) bool, method string) {
	for _, sub := range s.matchingSubs(func(sb *subscription) bool { return want(sb.filter) }) {
		sub.sess.Notify(method, map[string]any{"_meta": map[string]any{metaKeySubscriptionID: string(sub.id)}})
	}
}

// NotifyResourceUpdated delivers notifications/resources/updated for uri to
// every subscription that registered interest in it.
func (s *Server) NotifyResourceUpdated(uri string) {
	for _, sub := range s.matchingSubs(func(sb *subscription) bool { return sb.uris[uri] }) {
		sub.sess.Notify("notifications/resources/updated", map[string]any{
			"uri":   uri,
			"_meta": map[string]any{metaKeySubscriptionID: string(sub.id)},
		})
	}
}

func (s *Server) matchingSubs(pred func(*subscription) bool) []*subscription {
	s.submu.Lock()
	defer s.submu.Unlock()
	var out []*subscription
	for _, sub := range s.subs {
		if pred(sub) {
			out = append(out, sub)
		}
	}
	return out
}

// closeSubscription ends the subscription with the given id, sending the
// terminal `complete` result to its original listen request. Returns true if a
// subscription was closed.
func (s *Server) closeSubscription(idStr string) bool {
	s.submu.Lock()
	sub := s.subs[idStr]
	delete(s.subs, idStr)
	s.submu.Unlock()
	if sub == nil {
		return false
	}
	_ = sub.sess.conn.send(response{JSONRPC: "2.0", ID: sub.id,
		Result: map[string]any{"resultType": subscriptionComplete}})
	return true
}

// closeAllSubscriptions terminates every open subscription (called on
// disconnect / server shutdown).
func (s *Server) closeAllSubscriptions() {
	s.submu.Lock()
	subs := s.subs
	s.subs = nil
	s.submu.Unlock()
	for _, sub := range subs {
		_ = sub.sess.conn.send(response{JSONRPC: "2.0", ID: sub.id,
			Result: map[string]any{"resultType": subscriptionComplete}})
	}
}
