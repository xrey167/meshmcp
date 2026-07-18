package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"meshmcp/policy"
	"meshmcp/pubsub"
	"meshmcp/session"
)

// Gateway hooks turn the firewall's decisions into an observable event stream:
// every policy decision (deny / co-sign / allow) can be published onto the
// identity-native event bus and/or POSTed to a webhook. Hooks are strictly
// observability — decoupled from enforcement. The Emit path never blocks or
// fails a decision: it drops onto a buffered queue and a worker fans out, so a
// slow or dead sink cannot stall the request path (see policy.EventHook).

// HooksConfig configures gateway event hooks.
type HooksConfig struct {
	// Events selects which decision outcomes to emit: "deny", "cosign",
	// "allow". Empty defaults to deny + cosign (the notable ones).
	Events []string `yaml:"events"`
	// TopicPrefix is the bus topic namespace; the outcome is appended
	// (e.g. "gateway.deny"). Default "gateway".
	TopicPrefix string `yaml:"topic_prefix"`
	// QueueSize bounds the in-flight hook queue; events beyond it are dropped
	// (counted) rather than blocking the request path. Default 1024.
	QueueSize int                `yaml:"queue_size"`
	Bus       *HookBusConfig     `yaml:"bus"`
	Webhook   *HookWebhookConfig `yaml:"webhook"`
}

// HookBusConfig runs an embedded broker on the mesh that carries the gateway's
// decision events; mesh peers subscribe to it like any other broker.
type HookBusConfig struct {
	ListenPort int                   `yaml:"listen_port"`
	Allow      []string              `yaml:"allow"`  // subscriber connection ACL
	Policy     pubsub.RuleAuthorizer `yaml:"policy"` // per-topic subscribe authorization
	Limits     pubsub.Limits         `yaml:"limits"`
}

// HookWebhookConfig POSTs each decision event as JSON to an external URL.
// Note: a webhook to a public URL sends gateway metadata off the mesh; the URL
// is explicit and opt-in, and only the fields below (never payloads/secrets)
// are sent.
type HookWebhookConfig struct {
	URL            string `yaml:"url"`
	TimeoutSeconds int    `yaml:"timeout_seconds"` // default 5
	AuthHeader     string `yaml:"auth_header"`     // optional Authorization header value
}

// hookPayload is the JSON body of a decision event (bus payload and webhook
// body). It carries only decision metadata — never tool arguments, payloads,
// or injected secrets.
type hookPayload struct {
	Event    string `json:"event"` // the outcome: deny | cosign | allow
	Backend  string `json:"backend,omitempty"`
	Peer     string `json:"peer,omitempty"`
	PeerKey  string `json:"peer_key,omitempty"`
	Method   string `json:"method,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Rule     int    `json:"rule"`
	AuditSeq int    `json:"audit_seq"`
}

type hookMessage struct {
	topic string
	body  []byte
}

// gatewayHooks implements policy.EventHook. It is shared by every backend's
// filter and fans decision events out to the bus and/or a webhook.
type gatewayHooks struct {
	events map[string]bool
	prefix string

	broker *pubsub.Broker // optional embedded bus

	webhookURL string
	webhookHdr string
	httpc      *http.Client

	ch      chan hookMessage
	dropped uint64 // atomic

	quit      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	listeners []net.Listener
}

// newGatewayHooks builds the hook sink from config, starting the embedded bus
// (on the mesh) and/or the webhook worker. client may be nil only when no bus
// is configured (e.g. tests).
func newGatewayHooks(cfg *HooksConfig, client *embed.Client, audit *policy.AuditLog) (*gatewayHooks, error) {
	events := map[string]bool{}
	if len(cfg.Events) == 0 {
		events["deny"], events["cosign"] = true, true
	} else {
		for _, e := range cfg.Events {
			events[e] = true
		}
	}
	prefix := cfg.TopicPrefix
	if prefix == "" {
		prefix = "gateway"
	}
	qsize := cfg.QueueSize
	if qsize <= 0 {
		qsize = 1024
	}

	h := &gatewayHooks{
		events: events,
		prefix: prefix,
		ch:     make(chan hookMessage, qsize),
		quit:   make(chan struct{}),
	}

	if cfg.Bus != nil {
		if cfg.Bus.ListenPort <= 0 || cfg.Bus.ListenPort > 65535 {
			return nil, fmt.Errorf("hooks.bus.listen_port must be 1-65535")
		}
		policyCopy := cfg.Bus.Policy
		h.broker = pubsub.New(pubsub.Options{Authorizer: &policyCopy, Audit: audit, Limits: cfg.Bus.Limits})
		ln, err := serveBrokerOn(client, h.broker, cfg.Bus.ListenPort, cfg.Bus.Allow)
		if err != nil {
			return nil, fmt.Errorf("hooks bus: %w", err)
		}
		h.listeners = append(h.listeners, ln)
	}
	if cfg.Webhook != nil && cfg.Webhook.URL != "" {
		to := time.Duration(cfg.Webhook.TimeoutSeconds) * time.Second
		if to <= 0 {
			to = 5 * time.Second
		}
		h.webhookURL = cfg.Webhook.URL
		h.webhookHdr = cfg.Webhook.AuthHeader
		h.httpc = &http.Client{
			Timeout: to,
			// Do not follow redirects: a redirect must not cause the decision
			// payload (which may carry an Authorization header) to be re-sent to
			// a different host than the operator configured.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}

	h.wg.Add(1)
	go h.worker()
	return h, nil
}

// Emit implements policy.EventHook. It never blocks: a full queue drops the
// event (counted) so the enforcement path is never delayed by a slow sink.
func (h *gatewayHooks) Emit(rec policy.AuditRecord) {
	if !h.events[rec.Decision] {
		return
	}
	body, err := json.Marshal(hookPayload{
		Event:    rec.Decision,
		Backend:  rec.Backend,
		Peer:     rec.Peer,
		PeerKey:  rec.PeerKey,
		Method:   rec.Method,
		Tool:     rec.Tool,
		Reason:   rec.Reason,
		Rule:     rec.Rule,
		AuditSeq: rec.Seq,
	})
	if err != nil {
		return
	}
	select {
	case h.ch <- hookMessage{topic: h.prefix + "." + rec.Decision, body: body}:
	default:
		atomic.AddUint64(&h.dropped, 1)
	}
}

// Dropped reports how many hook events were dropped due to a full queue.
func (h *gatewayHooks) Dropped() uint64 { return atomic.LoadUint64(&h.dropped) }

func (h *gatewayHooks) worker() {
	defer h.wg.Done()
	for {
		select {
		case m := <-h.ch:
			if h.broker != nil {
				_, _ = h.broker.EmitInternal("gateway", m.topic, json.RawMessage(m.body), nil)
			}
			if h.webhookURL != "" {
				h.postWebhook(m)
			}
		case <-h.quit:
			return
		}
	}
}

func (h *gatewayHooks) postWebhook(m hookMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), h.httpc.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.webhookURL, bytes.NewReader(m.body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Meshmcp-Topic", m.topic)
	if h.webhookHdr != "" {
		req.Header.Set("Authorization", h.webhookHdr)
	}
	resp, err := h.httpc.Do(req)
	if err != nil {
		return // best-effort observability; never surfaces to the request path
	}
	// Drain (bounded) and close so the connection can be reused.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
}

// Close stops the worker and the embedded bus, draining outstanding events
// best-effort.
func (h *gatewayHooks) Close() {
	h.closeOnce.Do(func() {
		for _, ln := range h.listeners {
			ln.Close()
		}
		close(h.quit)
		h.wg.Wait()
		if h.broker != nil {
			h.broker.Close()
		}
	})
}

// serveBrokerOn listens on a mesh port and serves a pub/sub broker to admitted
// peers. It returns the listener (the caller closes it to stop). Shared by the
// standalone `pubsub` daemon and the gateway hook bus.
func serveBrokerOn(client *embed.Client, broker *pubsub.Broker, port int, allow []string) (net.Listener, error) {
	ln, err := client.ListenTCP(fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("listen on mesh port %d: %w", port, err)
	}
	checker := newACL(allow)
	srv := session.NewServer(func(meta session.Meta) (session.Backend, error) {
		return newBrokerBackend(broker, meta, nil), nil
	}, 2*time.Minute, nil)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
			if pubKey == "" || !checker.allows(pubKey, fqdn) {
				conn.Close()
				continue
			}
			go srv.Handle(conn, session.Meta{PeerFQDN: fqdn, PeerAddr: conn.RemoteAddr().String(), PeerKey: pubKey})
		}
	}()
	return ln, nil
}
