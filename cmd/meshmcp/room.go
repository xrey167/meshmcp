package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/mcpclient"
	"github.com/xrey167/meshmcp/policy"
)

// randToken returns a 32-byte hex bearer token for the control room's actuator
// endpoints.
func randToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// requireToken gates an actuator handler behind the startup bearer token,
// accepted in the X-Room-Token header or a ?token= query parameter. The compare
// is constant-time. This holds even on a loopback bind, so a co-resident
// process cannot drive the room without the token the operator was handed.
func (rs *roomServer) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Room-Token")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if rs.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(rs.token)) != 1 {
			http.Error(w, "forbidden: missing or invalid room token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// roomServer backs the interactive Control Room. It reads the audit log for the
// live view and — when joined to the mesh — dials backends to drive them, so an
// operator can list and call tools and run a governed terminal, all as an
// ordinary mesh client (every action goes through the gateway's policy + audit).
type roomServer struct {
	auditPath  string
	recent     int
	title      string
	mesh       *embed.Client // nil = view-only (no mesh creds)
	localShell bool
	token      string // bearer required by the actuator endpoints (call/shell)

	// control is the SOURCE gateway's mesh control address (from --control). When
	// set (and the room has mesh credentials) the room can list live sessions and
	// trigger a live-session MOVE by proxying to that gateway's /v1/sessions and
	// /v1/move. The room reaches the gateway as an ordinary mesh client whose OWN
	// WireGuard identity must be on the gateway's control.allow — the room holds
	// no special power; an un-allowed room is refused (403) by the gateway.
	control   string
	controlHC *http.Client // mesh-dialing HTTP client to `control`; nil when unwired

	mu   sync.Mutex
	pool map[string]*mcpclient.Client // target -> reused MCP client over the mesh

	// Multiplayer presence (S60): who else has this room open. Sessions
	// heartbeat via POST /api/presence (token-gated, piggybacked on the live
	// poll); entries expire after presenceTTL and the roster rides back on the
	// /api/room feed as `viewers`.
	vmu     sync.Mutex
	viewers map[string]*roomViewer // viewer id -> name + last heartbeat
}

// roomViewer is one live browser session in the room.
type roomViewer struct {
	name     string
	lastSeen time.Time
}

// viewerInfo is the wire form of one roster entry on the /api/room response.
type viewerInfo struct {
	Name string `json:"name"`
	Idle int    `json:"idle"` // seconds since the last heartbeat
}

// presenceTTL is how long a viewer stays on the roster without a heartbeat;
// the page heartbeats every poll (1.5s), so 15s tolerates blips, not tabs
// that were closed.
const presenceTTL = 15 * time.Second

// maxViewers bounds the roster so a heartbeat flood cannot grow it unbounded.
const maxViewers = 64

// handlePresence upserts a viewer heartbeat. Token-gated: only sessions
// holding the room token appear on the roster, so the roster itself never
// leaks to a blind local caller.
func (rs *roomServer) handlePresence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct{ ID, Name string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || strings.TrimSpace(body.ID) == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "operator"
	}
	if len(name) > 32 {
		name = name[:32]
	}
	now := time.Now()
	rs.vmu.Lock()
	if rs.viewers == nil {
		rs.viewers = map[string]*roomViewer{}
	}
	rs.sweepViewersLocked(now)
	if _, ok := rs.viewers[body.ID]; !ok && len(rs.viewers) >= maxViewers {
		rs.vmu.Unlock()
		http.Error(w, "viewer roster is full", http.StatusTooManyRequests)
		return
	}
	rs.viewers[body.ID] = &roomViewer{name: name, lastSeen: now}
	rs.vmu.Unlock()
	writeJSONResp(w, http.StatusOK, map[string]any{"ok": true})
}

// sweepViewersLocked drops entries whose heartbeat is older than presenceTTL.
// Callers hold vmu.
func (rs *roomServer) sweepViewersLocked(now time.Time) {
	for id, v := range rs.viewers {
		if now.Sub(v.lastSeen) > presenceTTL {
			delete(rs.viewers, id)
		}
	}
}

// viewerRoster returns the live viewers, expired entries swept, stable order.
func (rs *roomServer) viewerRoster(now time.Time) []viewerInfo {
	rs.vmu.Lock()
	defer rs.vmu.Unlock()
	rs.sweepViewersLocked(now)
	out := make([]viewerInfo, 0, len(rs.viewers))
	for _, v := range rs.viewers {
		out = append(out, viewerInfo{Name: v.name, Idle: int(now.Sub(v.lastSeen) / time.Second)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Idle < out[j].Idle
	})
	return out
}

// roomFeed is the /api/room response: the audit rollup plus the live roster.
type roomFeed struct {
	policy.Summary
	Viewers []viewerInfo `json:"viewers"`
}

// cmdRoom serves the interactive Control Room on a local address. With mesh
// credentials it can also drive backends (tool console + governed terminal);
// with --local-shell it additionally exposes a raw shell on this host (OFF by
// default, loopback-only — an unguarded shell must never be reachable remotely).
func cmdRoom(args []string) error {
	fs := flag.NewFlagSet("room", flag.ExitOnError)
	o := meshFlags(fs)
	auditPath := fs.String("audit", "", "audit log (JSONL) the gateway writes (required)")
	addr := fs.String("addr", "127.0.0.1:9900", "local listen address for the control room")
	recent := fs.Int("recent", 120, "live-feed events to keep")
	title := fs.String("title", "meshmcp control room", "page title / header")
	localShell := fs.Bool("local-shell", false, "expose a RAW local shell on this host (loopback bind only; a firewall bypass)")
	control := fs.String("control", "", "source gateway mesh control address (ip:port) — enables the live Sessions panel and drag-to-handoff; the room's own WireGuard identity must be on that gateway's control.allow")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("meshmcp room: --audit <file> is required")
	}
	if *localShell && !loopbackAddr(*addr) {
		return fmt.Errorf("--local-shell requires a loopback --addr (got %q); a raw shell must not be reachable remotely", *addr)
	}

	tok, err := randToken()
	if err != nil {
		return fmt.Errorf("generate room token: %w", err)
	}
	rs := &roomServer{auditPath: *auditPath, recent: *recent, title: *title,
		localShell: *localShell, token: tok, control: strings.TrimSpace(*control),
		pool: map[string]*mcpclient.Client{}}

	// Join the mesh only if credentials are available; otherwise stay view-only.
	if o.SetupKey != "" {
		o.BlockInbound = true
		client, err := startMesh(o, os.Stderr)
		if err != nil {
			return err
		}
		defer stopMesh(client)
		rs.mesh = client
		if st, err := client.Status(); err == nil {
			log.Printf("control room joined mesh as %s", st.LocalPeerState.FQDN)
		}
		// The live Sessions panel + drag-to-handoff proxy to the source gateway's
		// control endpoint over the mesh, under the room's own WireGuard identity.
		if rs.control != "" {
			rs.controlHC = &http.Client{
				Timeout: moveTriggerTimeout + 15*time.Second, // a move warms a backend on the destination
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return rs.mesh.Dial(ctx, "tcp", rs.control)
					},
				},
			}
			log.Printf("control room wired to gateway control %s (live sessions + drag-to-handoff; the room's WireGuard key must be on that gateway's control.allow)", rs.control)
		}
	} else {
		log.Printf("control room: no mesh credentials — live view only (set NB_SETUP_KEY to drive backends)")
		if rs.control != "" {
			log.Printf("control room: --control %s set but no mesh credentials — the Sessions panel needs NB_SETUP_KEY to reach the gateway", rs.control)
		}
	}
	if *localShell {
		log.Printf("WARNING: --local-shell is ON. Anyone who can reach http://%s can run commands on THIS host.", *addr)
	}

	mux := http.NewServeMux()
	registerAgentOSAssets(mux)
	mux.HandleFunc("/api/room", rs.handleRoom)
	mux.HandleFunc("/api/caps", rs.handleCaps)
	// The actuator endpoints (drive a backend, list its tools, run a
	// command/shell) require the startup token, so even a local process that
	// slips past the loopback and rebinding guards cannot act without the token
	// the operator was handed. /api/ls is included: it makes an outbound mesh
	// dial under the room's identity, so an unauthenticated caller could
	// enumerate any reachable backend through the room (a confused deputy).
	// Presence heartbeats are token-gated too: only sessions the operator
	// opened with the token appear on the multiplayer roster.
	mux.HandleFunc("/api/presence", rs.requireToken(rs.handlePresence))
	mux.HandleFunc("/api/ls", rs.requireToken(rs.handleLs))
	mux.HandleFunc("/api/call", rs.requireToken(rs.handleCall))
	mux.HandleFunc("/api/shell", rs.requireToken(rs.handleShell))
	// Live sessions + drag-to-handoff proxy to the source gateway's control
	// endpoint. Token-gated (browser->room) exactly like the other actuators; the
	// room->gateway hop re-gates on the gateway's operator ACL, so an
	// unauthenticated viewer cannot fire a move even past the room token.
	mux.HandleFunc("/api/sessions", rs.requireToken(rs.handleSessions))
	mux.HandleFunc("/api/move", rs.requireToken(rs.handleMove))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		// Bake the token into the page only when the caller already presents it
		// (in the URL the operator opened) — so the server never hands the
		// actuator token to a blind GET /.
		injected := ""
		if q := r.URL.Query().Get("token"); q != "" &&
			subtle.ConstantTimeCompare([]byte(q), []byte(rs.token)) == 1 {
			b, _ := json.Marshal(rs.token)
			injected = "window.__ROOM_TOKEN=" + string(b) + ";"
		}
		page := strings.Replace(roomHTML, "/*__ROOM_TOKEN__*/", injected, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	fmt.Fprintf(os.Stderr, "meshmcp control room on http://%s (audit: %s)\n", *addr, *auditPath)
	fmt.Fprintf(os.Stderr, "open the room with this token-bearing URL (keep it secret):\n  http://%s/?token=%s\n", *addr, tok)
	return serveGracefully(newLocalHTTPServer(*addr, guardLoopback(mux, *addr)), nil)
}

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return net.ParseIP(host).IsLoopback()
}

// guardLoopback wraps the room so its command endpoints can't be driven by a
// web page the operator happens to visit. It blocks DNS rebinding (the Host
// header must be a loopback name on the bind port, or the exact bind address —
// an attacker's rebound domain won't match) and CSRF (any Origin must be
// same-origin). Both are set by the browser and cannot be forged by a
// cross-site page, so /api/shell and /api/call are unreachable except from the
// room's own page.
func guardLoopback(next http.Handler, addr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, addr) {
			http.Error(w, "forbidden host (DNS-rebinding guard)", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !originAllowed(o, addr) {
			http.Error(w, "forbidden origin (CSRF guard)", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hostAllowed(reqHost, addr string) bool {
	if reqHost == addr {
		return true
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h, p, err := net.SplitHostPort(reqHost)
	if err != nil {
		h, p = reqHost, ""
	}
	if p != "" && p != port {
		return false
	}
	return h == "localhost" || (net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback())
}

func originAllowed(origin, addr string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return hostAllowed(u.Host, addr)
}

// maxTargets bounds the client pool so a flood of distinct targets can't
// exhaust connections/memory.
const maxTargets = 64

func (rs *roomServer) handleRoom(w http.ResponseWriter, r *http.Request) {
	viewers := rs.viewerRoster(time.Now())
	f, err := os.Open(rs.auditPath)
	if err != nil {
		writeJSONResp(w, http.StatusOK, roomFeed{Viewers: viewers}) // no log yet is normal
		return
	}
	defer f.Close()
	sum, err := policy.Analyze(f, rs.recent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResp(w, http.StatusOK, roomFeed{Summary: sum, Viewers: viewers})
}

func (rs *roomServer) handleCaps(w http.ResponseWriter, r *http.Request) {
	writeJSONResp(w, http.StatusOK, map[string]any{
		"mesh":        rs.mesh != nil,
		"local_shell": rs.localShell,
		"title":       rs.title,
		// control advertises whether the live Sessions panel + drag-to-handoff are
		// wired (--control set AND mesh credentials present). The SPA hides the panel
		// entirely when false, so an unwired room is byte-for-byte the read-only view.
		"control": rs.control != "" && rs.controlHC != nil,
	})
}

// proxyControl forwards one request to the wired source gateway's control
// endpoint over the mesh and streams its status + body straight back. Passing the
// gateway's verdict through UNCHANGED is load-bearing: the browser sees the real
// server-side outcome (moved / refused / unknown), never a status the room
// synthesized. Fails closed with a clear message when the room is not wired.
func (rs *roomServer) proxyControl(w http.ResponseWriter, method, path string, body []byte) {
	if rs.control == "" {
		http.Error(w, "room not wired to a control gateway (start the room with --control <gateway-mesh-addr>)", http.StatusConflict)
		return
	}
	if rs.controlHC == nil {
		http.Error(w, "room has no mesh credentials to reach the control gateway (set NB_SETUP_KEY)", http.StatusConflict)
		return
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://air-control"+path, rdr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := rs.controlHC.Do(req)
	if err != nil {
		http.Error(w, "control gateway unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(b)
}

// handleSessions proxies GET /v1/sessions from the wired source gateway, so the
// room's Sessions panel shows the gateway's LIVE sessions (not the audit rollup).
func (rs *roomServer) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	rs.proxyControl(w, http.MethodGet, "/v1/sessions", nil)
}

// handleMove proxies POST /v1/move: the drag-to-handoff actuator. The browser
// supplies {backend,id,dest_key,dest_addr}; the room forwards it to the gateway,
// which re-gates on its operator ACL and runs the tested move engine. The
// gateway's status/verdict passes through unchanged (delivered/refused/failed).
func (rs *roomServer) handleMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Backend  string `json:"backend"`
		ID       string `json:"id"`
		DestKey  string `json:"dest_key"`
		DestAddr string `json:"dest_addr"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil ||
		body.Backend == "" || body.ID == "" || body.DestKey == "" || body.DestAddr == "" {
		http.Error(w, "backend, id, dest_key and dest_addr are required", http.StatusBadRequest)
		return
	}
	out, _ := json.Marshal(body)
	rs.proxyControl(w, http.MethodPost, "/v1/move", out)
}

// client returns a reused MCP client to target over the mesh, dialing lazily.
func (rs *roomServer) client(target string) (*mcpclient.Client, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if c, ok := rs.pool[target]; ok {
		return c, nil
	}
	if rs.mesh == nil {
		return nil, fmt.Errorf("not connected to the mesh — restart the room with NB_SETUP_KEY to drive backends")
	}
	if len(rs.pool) >= maxTargets {
		return nil, fmt.Errorf("too many open targets (%d) — restart the room", maxTargets)
	}
	conn, err := rs.mesh.Dial(context.Background(), "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial %s over mesh: %w", target, err)
	}
	c := mcpclient.New(conn, nil)
	if _, err := c.Initialize(context.Background(), "meshmcp-room"); err != nil {
		c.Close()
		return nil, fmt.Errorf("initialize %s: %w", target, err)
	}
	rs.pool[target] = c
	return c, nil
}

func (rs *roomServer) drop(target string) {
	rs.mu.Lock()
	if c, ok := rs.pool[target]; ok {
		c.Close()
		delete(rs.pool, target)
	}
	rs.mu.Unlock()
}

func (rs *roomServer) handleLs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct{ Target string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil || body.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	c, err := rs.client(body.Target)
	if err != nil {
		writeJSONResp(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	ctx := r.Context()
	out := map[string]any{}
	if tools, err := c.ListTools(ctx); err == nil {
		out["tools"] = tools
	} else {
		rs.drop(body.Target)
		writeJSONResp(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	if res, err := c.ListResources(ctx); err == nil {
		out["resources"] = res
	}
	if pr, err := c.ListPrompts(ctx); err == nil {
		out["prompts"] = pr
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (rs *roomServer) handleCall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Target string          `json:"target"`
		Tool   string          `json:"tool"`
		Args   json.RawMessage `json:"args"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil || body.Target == "" || body.Tool == "" {
		http.Error(w, "target and tool are required", http.StatusBadRequest)
		return
	}
	c, err := rs.client(body.Target)
	if err != nil {
		writeJSONResp(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	var args any = map[string]any{}
	if len(body.Args) > 0 {
		args = body.Args
	}
	res, err := c.CallTool(r.Context(), body.Tool, args, false)
	if err != nil {
		// A transport error means the cached client is stale; drop it.
		if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "EOF") {
			rs.drop(body.Target)
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"result": res})
}

func (rs *roomServer) handleShell(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !rs.localShell {
		http.Error(w, "local shell is disabled (start the room with --local-shell)", http.StatusForbidden)
		return
	}
	var body struct{ Cmd string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil || strings.TrimSpace(body.Cmd) == "" {
		http.Error(w, "cmd is required", http.StatusBadRequest)
		return
	}
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/c", body.Cmd)
	} else {
		c = exec.Command("sh", "-c", body.Cmd)
	}
	out, err := c.CombinedOutput()
	resp := map[string]any{"output": string(out)}
	if err != nil {
		resp["exit"] = err.Error()
	}
	writeJSONResp(w, http.StatusOK, resp)
}

const roomHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>meshmcp — control room</title>
<style>
:root{--bg:#0a0d13;--panel:#12161f;--panel2:#171c27;--line:#232c3b;--fg:#dce4f2;--dim:#8a97ad;--faint:#67728a;
--accent:#5b8cff;--ok:#37d67a;--deny:#ff5c5c;--warn:#ffb020;--label:#c07bff;--term:#0c1018}
@media(prefers-color-scheme:light){:root{--bg:#eef1f7;--panel:#fff;--panel2:#e7ecf5;--line:#d6ddea;--fg:#101725;
--dim:#586179;--faint:#8a93a8;--accent:#2f5fe0;--ok:#128a45;--deny:#cf3636;--warn:#a9700a;--label:#8536e6;--term:#0c1018}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,"SF Mono",Menlo,Consolas,monospace}
header{display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid var(--line);flex-wrap:wrap}
h1{font-size:15px;margin:0;display:flex;align-items:center;gap:9px}
h1 .dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 22%,transparent);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
.chain{padding:5px 11px;border-radius:6px;font-size:12px;font-weight:600}
.chain.ok{color:var(--ok);background:color-mix(in srgb,var(--ok) 12%,transparent);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent)}
.chain.bad{color:var(--deny);background:color-mix(in srgb,var(--deny) 12%,transparent);border:1px solid color-mix(in srgb,var(--deny) 35%,transparent)}
.viewers{display:flex;align-items:center;gap:4px}
.viewers .vav{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:10px;font-weight:700;color:#fff;border:1px solid var(--line)}
.viewers .vav.idle{opacity:.45}
.viewers .vcount{font-size:11px;color:var(--faint);margin-left:3px}
.spacer{margin-left:auto}.caps{font-size:11px;color:var(--faint);display:flex;gap:10px}
.caps b{color:var(--fg)}.caps .on{color:var(--ok)}.caps .off{color:var(--faint)}
.kpis{display:flex;gap:22px}.kpi{display:flex;flex-direction:column;align-items:flex-end}
.kpi b{font-size:22px;font-variant-numeric:tabular-nums}.kpi span{font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.1em}
.kpi.a b{color:var(--ok)}.kpi.d b{color:var(--deny)}.kpi.c b{color:var(--warn)}
main{display:grid;grid-template-columns:1.5fr 1fr;gap:14px;padding:16px 20px}
@media(max-width:900px){main{grid-template-columns:1fr}}
.col{display:flex;flex-direction:column;gap:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card h2{font-size:11px;text-transform:uppercase;letter-spacing:.13em;color:var(--dim);margin:0 0 12px;display:flex;justify-content:space-between}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.tile{width:100%;color:var(--fg);font:inherit;text-align:left;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px 12px;cursor:pointer}
.tile:hover{border-color:var(--accent)}.tile .n{font-weight:600;font-size:13px}
.tile .meta{color:var(--faint);font-size:11px;margin-top:2px}
.tile .bar{height:5px;border-radius:3px;background:var(--line);overflow:hidden;margin-top:9px;display:flex}
.tile .bar i{display:block;height:100%}.tile .bar .ia{background:var(--ok)}.tile .bar .id{background:var(--deny)}.tile .bar .ic{background:var(--warn)}
.idlist{display:flex;flex-direction:column;gap:8px}
.id{display:flex;align-items:center;gap:10px;padding:8px 10px;background:var(--panel2);border:1px solid var(--line);border-radius:9px}
.id .av{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;font-size:12px;font-weight:700;color:#fff;flex:none}
.id .info{flex:1;min-width:0}.id .nm{font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.id .sub{color:var(--faint);font-size:11px}.id .cnt{text-align:right;font-size:11px;color:var(--dim)}.id .cnt b{color:var(--fg);font-size:15px;display:block}
.feed{max-height:34vh;overflow-y:auto}
.ev{display:grid;grid-template-columns:56px 1fr auto;gap:10px;padding:7px 4px;border-top:1px solid var(--line);align-items:center;font-size:12.5px}
.ev:first-child{border-top:0}.ev .t{color:var(--faint);font-size:11px}.ev .who{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ev .who .to{color:var(--accent)}.ev .who .be{color:var(--faint);font-size:11px}.ev .who .rs{color:var(--faint);font-size:11px}
.pill{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:20px;text-transform:uppercase}
.pill.allow{color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent)}
.pill.deny{color:var(--deny);background:color-mix(in srgb,var(--deny) 14%,transparent)}
.pill.cosign{color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,transparent)}
.empty{color:var(--faint);padding:16px;text-align:center}
/* live-session move (drag-to-handoff) */
.srow{cursor:grab}.srow:active{cursor:grabbing}.srow.dragging{opacity:.5}
.srow .av{background:var(--accent)!important}
.mv-dests{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.mv-dest{flex:1 1 45%;min-width:130px;padding:9px 10px;background:var(--panel2);border:1px dashed var(--line);border-radius:9px;font-size:12px}
.mv-dest.over{border-color:var(--accent);border-style:solid;background:color-mix(in srgb,var(--accent) 12%,transparent)}
.mv-dest .dn{font-weight:600;font-size:12px}.mv-dest .da{color:var(--faint);font-size:10.5px;word-break:break-all;margin-top:1px}
.mv-dest .rm{float:right;color:var(--faint);cursor:pointer;font-size:10.5px}.mv-dest .rm:hover{color:var(--deny)}
.mv-add{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.mv-add input{flex:1 1 30%;min-width:80px;background:var(--term);border:1px solid var(--line);border-radius:7px;color:var(--fg);font:12px ui-monospace,Menlo,monospace;padding:6px 8px;outline:none}
.mv-add button{background:var(--accent);color:#fff;border:0;border-radius:7px;padding:6px 12px;font:600 12px inherit;cursor:pointer}
.mv-stat{font-size:10.5px;margin-top:3px;min-height:13px}
.mv-stat.moving{color:var(--warn)}.mv-stat.delivered{color:var(--ok)}.mv-stat.refused{color:var(--warn)}.mv-stat.failed{color:var(--deny)}
/* console */
.console{margin:0 20px 20px}
.term{background:var(--term);border:1px solid var(--line);border-radius:11px;overflow:hidden}
.term .out{padding:12px 14px;height:40vh;overflow-y:auto;font-size:12.5px;line-height:1.55;color:#d5deee;white-space:pre-wrap;word-break:break-word}
.term .ln{margin:0}
.term .ln.cmd{color:var(--accent)}.term .ln.err{color:var(--deny)}.term .ln.ok{color:var(--ok)}.term .ln.dim{color:var(--faint)}
.term .inbar{display:flex;align-items:center;gap:8px;border-top:1px solid var(--line);padding:9px 12px;background:rgba(255,255,255,.02)}
.term .prompt{color:var(--accent);font-weight:600}
.term input{flex:1;background:transparent;border:0;color:var(--fg);font:13px ui-monospace,Menlo,monospace;outline:none}
.hint{color:var(--faint);font-size:11px;margin-top:8px}
.hint code{color:var(--fg)}
.warn{color:var(--warn)}
</style><link rel="stylesheet" href="/assets/agent-os.css"></head><body>
<header>
  <h1><span class="dot"></span> meshmcp <span style="color:var(--dim)">· control room</span></h1>
  <span id="chain" class="chain" role="status" aria-live="polite">…</span>
  <span class="viewers" id="viewers" aria-label="operators watching this room"></span>
  <span class="caps" id="caps"></span>
  <div class="spacer"></div>
  <div class="kpis">
    <div class="kpi"><b id="k-total">0</b><span>calls</span></div>
    <div class="kpi a"><b id="k-allow">0</b><span>allow</span></div>
    <div class="kpi d"><b id="k-deny">0</b><span>deny</span></div>
    <div class="kpi c"><b id="k-cosign">0</b><span>co-sign</span></div>
  </div>
</header>
<main>
  <div class="col">
    <div class="card"><h2><span>Servers · MCP backends</span><span class="dim" style="text-transform:none;letter-spacing:0">click a tile → console</span></h2><div class="tiles" id="tiles"></div></div>
    <div class="card"><h2>Live decision feed</h2><div class="feed" id="feed"><div class="empty">waiting for traffic…</div></div></div>
  </div>
  <div class="col">
    <div class="card"><h2>Identities · agent apps</h2><div class="idlist" id="ids"></div></div>
    <div class="card" id="movecard" style="display:none">
      <h2><span>Live sessions · drag to hand off</span><span class="dim" style="text-transform:none;letter-spacing:0">drag a session → a destination</span></h2>
      <div class="idlist" id="sessions"></div>
      <div class="mv-dests" id="dests"></div>
      <form class="mv-add" id="destform" autocomplete="off">
        <input id="d-label" placeholder="label (optional)" aria-label="destination label">
        <input id="d-addr" placeholder="dest addr ip:port" aria-label="destination mesh address" required>
        <input id="d-key" placeholder="dest WireGuard key" aria-label="destination WireGuard key" required>
        <button type="submit">add destination</button>
      </form>
    </div>
  </div>
</main>
<div class="console">
  <div class="card" style="padding:0;background:transparent;border:0">
    <h2 style="padding:0 4px">Console <span id="target-lbl" class="dim" style="text-transform:none;letter-spacing:0"></span></h2>
    <div class="term">
      <div class="out" id="out" role="log" aria-live="polite"></div>
      <div class="inbar"><span class="prompt" aria-hidden="true">meshmcp&gt;</span><input id="in" aria-label="Control Room command" autocomplete="off" spellcheck="false" placeholder="type a command — try: help"></div>
    </div>
    <div class="hint">
      <code>ls [peer:port]</code> · <code>call [peer:port] &lt;tool&gt; [json-args]</code> ·
      <code>run [peer:port] &lt;cmd&gt; [args…]</code> (governed) · <code>sh &lt;cmd…&gt;</code> (<span class="warn">raw local shell</span>) ·
      <code>target &lt;peer:port&gt;</code> · <code>clear</code>
    </div>
  </div>
</div>
<script>
/*__ROOM_TOKEN__*/
var $=function(id){return document.getElementById(id)};
function esc(s){return (s==null?'':String(s)).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function hue(s){var h=0;for(var i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))%360;return h}
function ago(ts){if(!ts)return '';var d=(Date.now()-Date.parse(ts))/1000;if(isNaN(d))return '';if(d<2)return 'now';if(d<60)return Math.floor(d)+'s';if(d<3600)return Math.floor(d/60)+'m';return Math.floor(d/3600)+'h'}
function hhmmss(ts){var d=new Date(ts);return isNaN(d)?'':d.toTimeString().slice(0,8)}

/* ---- live view ---- */
var seenSeq=0,firstLoad=true,caps={mesh:false,local_shell:false};
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
/* multiplayer presence: a per-tab id + name heartbeat, rendered as avatars */
var viewerId=(function(){try{var k=sessionStorage.getItem('roomViewerId');if(!k){k=Math.random().toString(36).slice(2,10);sessionStorage.setItem('roomViewerId',k)}return k}catch(e){return Math.random().toString(36).slice(2,10)}})();
var viewerName=(function(){try{return localStorage.getItem('roomViewerName')||('operator-'+viewerId.slice(0,4))}catch(e){return 'operator-'+viewerId.slice(0,4)}})();
function renderViewers(list){
  var vs=$('viewers');if(!vs)return;vs.textContent='';
  (list||[]).forEach(function(v){
    var nm=v.name||'operator';var a=el('span','vav'+(v.idle>5?' idle':''),(nm[0]||'?').toUpperCase());
    a.title=nm+(v.idle>5?' · idle '+v.idle+'s':'');a.style.background='hsl('+hue(nm)+',55%,45%)';vs.appendChild(a);
  });
  if((list||[]).length>1)vs.appendChild(el('span','vcount',list.length+' watching'));
}
function tick(){
  if(window.__ROOM_TOKEN){post('/api/presence',{id:viewerId,name:viewerName}).catch(function(){})}
  fetch('/api/room').then(function(r){return r.json()}).then(function(s){
    renderViewers(s.viewers);
    var c=$('chain');
    if(!s.records){c.className='chain';c.textContent='no records yet';}
    else if(s.chain&&s.chain.OK){c.className='chain ok';c.textContent='✓ chain intact · '+s.chain.Count;}
    else{c.className='chain bad';c.textContent='⚠ TAMPERED @ seq '+(s.chain?s.chain.BreakSeq:'?');}
    $('k-total').textContent=s.records||0;$('k-allow').textContent=s.allowed||0;$('k-deny').textContent=s.denied||0;$('k-cosign').textContent=s.cosign||0;
    var recent=s.recent||[];
    var tiles=$('tiles');tiles.textContent='';
    (s.backend_stats||[]).forEach(function(b){
      var t=el('button','tile');t.type='button';t.setAttribute('aria-label','Open '+b.backend+' in the console');t.appendChild(el('div','n',b.backend));
      t.appendChild(el('div','meta',b.calls+' calls · '+b.peers+' caller(s) · '+ago(b.last_seen)));
      var tot=b.calls||1,bar=el('div','bar');
      var ia=el('i','ia');ia.style.width=(100*b.allowed/tot)+'%';var ic=el('i','ic');ic.style.width=(100*b.cosign/tot)+'%';var idn=el('i','id');idn.style.width=(100*b.denied/tot)+'%';
      bar.appendChild(ia);bar.appendChild(ic);bar.appendChild(idn);t.appendChild(bar);
      t.addEventListener('click',function(){var i=$('in');i.value='ls ';i.focus()});
      tiles.appendChild(t);
    });
    if(!tiles.children.length)tiles.appendChild(el('div','empty','no servers seen yet'));
    var ids=$('ids');ids.textContent='';
    (s.peers||[]).forEach(function(p){
      var nm=p.peer||p.peer_key||'(unknown)';var row=el('div','id');
      var av=el('div','av',(nm[0]||'?').toUpperCase());av.style.background='hsl('+hue(nm)+',55%,45%)';row.appendChild(av);
      var info=el('div','info');info.appendChild(el('div','nm',nm));
      info.appendChild(el('div','sub',(p.last_tool?p.last_tool+' · ':'')+ago(p.last_seen)+' · '+p.denied+' denied'));row.appendChild(info);
      var cnt=el('div','cnt');cnt.appendChild(el('b',null,String(p.calls)));cnt.appendChild(document.createTextNode('calls'));row.appendChild(cnt);
      ids.appendChild(row);
    });
    if(!ids.children.length)ids.appendChild(el('div','empty','no identities yet'));
    var feed=$('feed');feed.textContent='';
    if(!recent.length){feed.appendChild(el('div','empty','waiting for traffic…'));}
    recent.forEach(function(r){
      var ev=el('div','ev');ev.appendChild(el('span','t',hhmmss(r.time)));
      var who=el('span','who');who.appendChild(document.createTextNode((r.peer||'(none)')+' → '));
      who.appendChild(el('span','to',r.tool||r.method));who.appendChild(el('span','be',' @'+(r.backend||'')));
      if(r.reason){who.appendChild(el('span','rs',' '+r.reason));}ev.appendChild(who);
      ev.appendChild(el('span','pill '+(r.decision||''),r.decision||''));feed.appendChild(ev);
    });
    seenSeq=recent.length?recent[0].seq:seenSeq;firstLoad=false;
  }).catch(function(){});
}

/* ---- console ---- */
var curTarget='';var history=[];var hIdx=0;
function pr(text,cls){var o=$('out');o.appendChild(el('div','ln '+(cls||''),text));o.scrollTop=o.scrollHeight}
function setTarget(t){curTarget=t;$('target-lbl').textContent=t?('→ '+t):'';}
function post(path,body){var h={'Content-Type':'application/json'};if(window.__ROOM_TOKEN)h['X-Room-Token']=window.__ROOM_TOKEN;return fetch(path,{method:'POST',headers:h,body:JSON.stringify(body)}).then(function(r){return r.json()})}
function textOf(res){ // extract content[].text if present, else pretty JSON
  try{if(res&&res.content&&res.content.length){return res.content.map(function(c){return c.text!=null?c.text:JSON.stringify(c)}).join('\n')}}catch(e){}
  return JSON.stringify(res,null,2);
}
function isTarget(tok){return /^[A-Za-z0-9_.\-]+:\d+$/.test(tok)}
function run(line){
  line=line.trim();if(!line)return;
  pr('meshmcp> '+line,'cmd');
  var tok=line.split(/\s+/);var cmd=tok.shift();
  if(cmd==='clear'){$('out').textContent='';return}
  if(cmd==='help'){pr('commands: ls · call · run (governed run_command) · sh (raw local shell) · target · clear','dim');
    pr('  ls [peer:port]                     list a backend\'s tools/resources/prompts','dim');
    pr('  call [peer:port] <tool> [json]     call a tool, e.g.  call 100.x:9101 add {"a":2,"b":40}','dim');
    pr('  run [peer:port] <cmd> [args…]      run_command on a backend (policy-governed + audited)','dim');
    pr('  sh <cmd…>                          run on THIS host (only if --local-shell)','dim');
    pr('  target <peer:port>                 set a default target so you can omit it','dim');return}
  if(cmd==='target'){setTarget(tok[0]||'');pr('target set: '+(curTarget||'(none)'),'dim');return}
  if(cmd==='sh'){
    if(!caps.local_shell){pr('local shell is disabled — start the room with --local-shell','err');return}
    post('/api/shell',{cmd:tok.join(' ')}).then(function(j){if(j.output!=null&&j.output!=='')pr(j.output);if(j.exit)pr(j.exit,'err')}).catch(function(e){pr('error: '+e,'err')});return}
  if(!caps.mesh){pr('not connected to the mesh — restart the room with NB_SETUP_KEY to drive backends','err');return}
  var target=curTarget;
  if(tok.length&&isTarget(tok[0])){target=tok.shift()}
  if(!target){pr('no target — use  target <peer:port>  or include it in the command','err');return}
  if(cmd==='ls'){
    post('/api/ls',{target:target}).then(function(j){
      if(j.error){pr(j.error,'err');return}
      pr('TOOLS ('+target+'):','ok');(j.tools||[]).forEach(function(t){pr('  '+t.name+(t.description?'  — '+t.description:''))});
      if(j.resources&&j.resources.length){pr('RESOURCES:','ok');j.resources.forEach(function(r){pr('  '+r.uri)})}
      if(j.prompts&&j.prompts.length){pr('PROMPTS:','ok');j.prompts.forEach(function(p){pr('  '+p.name)})}
    }).catch(function(e){pr('error: '+e,'err')});return}
  if(cmd==='call'){
    var tool=tok.shift();if(!tool){pr('usage: call [peer:port] <tool> [json-args]','err');return}
    var args={};var rest=tok.join(' ').trim();
    if(rest){try{args=JSON.parse(rest)}catch(e){pr('bad JSON args: '+e,'err');return}}
    post('/api/call',{target:target,tool:tool,args:args}).then(function(j){
      if(j.error){pr(j.error,'err')}else{pr(textOf(j.result))}
    }).catch(function(e){pr('error: '+e,'err')});return}
  if(cmd==='run'){
    var command=tok.shift();if(!command){pr('usage: run [peer:port] <cmd> [args…]','err');return}
    post('/api/call',{target:target,tool:'run_command',args:{command:command,args:tok}}).then(function(j){
      if(j.error){pr(j.error,'err')}else{pr(textOf(j.result))}
    }).catch(function(e){pr('error: '+e,'err')});return}
  pr('unknown command: '+cmd+' (try help)','err');
}
/* ---- live-session move (drag-to-handoff) ---- */
function humanAgeJS(s){s=s||0;if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';return Math.floor(s/3600)+'h'}
function mvDests(){try{return JSON.parse(localStorage.getItem('roomMoveDests')||'[]')}catch(e){return []}}
function mvSaveDests(d){try{localStorage.setItem('roomMoveDests',JSON.stringify(d))}catch(e){}}
function moveReq(body){
  var h={'Content-Type':'application/json'};if(window.__ROOM_TOKEN)h['X-Room-Token']=window.__ROOM_TOKEN;
  return fetch('/api/move',{method:'POST',headers:h,body:JSON.stringify(body)}).then(function(r){
    return r.text().then(function(t){var j=null;try{j=JSON.parse(t)}catch(_){}
      return {status:r.status,ok:r.ok,json:j,text:(t||'').trim()}})});
}
function doMove(s,d,st){
  if(!window.confirm('Move session '+s.id+'\nfrom backend '+s.backend+'\n→ '+(d.label||d.addr)+' ('+d.addr+') ?'))return;
  st.className='mv-stat moving';st.textContent='moving…';
  moveReq({backend:s.backend,id:s.id,dest_key:d.key,dest_addr:d.addr}).then(function(r){
    /* honest surfacing: delivered ONLY on the gateway's own 200 {status:"moved"};
       409 means the source thawed and still serves; anything else failed. */
    if(r.ok&&r.json&&r.json.status==='moved'){st.className='mv-stat delivered';st.textContent='delivered ✓ — now on '+(d.label||d.addr);loadSessions()}
    else if(r.status===409){st.className='mv-stat refused';st.textContent='refused — source still serving: '+r.text}
    else{st.className='mv-stat failed';st.textContent='failed ('+r.status+'): '+(r.text||'error')}
  }).catch(function(e){st.className='mv-stat failed';st.textContent='failed: '+e});
}
function renderDests(){
  var host=$('dests');if(!host)return;host.textContent='';
  var ds=mvDests();
  if(!ds.length){host.appendChild(el('div','empty','add a destination gateway below, then drag a session onto it'));return}
  ds.forEach(function(d,i){
    var t=el('div','mv-dest');
    var rm=el('span','rm','remove');rm.addEventListener('click',function(){var a=mvDests();a.splice(i,1);mvSaveDests(a);renderDests()});t.appendChild(rm);
    t.appendChild(el('div','dn',d.label||d.addr));
    t.appendChild(el('div','da',d.addr+' · '+String(d.key||'').slice(0,20)+'…'));
    var st=el('div','mv-stat');t.appendChild(st);
    t.addEventListener('dragover',function(e){e.preventDefault();e.dataTransfer.dropEffect='move';t.classList.add('over')});
    t.addEventListener('dragleave',function(){t.classList.remove('over')});
    t.addEventListener('drop',function(e){e.preventDefault();t.classList.remove('over');
      var raw=e.dataTransfer.getData('text/plain');if(!raw)return;var s;try{s=JSON.parse(raw)}catch(_){return}doMove(s,d,st)});
    host.appendChild(t);
  });
}
function renderSessions(list){
  var host=$('sessions');if(!host)return;host.textContent='';
  if(!list||!list.length){host.appendChild(el('div','empty','no live sessions'));return}
  list.forEach(function(s){
    var row=el('div','id srow');row.draggable=true;
    var av=el('div','av',((s.backend||'?')[0]||'?').toUpperCase());row.appendChild(av);
    var info=el('div','info');info.appendChild(el('div','nm',s.backend+' · '+s.id));
    info.appendChild(el('div','sub',(s.peer||s.peer_key||'(peer)')+' · '+humanAgeJS(s.age_sec)));row.appendChild(info);
    row.addEventListener('dragstart',function(e){e.dataTransfer.setData('text/plain',JSON.stringify({backend:s.backend,id:s.id}));e.dataTransfer.effectAllowed='move';row.classList.add('dragging')});
    row.addEventListener('dragend',function(){row.classList.remove('dragging')});
    host.appendChild(row);
  });
}
function loadSessions(){
  if(!caps.control)return;
  var h={};if(window.__ROOM_TOKEN)h['X-Room-Token']=window.__ROOM_TOKEN;
  fetch('/api/sessions',{headers:h}).then(function(r){return r.ok?r.json():{sessions:[]}}).then(function(j){renderSessions(j.sessions||[])}).catch(function(){});
}
var destForm=$('destform');
if(destForm){destForm.addEventListener('submit',function(e){e.preventDefault();
  var addr=$('d-addr').value.trim(),key=$('d-key').value.trim();if(!addr||!key)return;
  var ds=mvDests();ds.push({label:$('d-label').value.trim(),addr:addr,key:key});mvSaveDests(ds);
  $('d-label').value='';$('d-addr').value='';$('d-key').value='';renderDests();
});}

$('in').addEventListener('keydown',function(e){
  if(e.key==='Enter'){var v=e.target.value;if(v.trim()){history.push(v);hIdx=history.length}run(v);e.target.value='';}
  else if(e.key==='ArrowUp'){if(hIdx>0){hIdx--;e.target.value=history[hIdx]||'';e.preventDefault()}}
  else if(e.key==='ArrowDown'){if(hIdx<history.length){hIdx++;e.target.value=history[hIdx]||''}}
});
fetch('/api/caps').then(function(r){return r.json()}).then(function(c){
  caps=c;if(c.title)document.title=c.title;
  var el2=$('caps');el2.textContent='';
  var m=el('span',null,'mesh: ');m.appendChild(el('b',c.mesh?'on':'off',c.mesh?'connected':'view-only'));
  var s=el('span',null,'  shell: ');s.appendChild(el('b',c.local_shell?'on':'off',c.local_shell?'ON':'off'));
  el2.appendChild(m);el2.appendChild(s);
  pr('meshmcp control room. mesh '+(c.mesh?'connected':'view-only')+', local shell '+(c.local_shell?'ENABLED':'off')+'. type help.','dim');
  if(c.control){var mc=$('movecard');if(mc)mc.style.display='';renderDests();loadSessions();}
}).catch(function(){});
tick();setInterval(tick,1500);
setInterval(loadSessions,3000);
</script></body></html>`
