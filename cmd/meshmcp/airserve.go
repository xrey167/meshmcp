package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

//go:embed site/air-live.html
var airLiveHTML []byte

// maxAirUpload bounds a browser Drop/Push payload accepted by the served page.
const maxAirUpload = 8 << 20

// airServeDeps are the injectable dependencies of the served Air page, so the
// handler is testable with httptest (no mesh).
type airServeDeps struct {
	peers       func() ([]airPeerRow, error)              // reachable identities (from client.Status())
	identify    func(*http.Request) (pubkey, fqdn string) // resolve the browser's own mesh identity (nil = none)
	controlHC   *http.Client                              // client that reaches the gateway control endpoint
	controlBase string                                    // base URL for the control endpoint (empty = sessions/steer disabled)

	push         func(ctx context.Context, target, name string, data []byte) error // deliver a payload to a peer's drop inbox (nil = push/drop disabled)
	receipts     func(limit int) ([]json.RawMessage, error)                        // tail of the local audit ledger (nil = receipts disabled)
	gallery      func(limit int) ([]galleryImage, error)                           // images that landed in a drop inbox — the Vision view (nil = disabled)
	image        func(name string) (data []byte, contentType string, err error)    // read one gallery image, path-safe (nil = disabled)
	cast         func(limit int) ([]galleryImage, error)                           // images in the cast inbox — the "Now Showing" view (nil = disabled)
	castImage    func(name string) (data []byte, contentType string, err error)    // read one cast image, path-safe (nil = disabled)
	approvals    string                                                            // approvals server (mesh-ip:port) the page links out to ("" = hidden)
	allow        acl                                                               // page-wide viewer ACL; empty = any mesh peer
	allowedHosts []string                                                          // Host values the page may be served at (mesh ip/fqdn:port); empty = no Host check (dev)

	self         func() airPeerRow                      // this node's own mesh identity for /api/home (nil = zero You)
	pendingCount func(ctx context.Context) (int, error) // count held approvals for /api/home (nil = pending unknown, -1)
	viewAudit    *policy.AuditLog                       // SEPARATE view-audit chain for /api/home (nil = no view record; NEVER the enforcement ledger)
}

// airServeHandler builds the live Air page + its /api surface: proxied
// sessions/steer, relay-sent push/drop, a receipts tail, and an approvals link.
func airServeHandler(d airServeDeps) http.Handler {
	mux := http.NewServeMux()
	registerAgentOSAssets(mux)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(airLiveHTML)
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"approvals": d.approvals,
			"push":      d.push != nil,
			"receipts":  d.receipts != nil,
			"vision":    d.gallery != nil,
			"cast":      d.cast != nil,
			"catalog":   d.controlBase != "",
			"nearby":    d.controlBase != "",
			"home":      true,
		})
	})

	// /api/home is the aggregated primary poll: it fuses the already-wired
	// sources (peers, sessions, catalog, receipts tail, cast, pending) into one
	// air.Home so the page makes one cheap fetch instead of six. GET-only, behind
	// the same viewer ACL + web security as every other route.
	mux.HandleFunc("/api/home", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		home := d.assembleHome(r)
		// View-audit lands ONLY on the dedicated separate chain, never the
		// enforcement ledger (d.receipts). Off unless a viewAudit sink was
		// explicitly wired, so a page poll never pollutes the gateway chain.
		if d.viewAudit != nil {
			var pubkey, fqdn string
			if d.identify != nil {
				pubkey, fqdn = d.identify(r)
			}
			_ = d.viewAudit.Append(policy.AuditRecord{
				Peer: fqdn, PeerKey: pubkey, Method: "air.home",
				Decision: "allow", Rule: -1,
				Reason: fmt.Sprintf("view nearby=%d working=%d peers=%d sessions=%d pending=%d",
					home.Summary.Nearby, home.Summary.Working, home.Summary.PeersOnline, home.Summary.Sessions, home.Summary.Pending),
			})
		}
		writeJSONResp(w, http.StatusOK, home)
	})

	mux.HandleFunc("/api/catalog", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		if d.controlBase == "" {
			http.Error(w, "no --control endpoint configured", http.StatusServiceUnavailable)
			return
		}
		req, _ := http.NewRequest(http.MethodGet, d.controlBase+airCatalogPath, nil)
		d.attest(req, r)
		resp, err := d.controlHC.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		relay(w, resp)
	})

	mux.HandleFunc("/api/nearby", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		if d.controlBase == "" {
			http.Error(w, "no --control endpoint configured", http.StatusServiceUnavailable)
			return
		}
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, d.controlBase+"/v1/presence", nil)
		d.attest(req, r)
		resp, err := d.controlHC.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPresenceListBytes+1))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if len(body) > maxPresenceListBytes {
			http.Error(w, "nearby response is too large", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})

	mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		rows := []airPeerRow{}
		if d.peers != nil {
			got, err := d.peers()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			rows = got
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"peers": rows})
	})

	mux.HandleFunc("/api/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if d.push == nil {
			http.Error(w, "push is not enabled on this page", http.StatusServiceUnavailable)
			return
		}
		var body struct{ Target, Name, Text string }
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAirUpload)).Decode(&body) != nil || body.Target == "" || body.Text == "" {
			http.Error(w, "target and text are required", http.StatusBadRequest)
			return
		}
		if !validMeshTarget(body.Target) {
			http.Error(w, "target must be a mesh host:port", http.StatusBadRequest)
			return
		}
		// Base-sanitize the sender-supplied name (the receiver re-checks, but the
		// relay should never forward a path-y name), matching /api/drop.
		name := filepath.Base(body.Name)
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "clip.txt"
		}
		if err := d.push(r.Context(), body.Target, name, []byte(body.Text)); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]string{"status": "pushed", "target": body.Target, "name": name})
	})

	mux.HandleFunc("/api/drop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if d.push == nil {
			http.Error(w, "drop is not enabled on this page", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAirUpload)
		if err := r.ParseMultipartForm(maxAirUpload); err != nil {
			http.Error(w, "bad upload: "+err.Error(), http.StatusBadRequest)
			return
		}
		target := r.FormValue("target")
		file, hdr, err := r.FormFile("file")
		if target == "" || err != nil {
			http.Error(w, "target and file are required", http.StatusBadRequest)
			return
		}
		if !validMeshTarget(target) {
			http.Error(w, "target must be a mesh host:port", http.StatusBadRequest)
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxAirUpload))
		if err != nil {
			http.Error(w, "read upload: "+err.Error(), http.StatusBadRequest)
			return
		}
		name := filepath.Base(hdr.Filename)
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "upload.bin"
		}
		if err := d.push(r.Context(), target, name, data); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"status": "dropped", "target": target, "name": name, "bytes": len(data)})
	})

	mux.HandleFunc("/api/receipts", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		if d.receipts == nil {
			http.Error(w, "receipts are not enabled on this page", http.StatusServiceUnavailable)
			return
		}
		limit := 50
		if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 500 {
			limit = n
		}
		recs, err := d.receipts(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if recs == nil {
			recs = []json.RawMessage{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"receipts": recs})
	})

	// Air · Vision (a gallery of received drops) and Air · Cast (a single "Now
	// Showing" slot a sender presents) share the same read-only, path-safe image
	// plumbing over different inbox dirs: listHandler enumerates, imageHandler
	// serves one by name (the reader re-validates the name against its root).
	// Both are gated by the page-wide viewer ACL like every other endpoint.
	listHandler := func(list func(int) ([]galleryImage, error), disabled string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !getOnly(w, r) {
				return
			}
			if list == nil {
				http.Error(w, disabled, http.StatusServiceUnavailable)
				return
			}
			limit := 60
			if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= maxGalleryImages {
				limit = n
			}
			imgs, err := list(limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if imgs == nil {
				imgs = []galleryImage{}
			}
			writeJSONResp(w, http.StatusOK, map[string]any{"images": imgs})
		}
	}
	imageHandler := func(read func(string) ([]byte, string, error), disabled string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !getOnly(w, r) {
				return
			}
			if read == nil {
				http.Error(w, disabled, http.StatusServiceUnavailable)
				return
			}
			name := r.URL.Query().Get("name")
			if name == "" {
				http.Error(w, "name is required", http.StatusBadRequest)
				return
			}
			data, contentType, err := read(name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			// Exact type, never sniffed (nosniff is set globally); rendered inline,
			// not downloaded; cached briefly since inbox files are content-stable.
			h := w.Header()
			h.Set("Content-Type", contentType)
			h.Set("Content-Disposition", "inline")
			h.Set("Cache-Control", "private, max-age=60")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		}
	}
	mux.HandleFunc("/api/gallery", listHandler(d.gallery, "the Vision gallery is not enabled on this page"))
	mux.HandleFunc("/api/image", imageHandler(d.image, "the Vision gallery is not enabled on this page"))
	mux.HandleFunc("/api/cast", listHandler(d.cast, "casting is not enabled on this page"))
	mux.HandleFunc("/api/castimage", imageHandler(d.castImage, "casting is not enabled on this page"))

	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		if d.controlBase == "" {
			http.Error(w, "no --control endpoint configured", http.StatusServiceUnavailable)
			return
		}
		req, _ := http.NewRequest(http.MethodGet, d.controlBase+"/v1/sessions", nil)
		d.attest(req, r)
		resp, err := d.controlHC.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		relay(w, resp)
	})

	mux.HandleFunc("/api/steer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if d.controlBase == "" {
			http.Error(w, "no --control endpoint configured", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		req, _ := http.NewRequest(http.MethodPost, d.controlBase+"/v1/steer", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		d.attest(req, r)
		resp, err := d.controlHC.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		relay(w, resp)
	})

	// Optional page-wide viewer gate: when an --allow list is set, only listed
	// mesh identities may load the page or call its API (empty = any mesh peer,
	// matching backend Allow semantics).
	var gated http.Handler = mux
	if !d.allow.empty() && d.identify != nil {
		gated = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pubKey, fqdn := d.identify(r)
			if !d.allow.allows(pubKey, fqdn) {
				http.Error(w, "not permitted", http.StatusForbidden)
				return
			}
			mux.ServeHTTP(w, r)
		})
	}
	return withWebSecurity(gated, d.allowedHosts)
}

// withWebSecurity wraps the served Air page with defence-in-depth for a browser
// surface: hardening response headers on every response, a Host allow-list that
// defeats DNS rebinding, and a same-origin guard on state-changing POSTs so a
// page on another origin can't drive the relay through a viewer's browser.
func withWebSecurity(h http.Handler, allowedHosts []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		// Self-contained page: no external hosts for scripts, styles, images,
		// or fetch/XHR; not framable; no MIME sniffing; no referrer leakage.
		// ('unsafe-inline' is required for the inline <style>/<script>; the
		// locked default-src/connect-src still prevent exfiltration to any
		// other origin, and every dynamic value is HTML-escaped.)
		hdr.Set("Content-Security-Policy",
			"default-src 'self'; connect-src 'self'; img-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "+
				"object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "no-referrer")
		// The page and its API expose identity-attributed, per-caller-filtered
		// data (peers, catalog, receipts, sessions) — never let a shared or proxy
		// cache retain it. Handlers that serve cacheable bytes (e.g. /api/image)
		// override this with their own Cache-Control after us.
		hdr.Set("Cache-Control", "no-store")
		// DNS-rebinding defence: the page is only ever reached at the gateway's
		// own mesh address, so a request whose Host is anything else (an
		// attacker domain rebound to the mesh IP) is refused — this is what a
		// same-origin check alone misses, because under rebinding Origin==Host.
		// Applied to ALL methods, since a rebound page can read as well as write.
		if len(allowedHosts) > 0 && !airHostAllowed(r.Host, allowedHosts) {
			http.Error(w, "host not permitted", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// getOnly rejects any method other than GET/HEAD on a read-only endpoint,
// returning false (after writing a 405) so the handler stops. Read-only API
// routes must not silently accept POST/PUT/DELETE.
func getOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// validMeshTarget reports whether target is a well-formed mesh host:port — a
// syntactic guard so the relay's push/drop cannot be pointed at garbage (and,
// with a bad port, at an unintended local service).
func validMeshTarget(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return false
	}
	if _, err := strconv.Atoi(port); err != nil {
		return false
	}
	return true
}

// hostAllowed reports whether the request Host matches one of the expected
// mesh addresses the page is served on.
func airHostAllowed(host string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(host, a) {
			return true
		}
	}
	return false
}

// sameOrigin reports whether a state-changing request is same-origin: a present
// Origin header must match the request's Host. A browser always sends Origin on
// a cross-origin fetch, so a mismatch is a classic CSRF attempt; an absent
// Origin (a non-browser client such as the CLI) is allowed — the mesh + viewer
// ACL already gate those. (Host-pinning above handles the rebinding case where
// Origin==Host.)
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// attest stamps the outbound control-endpoint request with the browser's own mesh
// identity, so the gateway audits the human who clicked — not the air-serve relay.
// Relay-attested: the control endpoint honours it only because this proxy is
// itself an ACL-allowed mesh peer (see aircontrol.onBehalfOf).
func (d airServeDeps) attest(out, in *http.Request) {
	if d.identify == nil {
		return
	}
	pubkey, fqdn := d.identify(in)
	if fqdn != "" {
		out.Header.Set("X-Air-On-Behalf", fqdn)
	}
	if pubkey != "" {
		out.Header.Set("X-Air-On-Behalf-Key", pubkey)
	}
}

// assembleHome fuses the wired sources into one air.Home as this viewer sees it.
// Every section is best-effort: a source that errors or is not wired leaves its
// section empty, so the home degrades section by section. Pending is -1 unless a
// pendingCount dep is wired AND returns a count (the relay is a real approver).
func (d airServeDeps) assembleHome(r *http.Request) air.Home {
	h := air.Home{Generated: nowRFC3339(), Pending: -1}
	if d.self != nil {
		h.You = d.self()
	}
	if d.peers != nil {
		if rows, err := d.peers(); err == nil {
			h.Peers = rows
		}
	}
	if d.controlBase != "" {
		if cards := d.relayPresence(r); cards != nil {
			h.Nearby = cards
		}
		if sess := d.relaySessions(r); sess != nil {
			h.Sessions = sess
		}
		if eps := d.relayCatalog(r); eps != nil {
			h.Reachable = eps
		}
	}
	if d.receipts != nil {
		if acts, err := homeReceipts(d.receipts, 50); err == nil {
			h.Activity = acts
		}
	}
	if d.cast != nil {
		if imgs, err := d.cast(1); err == nil && len(imgs) > 0 {
			h.Showing = &air.Media{Name: imgs[0].Name, ModUnix: imgs[0].ModUnix}
		}
	}
	if d.gallery != nil {
		if imgs, err := d.gallery(maxGalleryImages); err == nil {
			h.Landed = len(imgs)
		}
	}
	if d.pendingCount != nil {
		if n, err := d.pendingCount(r.Context()); err == nil {
			h.Pending = n
		}
	}
	h.Summary = air.Summarize(h)
	return h
}

// relayPresence fetches identity-stamped Air cards with browser attribution,
// returning nil (an empty section) on any gateway or decoding failure.
func (d airServeDeps) relayPresence(r *http.Request) []air.Presence {
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, d.controlBase+"/v1/presence", nil)
	d.attest(req, r)
	resp, err := d.controlHC.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPresenceListBytes+1))
	if err != nil || len(body) > maxPresenceListBytes {
		return nil
	}
	var out struct {
		Presence []air.Presence `json:"presence"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	return out.Presence
}

// relaySessions fetches the gateway's live sessions with browser attestation,
// returning nil (empty section) on any failure.
func (d airServeDeps) relaySessions(r *http.Request) []air.Session {
	req, _ := http.NewRequest(http.MethodGet, d.controlBase+"/v1/sessions", nil)
	d.attest(req, r)
	resp, err := d.controlHC.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Sessions []air.Session `json:"sessions"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	return out.Sessions
}

// relayCatalog fetches the gateway's per-caller ARD catalog with attestation,
// returning nil (empty section) on any failure.
func (d airServeDeps) relayCatalog(r *http.Request) []air.CatalogEntry {
	req, _ := http.NewRequest(http.MethodGet, d.controlBase+airCatalogPath, nil)
	d.attest(req, r)
	resp, err := d.controlHC.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var cat air.Catalog
	if json.Unmarshal(body, &cat) != nil {
		return nil
	}
	return cat.Endpoints
}

// homeReceipts tails the local ledger and returns the newest limit records as
// Receipts, newest first (the tail func is oldest-first).
func homeReceipts(tail func(int) ([]json.RawMessage, error), limit int) ([]air.Receipt, error) {
	recs, err := tail(limit)
	if err != nil {
		return nil, err
	}
	out := make([]air.Receipt, 0, len(recs))
	for i := len(recs) - 1; i >= 0; i-- {
		if rr, ok := air.ParseReceipt(recs[i]); ok {
			out = append(out, rr)
		}
	}
	return out, nil
}

// tailAuditRecords returns the last limit records of a JSONL audit ledger,
// oldest first. Lines that are not valid JSON are skipped.
func tailAuditRecords(path string, limit int) ([]json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var recs []json.RawMessage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || !json.Valid(line) {
			continue
		}
		recs = append(recs, json.RawMessage(append([]byte(nil), line...)))
		if len(recs) > limit {
			recs = recs[1:]
		}
	}
	return recs, sc.Err()
}

// relay copies an upstream control-endpoint response back to the caller.
func relay(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// cmdAirServe serves the live Air page over the mesh (or a local addr for dev),
// proxying session list/steer to a gateway control endpoint.
func cmdAirServe(args []string) error {
	fs := flag.NewFlagSet("air serve", flag.ExitOnError)
	o := meshFlags(fs)
	port := fs.Int("port", 9800, "mesh port to serve the Air page on")
	addr := fs.String("addr", "", "bind a plain local address instead of the mesh (dev; peers/sessions need the mesh)")
	control := fs.String("control", "", "gateway control endpoint (mesh-ip:port) for the sessions/steer views")
	approvals := fs.String("approvals", "", "approvals server (mesh-ip:port) the Approvals view links out to — the browser talks to it directly, keeping human attribution")
	auditPath := fs.String("audit", "", "local audit JSONL to serve as the Receipts view (read-only tail)")
	gallery := fs.String("gallery", "", "drop-inbox directory to render as the Vision gallery (images the mesh dropped to this node)")
	cast := fs.String("cast", "", "cast-inbox directory to render as the \"Now Showing\" slot (the newest image a peer cast here)")
	auditViews := fs.String("audit-views", "", "append one 'air.home' view record per /api/home assembly to this SEPARATE audit chain (opt-in; never the enforcement --audit ledger)")
	allow := multiFlag{}
	fs.Var(&allow, "allow", "identity permitted to open the page (FQDN glob or pubkey:<key>); repeatable; empty = any mesh peer")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Local/dev mode: serve the page without joining the mesh.
	if *addr != "" {
		d := airServeDeps{
			peers:        func() ([]airPeerRow, error) { return nil, nil },
			allowedHosts: []string{*addr},
		}
		if *gallery != "" {
			galleryDir := *gallery
			d.gallery = func(limit int) ([]galleryImage, error) { return listGalleryImages(galleryDir, limit) }
			d.image = func(name string) ([]byte, string, error) { return readGalleryImage(galleryDir, name) }
		}
		if *cast != "" {
			castDir := *cast
			d.cast = func(limit int) ([]galleryImage, error) { return listGalleryImages(castDir, limit) }
			d.castImage = func(name string) ([]byte, string, error) { return readGalleryImage(castDir, name) }
		}
		fmt.Fprintf(os.Stderr, "Air (live) on http://%s (LOCAL — no mesh; peers/sessions unavailable)\n", *addr)
		return newLocalHTTPServer(*addr, airServeHandler(d)).ListenAndServe()
	}

	// The privileged endpoints (steer/sessions via --control, push, drop) act
	// with THIS relay's mesh identity: any browser that reaches them borrows
	// the relay's authority. So they are exposed only when --allow names who
	// may use them — the viewer gate then admits only those identities. Without
	// --allow the page is read-only (peers + receipts), never a confused deputy
	// letting an arbitrary mesh peer steer sessions or drop files as the relay.
	privileged := len(allow) > 0
	if *control != "" && !privileged {
		return fmt.Errorf("air serve: --control requires --allow (the browsers permitted to steer/push through this relay); without it any mesh peer could act with the relay's identity")
	}

	o.BlockInbound = false // we listen for browsers on the mesh
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	// The page is reached only at this gateway's own mesh address, so pin the
	// Host to the mesh IP (and FQDN) with the serve port — a DNS-rebinding page
	// carries the attacker's Host and is refused (withWebSecurity).
	var allowedHosts []string
	if st, err := client.Status(); err == nil {
		ip := strings.SplitN(st.LocalPeerState.IP, "/", 2)[0]
		if ip != "" {
			allowedHosts = append(allowedHosts, fmt.Sprintf("%s:%d", ip, *port))
		}
		if st.LocalPeerState.FQDN != "" {
			allowedHosts = append(allowedHosts, fmt.Sprintf("%s:%d", st.LocalPeerState.FQDN, *port))
		}
	}

	d := airServeDeps{
		approvals:    *approvals,
		allow:        newACL(allow),
		allowedHosts: allowedHosts,
		// The browser is itself a mesh peer; resolve its WireGuard identity so
		// steers it drives are attributed to the human, not this relay.
		identify: func(r *http.Request) (string, string) { return peerIdentityStr(client, r.RemoteAddr) },
		peers: func() ([]airPeerRow, error) {
			st, err := client.Status()
			if err != nil {
				return nil, err
			}
			rows := []airPeerRow{}
			for _, p := range st.Peers {
				connected := strings.EqualFold(fmt.Sprint(p.ConnStatus), "Connected")
				status := "connected"
				if !connected {
					status = strings.ToLower(fmt.Sprint(p.ConnStatus))
				}
				rows = append(rows, airPeerRow{
					Status: status,
					IP:     strings.SplitN(p.IP, "/", 2)[0],
					FQDN:   p.FQDN,
					PubKey: shortKey(p.PubKey),
				})
			}
			return rows, nil
		},
	}
	// This node's own identity for the /api/home hero (Status()'s local peer).
	d.self = func() airPeerRow {
		st, err := client.Status()
		if err != nil {
			return airPeerRow{}
		}
		return airPeerRow{
			Status: "connected",
			IP:     strings.SplitN(st.LocalPeerState.IP, "/", 2)[0],
			FQDN:   st.LocalPeerState.FQDN,
			PubKey: shortKey(st.LocalPeerState.PubKey),
		}
	}
	// Push/Drop send over THIS relay's mesh identity (the receiver's ACL and
	// audit see the air-serve node; the browser identity is the allow-listed
	// page viewer). Enabled only when --allow gates who may drive the relay.
	if privileged {
		d.push = func(ctx context.Context, target, name string, data []byte) error {
			pr, pw := io.Pipe()
			// Close the read end when Run returns: if it exits early (send
			// error or ctx cancel) the writer goroutine is otherwise left
			// blocked forever on pw.Write into an unread pipe.
			defer pr.Close()
			go func() { pw.CloseWithError(sendData(pw, name, data)) }()
			dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
			return session.NewClient(dial, log.Printf).Run(ctx, sendStream{r: pr})
		}
	}
	if *control != "" {
		d.controlBase = "http://air-control"
		d.controlHC = &http.Client{
			Timeout: 20 * time.Second, // never let a hung control endpoint wedge the page
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return client.Dial(ctx, "tcp", *control)
				},
			},
		}
	}
	if *auditPath != "" {
		d.receipts = func(limit int) ([]json.RawMessage, error) { return tailAuditRecords(*auditPath, limit) }
	}
	// Air · Vision: render the images that landed in a drop inbox. Read-only —
	// like Receipts, it exposes what THIS node already received, so it needs no
	// --allow; when --allow is set, the viewer gate covers it too.
	if *gallery != "" {
		galleryDir := *gallery
		d.gallery = func(limit int) ([]galleryImage, error) { return listGalleryImages(galleryDir, limit) }
		d.image = func(name string) ([]byte, string, error) { return readGalleryImage(galleryDir, name) }
		// A Receipt is audit metadata; a gallery streams the raw pixels of whatever
		// landed in the inbox (a screenshot, a scanned document) — materially more
		// sensitive. Without --allow any mesh peer can view them, so say so loudly.
		if len(allow) == 0 {
			fmt.Fprintln(os.Stderr, amber("warning:")+" --gallery exposes received images to ANY mesh peer; add --allow <id> to restrict who can view them")
		}
	}
	if *cast != "" {
		castDir := *cast
		d.cast = func(limit int) ([]galleryImage, error) { return listGalleryImages(castDir, limit) }
		d.castImage = func(name string) ([]byte, string, error) { return readGalleryImage(castDir, name) }
		if len(allow) == 0 {
			fmt.Fprintln(os.Stderr, amber("warning:")+" --cast exposes cast images to ANY mesh peer; add --allow <id> to restrict who can view them")
		}
	}
	// Pending-count for /api/home is disclosed ONLY when (a) --allow gates who may
	// drive this relay (privileged) AND (b) the relay identity is actually an
	// approver on the target — otherwise /v1/pending returns 403 and the count
	// stays unknown (-1), so a non-approver page viewer never learns the number.
	// air home only ever counts; approve/deny stays on the approvals page.
	if privileged && *approvals != "" {
		approvalsAddr := *approvals
		approvalsHC := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return client.Dial(ctx, "tcp", approvalsAddr)
				},
			},
		}
		d.pendingCount = func(ctx context.Context) (int, error) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://air-approvals/v1/pending", nil)
			resp, err := approvalsHC.Do(req)
			if err != nil {
				return 0, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return 0, fmt.Errorf("pending: %s", resp.Status) // 403 => relay is not an approver
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			var out struct {
				Pending []json.RawMessage `json:"pending"`
			}
			if json.Unmarshal(body, &out) != nil {
				return 0, fmt.Errorf("pending: bad response")
			}
			return len(out.Pending), nil
		}
	}
	// Opt-in view-audit for /api/home: its OWN tamper-evident chain in its OWN
	// file, never the enforcement --audit ledger.
	if *auditViews != "" {
		va, closeVA, err := openViewAudit(*auditViews)
		if err != nil {
			return fmt.Errorf("air serve: --audit-views: %w", err)
		}
		defer closeVA()
		d.viewAudit = va
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()
	if len(allowedHosts) > 0 {
		fmt.Fprintf(os.Stderr, "Air (live) on http://%s (open it from any device on the mesh)\n", allowedHosts[0])
	} else {
		fmt.Fprintf(os.Stderr, "Air (live) on mesh port %d (open it from any device on the mesh)\n", *port)
	}
	// Read/header timeouts even on the mesh: any admitted peer could otherwise
	// dribble headers forever and exhaust the listener (Slowloris).
	return newLocalHTTPServer("", airServeHandler(d)).Serve(ln)
}
