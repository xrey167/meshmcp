package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
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

const (
	// maxAirUpload bounds the decoded Drop/Push payload accepted by the served
	// page and matches the receiver-confirmed action protocol's payload bound.
	maxAirUpload = air.MaxActionPayloadBytes
	// maxAirActionJSON bounds small control requests such as Ring before their
	// stricter domain validation runs.
	maxAirActionJSON = 64 << 10
	// JSON strings can encode one byte as a six-byte escape (for example,
	// "\\u0000"), so the request bound admits that worst case. Multipart only
	// needs a small, independently bounded framing allowance.
	maxAirRequestOverhead       = maxAirActionJSON
	maxAirJSONRequestBytes      = 6*maxAirUpload + maxAirRequestOverhead
	maxAirMultipartRequestBytes = maxAirUpload + maxAirRequestOverhead
)

// airServeDeps are the injectable dependencies of the served Air page, so the
// handler is testable with httptest (no mesh).
type airServeDeps struct {
	peers       func() ([]airPeerRow, error)              // reachable identities (from client.Status())
	identify    func(*http.Request) (pubkey, fqdn string) // resolve the browser's own mesh identity (nil = none)
	controlHC   *http.Client                              // client that reaches the gateway control endpoint
	controlBase string                                    // base URL for the control endpoint (empty = sessions/steer disabled)

	push          func(ctx context.Context, target, name string, data []byte) error              // legacy best-effort delivery for explicit raw targets
	pushConfirmed func(ctx context.Context, target, expectedKey, name string, data []byte) error // identity-bound, receiver-confirmed resolved delivery
	ring          func(ctx context.Context, target string, notice air.Notice) error              // deliver an attention notice to a peer's ring inbox (nil = disabled)
	receipts      func(limit int) ([]json.RawMessage, error)                                     // tail of the local audit ledger (nil = receipts disabled)
	gallery       func(limit int) ([]galleryImage, error)                                        // images that landed in a drop inbox — the Vision view (nil = disabled)
	image         func(name string) (data []byte, contentType string, err error)                 // read one gallery image, path-safe (nil = disabled)
	cast          func(limit int) ([]galleryImage, error)                                        // images in the cast inbox — the "Now Showing" view (nil = disabled)
	castImage     func(name string) (data []byte, contentType string, err error)                 // read one cast image, path-safe (nil = disabled)
	approvals     string                                                                         // approvals server (mesh-ip:port) the page links out to ("" = hidden)
	allow         acl                                                                            // page-wide viewer ACL; empty = any mesh peer
	allowedHosts  []string                                                                       // Host values the page may be served at (mesh ip/fqdn:port); empty = no Host check (dev)

	self         func() airPeerRow                      // this node's own mesh identity for /api/home (nil = zero You)
	pendingCount func(ctx context.Context) (int, error) // count held approvals for /api/home (nil = pending unknown, -1)
	viewAudit    *policy.AuditLog                       // SEPARATE view-audit chain for /api/home (nil = no view record; NEVER the enforcement ledger)
}

// airServeHandler builds the live Air page + its /api surface: proxied
// sessions/steer, relay-sent push/drop/ring, a receipts tail, and an approvals
// link.
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
			"push":      d.push != nil || d.pushConfirmed != nil,
			"ring":      d.ring != nil,
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
		if d.push == nil && d.pushConfirmed == nil {
			http.Error(w, "push is not enabled on this page", http.StatusServiceUnavailable)
			return
		}
		var body struct {
			To        string `json:"to"`
			Target    string `json:"target"`
			Recipient string `json:"recipient"`
			Name      string `json:"name"`
			Text      string `json:"text"`
		}
		if status, err := decodeAirJSON(w, r, &body, maxAirJSONRequestBytes); err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		if body.Text == "" {
			http.Error(w, "text is required", http.StatusBadRequest)
			return
		}
		if int64(len(body.Text)) > maxAirUpload {
			http.Error(w, "text exceeds the 8 MiB payload limit", http.StatusRequestEntityTooLarge)
			return
		}
		// Base-sanitize the sender-supplied name (the receiver re-checks, but the
		// relay should never forward a path-y name), matching /api/drop.
		name := filepath.Base(body.Name)
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "clip.txt"
		}
		logicalTo, err := airLogicalRecipient(body.To, body.Recipient)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Resolve only after the request payload is fully accepted, so Presence is
		// fetched as close as possible to the actual delivery attempt.
		recipient, err := d.resolveActionRecipient(r, logicalTo, body.Target)
		if err != nil {
			http.Error(w, err.Error(), airActionStatus(err))
			return
		}
		logical := logicalTo != ""
		if logical {
			if d.pushConfirmed == nil {
				http.Error(w, "receiver-confirmed delivery is not enabled on this page", http.StatusServiceUnavailable)
				return
			}
			if _, err := air.NewActionReceipt(air.ActionPush, recipient, name, int64(len(body.Text)), time.Unix(1, 0)); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if !logical && d.push == nil {
			http.Error(w, "legacy raw-address delivery is not enabled on this page", http.StatusServiceUnavailable)
			return
		}
		var sendErr error
		if logical {
			sendErr = d.pushConfirmed(r.Context(), recipient.Address, recipient.PublicKey, name, []byte(body.Text))
		} else {
			sendErr = d.push(r.Context(), recipient.Address, name, []byte(body.Text))
		}
		if sendErr != nil {
			http.Error(w, sendErr.Error(), http.StatusBadGateway)
			return
		}
		if !logical {
			writeJSONResp(w, http.StatusOK, map[string]string{"status": "pushed", "target": recipient.Address, "name": name})
			return
		}
		receipt, err := air.NewActionReceipt(air.ActionPush, recipient, name, int64(len(body.Text)), time.Now())
		if err != nil {
			http.Error(w, "build confirmed receipt", http.StatusInternalServerError)
			return
		}
		result, err := air.NewActionResult(recipient, []air.ActionReceipt{receipt})
		if err != nil {
			http.Error(w, "build confirmed result", http.StatusInternalServerError)
			return
		}
		writeJSONResp(w, http.StatusOK, result)
	})

	mux.HandleFunc("/api/drop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if d.push == nil && d.pushConfirmed == nil {
			http.Error(w, "drop is not enabled on this page", http.StatusServiceUnavailable)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAirMultipartRequestBytes)
		if err := r.ParseMultipartForm(maxAirUpload); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, fmt.Sprintf("upload request exceeds %d bytes", maxAirMultipartRequestBytes), http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad upload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file is required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxAirUpload+1))
		if err != nil {
			http.Error(w, "read upload: "+err.Error(), http.StatusBadRequest)
			return
		}
		if int64(len(data)) > maxAirUpload {
			http.Error(w, "file exceeds the 8 MiB payload limit", http.StatusRequestEntityTooLarge)
			return
		}
		name := filepath.Base(hdr.Filename)
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "upload.bin"
		}
		logicalTo, err := airLogicalRecipient(r.FormValue("to"), r.FormValue("recipient"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Resolve after the upload has been read and validated. The chosen inbox
		// therefore comes from a fresh Presence view immediately before delivery.
		recipient, err := d.resolveActionRecipient(r, logicalTo, r.FormValue("target"))
		if err != nil {
			http.Error(w, err.Error(), airActionStatus(err))
			return
		}
		logical := logicalTo != ""
		if logical {
			if d.pushConfirmed == nil {
				http.Error(w, "receiver-confirmed delivery is not enabled on this page", http.StatusServiceUnavailable)
				return
			}
			if _, err := air.NewActionReceipt(air.ActionDrop, recipient, name, int64(len(data)), time.Unix(1, 0)); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if !logical && d.push == nil {
			http.Error(w, "legacy raw-address delivery is not enabled on this page", http.StatusServiceUnavailable)
			return
		}
		var sendErr error
		if logical {
			sendErr = d.pushConfirmed(r.Context(), recipient.Address, recipient.PublicKey, name, data)
		} else {
			sendErr = d.push(r.Context(), recipient.Address, name, data)
		}
		if sendErr != nil {
			http.Error(w, sendErr.Error(), http.StatusBadGateway)
			return
		}
		if !logical {
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "dropped", "target": recipient.Address, "name": name, "bytes": len(data)})
			return
		}
		receipt, err := air.NewActionReceipt(air.ActionDrop, recipient, name, int64(len(data)), time.Now())
		if err != nil {
			http.Error(w, "build confirmed receipt", http.StatusInternalServerError)
			return
		}
		result, err := air.NewActionResult(recipient, []air.ActionReceipt{receipt})
		if err != nil {
			http.Error(w, "build confirmed result", http.StatusInternalServerError)
			return
		}
		writeJSONResp(w, http.StatusOK, result)
	})

	mux.HandleFunc("/api/ring", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if d.ring == nil {
			http.Error(w, "ring is not enabled on this page", http.StatusServiceUnavailable)
			return
		}
		var body struct {
			To        string `json:"to"`
			Target    string `json:"target"`
			Recipient string `json:"recipient"`
			Message   string `json:"message"`
			Priority  string `json:"priority"`
		}
		if status, err := decodeAirJSON(w, r, &body, maxAirActionJSON); err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		notice := air.Notice{
			Kind: air.NoticeRing, Message: body.Message, Priority: body.Priority,
		}
		if err := notice.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		notice = notice.Normalized()
		logicalTo, err := airLogicalRecipient(body.To, body.Recipient)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		target, status, err := d.resolveActionTarget(r, body.Target, logicalTo, air.ServiceRing)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		if err := d.ring(r.Context(), target, notice); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]string{
			"status": "rung", "target": target, "priority": notice.Priority,
		})
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

// decodeAirJSON decodes one bounded JSON object and rejects trailing values.
// Callers receive 413 for a size violation and 400 for malformed JSON.
func decodeAirJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) (int, error) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", limit)
		}
		return http.StatusBadRequest, fmt.Errorf("invalid JSON body")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", limit)
		}
		return http.StatusBadRequest, fmt.Errorf("request body must contain one JSON object")
	}
	return 0, nil
}

// airLogicalRecipient normalizes the two public names for a logical action
// destination. `recipient` is the universal-action UI contract; `to` is the
// receiver-confirmed action contract. They are aliases, never two independent
// selectors, so accepting both would make the delivery target ambiguous.
func airLogicalRecipient(to, recipient string) (string, error) {
	switch {
	case to != "" && recipient != "":
		return "", fmt.Errorf("to and recipient are aliases; give only one")
	case to != "":
		return to, nil
	default:
		return recipient, nil
	}
}

// resolveActionTarget keeps explicit host:port compatibility while making a
// logical recipient a fail-closed lookup in the browser-attributed Presence
// directory. A failed selector is never retried as a raw address.
func (d airServeDeps) resolveActionTarget(r *http.Request, target, recipient string, kind air.ServiceKind) (string, int, error) {
	target = strings.TrimSpace(target)
	recipient = strings.TrimSpace(recipient)
	if target != "" && recipient != "" {
		return "", http.StatusBadRequest, fmt.Errorf("target and recipient are mutually exclusive")
	}
	if target != "" {
		if !validMeshTarget(target) {
			return "", http.StatusBadRequest, fmt.Errorf("target must be a mesh host:port")
		}
		return target, 0, nil
	}
	if recipient == "" {
		return "", http.StatusBadRequest, fmt.Errorf("target or recipient is required")
	}
	if d.controlBase == "" || d.controlHC == nil {
		return "", http.StatusServiceUnavailable, fmt.Errorf("presence resolver is not configured")
	}
	cards, err := d.loadPresence(r)
	if err != nil {
		return "", http.StatusBadGateway, fmt.Errorf("presence resolver unavailable: %w", err)
	}
	resolved, err := air.ResolvePresence(cards, recipient, kind)
	if err != nil {
		return "", http.StatusBadRequest, err
	}
	if !validMeshTarget(resolved.Service.Address) {
		return "", http.StatusBadGateway, fmt.Errorf("presence resolver returned an invalid %s address", kind)
	}
	return resolved.Service.Address, 0, nil
}

// validMeshTarget reports whether target is a well-formed mesh host:port — a
// syntactic guard so the relay's push/drop/ring cannot be pointed at garbage
// (and, with a bad port, at an unintended local service).
func validMeshTarget(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
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

// loadPresence fetches one bounded, browser-attributed Presence snapshot. It is
// shared by Home and action-time logical recipient resolution.
func (d airServeDeps) loadPresence(r *http.Request) ([]air.Presence, error) {
	if d.controlBase == "" || d.controlHC == nil {
		return nil, fmt.Errorf("no control endpoint configured")
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, d.controlBase+"/v1/presence", nil)
	d.attest(req, r)
	resp, err := d.controlHC.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("presence endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPresenceListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPresenceListBytes {
		return nil, fmt.Errorf("presence response exceeds %d bytes", maxPresenceListBytes)
	}
	var out struct {
		Presence []air.Presence `json:"presence"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("invalid presence response: %w", err)
	}
	return out.Presence, nil
}

// relayPresence fetches identity-stamped Air cards with browser attribution,
// returning nil (an empty section) on any gateway or decoding failure.
func (d airServeDeps) relayPresence(r *http.Request) []air.Presence {
	cards, err := d.loadPresence(r)
	if err != nil {
		return nil
	}
	return cards
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
		return serveGracefully(newAirHTTPServer(*addr, airServeHandler(d)), nil)
	}

	// The privileged endpoints (steer/sessions via --control, push, drop, ring) act
	// with THIS relay's mesh identity: any browser that reaches them borrows
	// the relay's authority. So they are exposed only when --allow names who
	// may use them — the viewer gate then admits only those identities. Without
	// --allow the page is read-only (peers + receipts), never a confused deputy
	// letting an arbitrary mesh peer steer sessions or send actions as the relay.
	privileged := len(allow) > 0
	if *control != "" && !privileged {
		return fmt.Errorf("air serve: --control requires --allow (the browsers permitted to steer or resolve actions through this relay); without it any mesh peer could act with the relay's identity")
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
	// Push/Drop/Ring send over THIS relay's mesh identity (the receiver's ACL and
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
		d.pushConfirmed = func(ctx context.Context, target, expectedKey, name string, data []byte) error {
			dial := verifiedAirDialer(client, target, expectedKey)
			return runDropWithCompletion(ctx, dial, func(w io.Writer) error {
				return sendData(w, name, data)
			}, 1, int64(len(data)), log.Printf)
		}
		d.ring = func(ctx context.Context, target string, notice air.Notice) error {
			return sendNotice(ctx, client, target, notice)
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
	return serveGracefully(newAirHTTPServer("", airServeHandler(d)), ln)
}
