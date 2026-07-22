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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/session"
)

//go:embed site/air-live.html
var airLiveHTML []byte

// airPeerRow is one reachable mesh identity in the served Air page.
type airPeerRow struct {
	Status string `json:"status"`
	IP     string `json:"ip"`
	FQDN   string `json:"fqdn"`
	PubKey string `json:"pubkey"`
}

// maxAirUpload bounds a browser Drop/Push payload accepted by the served page.
const maxAirUpload = 8 << 20

// airServeDeps are the injectable dependencies of the served Air page, so the
// handler is testable with httptest (no mesh).
type airServeDeps struct {
	peers       func() ([]airPeerRow, error)              // reachable identities (from client.Status())
	identify    func(*http.Request) (pubkey, fqdn string) // resolve the browser's own mesh identity (nil = none)
	controlHC   *http.Client                              // client that reaches the gateway control endpoint
	controlBase string                                    // base URL for the control endpoint (empty = sessions/steer disabled)

	push      func(ctx context.Context, target, name string, data []byte) error // deliver a payload to a peer's drop inbox (nil = push/drop disabled)
	receipts  func(limit int) ([]json.RawMessage, error)                        // tail of the local audit ledger (nil = receipts disabled)
	approvals string                                                            // approvals server (mesh-ip:port) the page links out to ("" = hidden)
	allow     acl                                                               // page-wide viewer ACL; empty = any mesh peer
}

// airServeHandler builds the live Air page + its /api surface: proxied
// sessions/steer, relay-sent push/drop, a receipts tail, and an approvals link.
func airServeHandler(d airServeDeps) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(airLiveHTML)
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResp(w, http.StatusOK, map[string]any{
			"approvals": d.approvals,
			"push":      d.push != nil,
			"receipts":  d.receipts != nil,
		})
	})

	mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
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
		name := body.Name
		if name == "" {
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

	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
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
	if d.allow.empty() || d.identify == nil {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pubKey, fqdn := d.identify(r)
		if !d.allow.allows(pubKey, fqdn) {
			http.Error(w, "not permitted", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
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
	allow := multiFlag{}
	fs.Var(&allow, "allow", "identity permitted to open the page (FQDN glob or pubkey:<key>); repeatable; empty = any mesh peer")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Local/dev mode: serve the page without joining the mesh.
	if *addr != "" {
		d := airServeDeps{peers: func() ([]airPeerRow, error) { return nil, nil }}
		fmt.Fprintf(os.Stderr, "Air (live) on http://%s (LOCAL — no mesh; peers/sessions unavailable)\n", *addr)
		return http.ListenAndServe(*addr, airServeHandler(d))
	}

	o.BlockInbound = false // we listen for browsers on the mesh
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	d := airServeDeps{
		approvals: *approvals,
		allow:     newACL(allow),
		// The browser is itself a mesh peer; resolve its WireGuard identity so
		// steers it drives are attributed to the human, not this relay.
		identify: func(r *http.Request) (string, string) { return peerIdentityStr(client, r.RemoteAddr) },
		// Push/Drop send over THIS relay's mesh identity (the receiver's ACL and
		// audit see the air-serve node); the browser identity is the page viewer.
		push: func(ctx context.Context, target, name string, data []byte) error {
			pr, pw := io.Pipe()
			go func() { pw.CloseWithError(sendData(pw, name, data)) }()
			dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
			return session.NewClient(dial, log.Printf).Run(ctx, sendStream{r: pr})
		},
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

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "Air (live) on mesh port %d (open it from any device on the mesh)\n", *port)
	return http.Serve(ln, airServeHandler(d))
}
