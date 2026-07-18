package main

import (
	"bytes"
	"context"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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

// airServeDeps are the injectable dependencies of the served Air page, so the
// handler is testable with httptest (no mesh).
type airServeDeps struct {
	peers       func() ([]airPeerRow, error) // reachable identities (from client.Status())
	controlHC   *http.Client                 // client that reaches the gateway control endpoint
	controlBase string                       // base URL for the control endpoint (empty = sessions/steer disabled)
}

// airServeHandler builds the live Air page + its /api proxy to the gateway
// control endpoint.
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

	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		if d.controlBase == "" {
			http.Error(w, "no --control endpoint configured", http.StatusServiceUnavailable)
			return
		}
		resp, err := d.controlHC.Get(d.controlBase + "/v1/sessions")
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
		resp, err := d.controlHC.Post(d.controlBase+"/v1/steer", "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		relay(w, resp)
	})

	return mux
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
		d.controlHC = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return client.Dial(ctx, "tcp", *control)
			},
		}}
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "Air (live) on mesh port %d (open it from any device on the mesh)\n", *port)
	return http.Serve(ln, airServeHandler(d))
}
