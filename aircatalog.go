package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
)

// The Air catalog is an ARD-style (Agentic Resource Discovery) well-known
// document a gateway serves at /.well-known/ai-catalog.json over the mesh: a
// peer asks "what can I reach here?" and gets back the backends its own
// identity is permitted to use. Discovery respects the firewall — the list is
// filtered per-caller by each backend's ACL, so an unprivileged peer discovers
// nothing it could not already call, and an unidentifiable peer discovers
// nothing at all. It is the discovery counterpart to Air's drive verbs.

// airCatalogPath is the standard well-known discovery URL, mirroring the ARD
// spec's /.well-known/ai-catalog.json.
const airCatalogPath = "/.well-known/ai-catalog.json"

// AirCatalog is the discovery document: the service, its version, the gateway
// identity, and the endpoints the calling identity may reach.
type AirCatalog struct {
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	Gateway   string            `json:"gateway,omitempty"`
	Endpoints []AirCatalogEntry `json:"endpoints"`
}

// AirCatalogEntry is one discoverable backend: how to address it and what it
// supports, so a client knows whether it can list tools, resume, or be steered.
type AirCatalogEntry struct {
	Name      string `json:"name"`
	Address   string `json:"address"`   // mesh-ip:port to dial
	Transport string `json:"transport"` // stdio | http | remote
	Resumable bool   `json:"resumable,omitempty"`
	Steerable bool   `json:"steerable,omitempty"` // has a live session server (Air · Steer)
}

// catalogBackend is a gateway's static per-backend catalog data, captured at
// startup; steerability is resolved live from the session-server map.
type catalogBackend struct {
	name, address, transport string
	resumable                bool
}

// cmdAirCatalog fetches and renders a gateway's Air catalog — the discovery
// view. It dials the gateway's control endpoint over the mesh (the URL host is
// ignored) exactly like `air sessions`.
func cmdAirCatalog(args []string) error {
	fs := flag.NewFlagSet("air catalog", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the raw catalog JSON instead of a table")
	resolve := fs.String("resolve", "", "discover the control endpoint from a domain's ARD DNS record instead of a positional address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Two ways in: a known control address, or ARD leg-2 DNS discovery from a
	// domain name (the `--resolve` bootstrap). Resolution yields a catalog URL
	// whose mesh host:port is the control endpoint we then dial over the mesh.
	control, catalogURL := "", "http://air-control"+airCatalogPath
	switch {
	case *resolve != "":
		if fs.NArg() != 0 {
			return errors.New("air catalog: give either --resolve <domain> or a <control-ip:port>, not both")
		}
		u, via, err := resolveCatalog(net.LookupTXT, net.LookupSRV, *resolve)
		if err != nil {
			return fmt.Errorf("air catalog: %w", err)
		}
		parsed, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf("air catalog: resolved a bad catalog url %q: %w", u, err)
		}
		control, catalogURL = parsed.Host, u
		fmt.Fprintln(os.Stderr, dim("resolved "+*resolve+" → "+u+" (via "+via+")"))
	case fs.NArg() == 1:
		control = fs.Arg(0)
	default:
		return errors.New("usage: meshmcp air catalog [flags] <control-ip:port>  (or --resolve <domain>)")
	}

	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	resp, err := hc.Get(catalogURL)
	if err != nil {
		return fmt.Errorf("air catalog: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air catalog: %s: %s", resp.Status, body)
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
	}
	var cat AirCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return fmt.Errorf("air catalog: bad response: %w", err)
	}
	if cat.Gateway != "" {
		fmt.Fprintln(os.Stderr, dim("gateway ")+bold(cat.Gateway)+dim(" · "+cat.Service+" "+cat.Version))
	}
	if len(cat.Endpoints) == 0 {
		fmt.Fprintln(os.Stderr, dim("no endpoints you may reach here"))
		return nil
	}
	var rows [][]cell
	for _, e := range cat.Endpoints {
		rows = append(rows, []cell{
			styled(e.Name, bold),
			styled(e.Address, cyan),
			plain(e.Transport),
			plain(catalogCaps(e)),
		})
	}
	renderTable(os.Stdout, []string{"backend", "address", "transport", "supports"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d reachable endpoint(s)", len(rows))))
	return nil
}

// catalogCaps renders an entry's capabilities as small labels.
func catalogCaps(e AirCatalogEntry) string {
	caps := []string{}
	if e.Resumable {
		caps = append(caps, green("resumable"))
	}
	if e.Steerable {
		caps = append(caps, blue("steerable"))
	}
	if len(caps) == 0 {
		return dim("—")
	}
	out := caps[0]
	for _, c := range caps[1:] {
		out += " " + c
	}
	return out
}

// buildCatalogBackends captures the static catalog data for a gateway's
// configured backends: address (meshIP:port) and transport kind. Steerability
// is resolved live from the running session-server map, not here.
func buildCatalogBackends(backends []*Backend, meshIP string) []catalogBackend {
	out := make([]catalogBackend, 0, len(backends))
	for _, b := range backends {
		transport := "stdio"
		if b.HTTP != "" {
			transport = "http"
		}
		addr := fmt.Sprintf("%s:%d", meshIP, b.Port)
		out = append(out, catalogBackend{name: b.Name, address: addr, transport: transport, resumable: b.Resumable})
	}
	return out
}

// writeCatalog is a tiny convenience the handler uses; kept here so the
// discovery response shape lives with the catalog types.
func writeCatalog(w http.ResponseWriter, cat AirCatalog) {
	if cat.Endpoints == nil {
		cat.Endpoints = []AirCatalogEntry{}
	}
	writeJSONResp(w, http.StatusOK, cat)
}
