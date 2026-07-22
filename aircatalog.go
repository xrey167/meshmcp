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
	"strings"

	"github.com/xrey167/meshmcp/air"
)

// The Air catalog is an ARD-style (Agentic Resource Discovery) well-known
// document a gateway serves at /.well-known/ai-catalog.json over the mesh: a
// peer asks "what can I reach here?" and gets back the backends its own
// identity is permitted to use. Discovery respects the firewall — the list is
// filtered per-caller by each backend's ACL, so an unprivileged peer discovers
// nothing it could not already call, and an unidentifiable peer discovers
// nothing at all. It is the discovery counterpart to Air's drive verbs.
//
// The catalog model (AirCatalog/AirCatalogEntry) and the ARD DNS logic live in
// the `air` package (aliased in airalias.go); this file is the mesh-wired CLI
// and the gateway's per-caller filtering that binds them to a live mesh.

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
		u, via, err := air.ResolveCatalog(net.LookupTXT, net.LookupSRV, *resolve)
		if err != nil {
			return fmt.Errorf("air catalog: %w", err)
		}
		parsed, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf("air catalog: resolved a bad catalog url %q: %w", u, err)
		}
		// Trust the resolved record only for the host:port — pin the request to
		// the well-known catalog path, so a hostile/hijacked DNS record can't
		// redirect the client to fetch an arbitrary path on a mesh host.
		control = parsed.Host
		catalogURL = parsed.Scheme + "://" + parsed.Host + airCatalogPath
		fmt.Fprintln(os.Stderr, dim("resolved "+*resolve+" → "+catalogURL+" (via "+via+")"))
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

// catalogCaps renders an entry's capabilities as a plain label string. It must
// NOT embed colour codes: the value goes into a table cell whose width is
// measured from plain text and whose colour is applied after padding, so
// pre-coloured text here would both miscount the column width and defeat the
// cell sanitizer.
func catalogCaps(e AirCatalogEntry) string {
	caps := []string{}
	if e.Resumable {
		caps = append(caps, "resumable")
	}
	if e.Steerable {
		caps = append(caps, "steerable")
	}
	if len(caps) == 0 {
		return "—"
	}
	return strings.Join(caps, " · ")
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
