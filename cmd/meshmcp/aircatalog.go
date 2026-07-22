package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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

// cmdAirCatalog fetches and renders a gateway's Air catalog — the discovery
// view. It dials the gateway's control endpoint over the mesh (the URL host is
// ignored) exactly like `air sessions`.
func cmdAirCatalog(args []string) error {
	fs := flag.NewFlagSet("air catalog", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the raw catalog JSON instead of a table")
	resolve := fs.String("resolve", "", "discover the control endpoint from a domain's ARD DNS record instead of a positional address")
	steerable := fs.Bool("steerable", false, "show only backends you can steer (Air · Steer)")
	resumable := fs.Bool("resumable", false, "show only backends whose sessions survive a reconnect")
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

	cat, body, err := air.FetchCatalog(hc, catalogURL)
	if err != nil {
		return fmt.Errorf("air catalog: %w", err)
	}
	// Optional filters, using the module's discovery helpers. --json prints the
	// full raw response (a filtered view is a human aid, not a wire format).
	switch {
	case *steerable:
		cat.Endpoints = cat.Steerable()
	case *resumable:
		cat.Endpoints = cat.Resumable()
	}
	if *asJSON {
		if *steerable || *resumable {
			b, err := json.MarshalIndent(cat, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		}
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
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
			styled(catalogID(e), dim),
			plain(catalogType(e)),
			plain(catalogOwner(e)),
			styled(e.Address, cyan),
			plain(e.Transport),
			plain(catalogState(e)),
			plain(catalogCaps(e)),
		})
	}
	renderTable(os.Stdout, []string{"component", "id", "type", "owner", "address", "transport", "state", "features"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d reachable component(s)", len(rows))))
	return nil
}

// catalogCaps renders an entry's capabilities as a plain label string. It must
// NOT embed colour codes: the value goes into a table cell whose width is
// measured from plain text and whose colour is applied after padding, so
// pre-coloured text here would both miscount the column width and defeat the
// cell sanitizer.
func catalogCaps(e AirCatalogEntry) string {
	features, err := air.NormalizeFeatures(e.Features)
	if err != nil {
		features = e.Features
	}
	caps, seen := []string{}, map[string]bool{}
	add := func(label string) {
		if label != "" && !seen[label] {
			seen[label] = true
			caps = append(caps, label)
		}
	}
	for _, feature := range features {
		add(catalogFeatureLabel(feature))
	}
	// Legacy catalogs have only these booleans. Keep their familiar labels
	// while component cards converge on the versioned feature vocabulary.
	if e.Resumable {
		add("resumable")
	}
	if e.Steerable {
		add("steerable")
	}
	if len(caps) == 0 {
		return "—"
	}
	return strings.Join(caps, " · ")
}

func catalogFeatureLabel(feature air.Feature) string {
	label := feature.Name
	switch feature.Name {
	case air.FeatureMCP20250618:
		label = "mcp 2025-06-18"
	case air.FeatureAirBrowseV1:
		label = "browse"
	case air.FeatureAirResumeV1:
		label = "resumable"
	case air.FeatureAirSteerV1:
		label = "steerable"
	case air.FeatureCapabilityV1:
		label = "capability auth"
	}
	if feature.Version != "" {
		label += "@" + feature.Version
	}
	return label
}

func catalogKind(e AirCatalogEntry) string {
	if e.Kind == "" {
		return "backend"
	}
	return string(e.Kind)
}

func catalogVersion(e AirCatalogEntry) string {
	if e.Version == "" {
		return "—"
	}
	return e.Version
}

func catalogID(e AirCatalogEntry) string {
	if e.ID == "" {
		return "—"
	}
	return e.ID
}

func catalogType(e AirCatalogEntry) string {
	t := catalogKind(e)
	if e.Version != "" {
		t += "@" + e.Version
	}
	return t
}

func catalogOwner(e AirCatalogEntry) string {
	switch {
	case e.Owner.FQDN != "":
		return e.Owner.FQDN
	case e.Owner.PubKey != "":
		return shortKey(e.Owner.PubKey)
	case e.Owner.SPIFFE != "":
		return e.Owner.SPIFFE
	default:
		return "—"
	}
}

func catalogState(e AirCatalogEntry) string {
	if e.Lifecycle.State == "" {
		return "unknown"
	}
	return string(e.Lifecycle.State)
}

// buildCatalogBackends creates the gateway's canonical component cards. The
// same cards feed HTTP discovery, Air Home/Map/Change, and the MCP app. Live
// steerability is added by gatewayAirControl.catalog; every other advertised
// feature comes from real configured behavior. Cards are descriptive only:
// the transport identity, backend ACL, policy, and capability verifier still
// decide whether an operation is authorized.
func buildCatalogBackends(backends []*Backend, meshIP string, owner air.IdentityRef) ([]AirCatalogEntry, error) {
	if owner.PubKey == "" {
		return nil, errors.New("component cards require the gateway mesh public key")
	}
	out := make([]AirCatalogEntry, 0, len(backends))
	seenIDs := make(map[string]string, len(backends))
	since := time.Now().UTC().Format(time.RFC3339Nano)
	for _, b := range backends {
		transport := air.TransportStdio
		switch {
		case b.Remote != nil:
			transport = air.TransportRemote
		case b.HTTP != "":
			transport = air.TransportHTTP
		}

		id := b.ID
		if id == "" {
			var err error
			id, err = air.StableComponentID(owner.PubKey, air.ComponentBackend, b.Name)
			if err != nil {
				return nil, fmt.Errorf("backend %q: derive component id: %w", b.Name, err)
			}
		}
		features := []air.Feature{
			{Name: air.FeatureMCP20250618},
			{Name: air.FeatureAirBrowseV1},
		}
		if b.Resumable {
			features = append(features, air.Feature{Name: air.FeatureAirResumeV1})
		}
		if b.Capabilities != nil {
			features = append(features, air.Feature{Name: air.FeatureCapabilityV1})
		}
		entry, err := (AirCatalogEntry{
			ID:        id,
			Kind:      air.ComponentBackend,
			Name:      b.Name,
			Version:   b.Version,
			Owner:     owner,
			Address:   net.JoinHostPort(meshIP, fmt.Sprintf("%d", b.Port)),
			Transport: transport,
			Features:  features,
			Lifecycle: air.Lifecycle{State: air.LifecycleServing, Since: since},
			Resumable: b.Resumable,
		}).Normalized()
		if err != nil {
			return nil, fmt.Errorf("backend %q: component card: %w", b.Name, err)
		}
		if other, duplicate := seenIDs[entry.ID]; duplicate {
			return nil, fmt.Errorf("backend %q: component id %q collides with backend %q", b.Name, entry.ID, other)
		}
		seenIDs[entry.ID] = b.Name
		out = append(out, entry)
	}
	return out, nil
}

// writeCatalog is a tiny convenience the handler uses; kept here so the
// discovery response shape lives with the catalog types.
func writeCatalog(w http.ResponseWriter, cat AirCatalog) {
	if cat.Endpoints == nil {
		cat.Endpoints = []AirCatalogEntry{}
	}
	writeJSONResp(w, http.StatusOK, cat)
}
