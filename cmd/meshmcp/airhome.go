package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
)

// cmdAirHome is the home screen of a mesh: one glance shows who's here, what's
// live, and what needs you. It invents no data source — it fuses the ones Air
// already exposes (peers, sessions, catalog, ledger tail, pending approvals)
// into a single at-a-glance board, in both faces Air has: this terminal
// dashboard, and (via --serve) the web page's primary poll.
//
//	meshmcp air home <control-ip:port> [flags]   # terminal dashboard over the mesh
//	meshmcp air home --serve [air serve flags]   # shell into `air serve` (web home)
func cmdAirHome(args []string) error {
	// --serve is a thin, obvious door to the web home: everything after it is
	// `air serve`'s own surface, passed straight through.
	if len(args) > 0 && args[0] == "--serve" {
		return cmdAirServe(args[1:])
	}

	fs := flag.NewFlagSet("air home", flag.ExitOnError)
	o := meshFlags(fs)
	auditPath := fs.String("audit", "", "local audit JSONL to summarize as Recent Activity (newest-first tail)")
	approvals := fs.String("approvals", "", "approvals server (mesh-ip:port) to count pending approvals (your identity must be an approver, else it stays unknown)")
	auditViews := fs.String("audit-views", "", "append one 'air.home' view record per render to this SEPARATE audit chain (opt-in; never the enforcement ledger)")
	watch := fs.Bool("watch", false, "redraw on change instead of printing once (Ctrl-C to stop)")
	interval := fs.Duration("interval", 2*time.Second, "poll cadence for --watch")
	limit := fs.Int("limit", 5, "rows per section in the terminal view")
	asJSON := fs.Bool("json", false, "emit the aggregated Home as JSON (no color, scriptable)")
	resolve := fs.String("resolve", "", "discover the control endpoint from a domain's ARD DNS record instead of a positional address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	control, catalogURL, err := homeControlEndpoint(*resolve, fs.Args())
	if err != nil {
		return err
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	// View-audit sink: opt-in, its OWN hash chain seeded from its OWN file — a
	// view is not an enforcement decision, so it must never interleave into the
	// gateway ledger. Off unless --audit-views names a dedicated file.
	var views *policy.AuditLog
	if *auditViews != "" {
		v, closeViews, err := openViewAudit(*auditViews)
		if err != nil {
			return fmt.Errorf("air home: --audit-views: %w", err)
		}
		defer closeViews()
		views = v
	}

	gather := func() (air.Home, error) {
		return gatherHome(client, control, catalogURL, *approvals, *auditPath, *limit)
	}

	if *watch {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		fmt.Fprintln(os.Stderr, dim("watching ")+bold(control)+dim(" · Ctrl-C to stop"))
		ticker := time.NewTicker(*interval)
		defer ticker.Stop()
		return watchHome(ctx, os.Stdout, gather, ticker.C, func(w io.Writer, h air.Home) {
			renderHomeWatch(w, h, *limit)
			auditView(views, h)
		})
	}

	home, err := gather()
	if err != nil {
		return fmt.Errorf("air home: %w", err)
	}
	if *asJSON {
		b, err := json.MarshalIndent(home, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	renderHome(os.Stdout, home, *limit)
	auditView(views, home)
	return nil
}

// homeControlEndpoint resolves the control endpoint the board fetches over: a
// positional <control-ip:port>, or ARD leg-2 DNS discovery from a domain via
// --resolve (mirroring air catalog / air change). It returns the mesh control
// host and the well-known catalog URL to fetch.
func homeControlEndpoint(resolve string, posArgs []string) (control, catalogURL string, err error) {
	catalogURL = "http://air-control" + airCatalogPath
	switch {
	case resolve != "":
		if len(posArgs) != 0 {
			return "", "", errors.New("air home: give either --resolve <domain> or a <control-ip:port>, not both")
		}
		u, via, rerr := air.ResolveCatalog(net.LookupTXT, net.LookupSRV, resolve)
		if rerr != nil {
			return "", "", fmt.Errorf("air home: %w", rerr)
		}
		parsed, perr := url.Parse(u)
		if perr != nil {
			return "", "", fmt.Errorf("air home: resolved a bad catalog url %q: %w", u, perr)
		}
		// Trust the resolved record only for host:port — pin the request to the
		// well-known catalog path so a hijacked DNS record can't redirect us.
		control = parsed.Host
		catalogURL = parsed.Scheme + "://" + parsed.Host + airCatalogPath
		fmt.Fprintln(os.Stderr, dim("resolved "+resolve+" → "+catalogURL+" (via "+via+")"))
	case len(posArgs) == 1:
		control = posArgs[0]
	default:
		return "", "", errors.New("usage: meshmcp air home [flags] <control-ip:port>  (or --resolve <domain>)")
	}
	return control, catalogURL, nil
}

// gatherHome fans out over the already-wired Air sources and assembles one Home
// as this caller sees it. Every section is best-effort: a source this identity
// may not reach leaves its section empty rather than failing the whole board —
// the home degrades section by section.
func gatherHome(client *embed.Client, control, catalogURL, approvals, auditPath string, limit int) (air.Home, error) {
	h := air.Home{Generated: nowRFC3339(), Pending: -1}

	st, err := client.Status()
	if err != nil {
		return air.Home{}, fmt.Errorf("mesh status: %w", err)
	}
	h.You = air.PeerRow{
		Status: "connected",
		IP:     strings.SplitN(st.LocalPeerState.IP, "/", 2)[0],
		FQDN:   st.LocalPeerState.FQDN,
		PubKey: st.LocalPeerState.PubKey,
	}
	rows := []air.PeerRow{}
	for _, p := range st.Peers {
		connected := strings.EqualFold(fmt.Sprint(p.ConnStatus), "Connected")
		status := "connected"
		if !connected {
			status = strings.ToLower(fmt.Sprint(p.ConnStatus))
		}
		rows = append(rows, air.PeerRow{
			Status: status,
			IP:     strings.SplitN(p.IP, "/", 2)[0],
			FQDN:   p.FQDN,
			PubKey: p.PubKey,
		})
	}
	h.Peers = rows

	hc := meshDialHTTP(client, control)
	if sessions, err := fetchHomeSessions(hc); err == nil {
		h.Sessions = sessions
	}
	if cat, _, err := air.FetchCatalog(hc, catalogURL); err == nil {
		h.Reachable = cat.Endpoints
	}
	if auditPath != "" {
		if acts, err := homeActivity(auditPath, limit); err == nil {
			h.Activity = acts
		}
	}
	// Pending is a COUNT only, over the caller's OWN mesh identity. A non-approver
	// gets 403 from /v1/pending → the count stays unknown (-1). air home never
	// approves or denies; it only counts.
	if approvals != "" {
		if n, err := countPending(meshDialHTTP(client, approvals)); err == nil {
			h.Pending = n
		}
	}

	h.Summary = air.Summarize(h)
	return h, nil
}

// meshDialHTTP returns an http.Client that dials addr over the mesh (the URL
// host is ignored), matching airControlHTTP's transport.
func meshDialHTTP(client *embed.Client, addr string) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return client.Dial(ctx, "tcp", addr)
			},
		},
	}
}

// fetchHomeSessions reads a gateway's live sessions, identical to air sessions.
func fetchHomeSessions(hc *http.Client) ([]air.Session, error) {
	resp, err := hc.Get("http://air-control/v1/sessions")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sessions: %s", resp.Status)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Sessions []air.Session `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Sessions, nil
}

// countPending returns how many approvals are held on an approvals server. It
// counts only; a non-approver identity is refused (403) and the error leaves the
// count unknown to the caller.
func countPending(hc *http.Client) (int, error) {
	resp, err := hc.Get("http://air-approvals/v1/pending")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("pending: %s", resp.Status)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Pending []json.RawMessage `json:"pending"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, err
	}
	return len(out.Pending), nil
}

// homeActivity tails the local audit ledger and returns the newest limit records
// as Receipts, newest first (tailAuditRecords is oldest-first).
func homeActivity(path string, limit int) ([]air.Receipt, error) {
	if limit <= 0 {
		limit = 5
	}
	recs, err := tailAuditRecords(path, limit)
	if err != nil {
		return nil, err
	}
	out := make([]air.Receipt, 0, len(recs))
	for i := len(recs) - 1; i >= 0; i-- {
		if r, ok := air.ParseReceipt(recs[i]); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

// openViewAudit opens path as a SEPARATE tamper-evident view-audit chain,
// seeding from its own tail so restarts continue the same chain (never the
// gateway enforcement ledger). It returns the log and a closer for its file.
func openViewAudit(path string) (*policy.AuditLog, func(), error) {
	seq, last, err := seedAuditFromExisting(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	log := policy.NewAuditLog(f, nowRFC3339)
	log.SeedFrom(seq, last)
	return log, func() { _ = f.Close() }, nil
}

// auditView appends one 'air.home' record to the SEPARATE view chain, attributed
// to the viewer's own mesh identity, so "who looked at the mesh, and when" is
// provable. A no-op when view-auditing was not opted into.
func auditView(views *policy.AuditLog, h air.Home) {
	if views == nil {
		return
	}
	_ = views.Append(policy.AuditRecord{
		Peer:     h.You.FQDN,
		PeerKey:  h.You.PubKey,
		Method:   "air.home",
		Decision: "allow",
		Rule:     -1,
		Reason: fmt.Sprintf("view peers=%d sessions=%d pending=%d",
			h.Summary.PeersOnline, h.Summary.Sessions, h.Summary.Pending),
	})
}

// watchHome redraws the board only when the Home signature changes — the
// terminal analog of the page's changed(el, sig). It draws once immediately,
// then re-polls on each tick, skipping identical state. It returns when ctx is
// done or the tick channel closes. Injectable poll/ticks/render keep it testable
// without a mesh or a real clock.
func watchHome(ctx context.Context, w io.Writer, poll func() (air.Home, error), ticks <-chan time.Time, render func(io.Writer, air.Home)) error {
	prev := ""
	draw := func() error {
		h, err := poll()
		if err != nil {
			return err
		}
		if sig := h.Signature(); sig != prev {
			prev = sig
			render(w, h)
		}
		return nil
	}
	if err := draw(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ticks:
			if !ok {
				return nil
			}
			if err := draw(); err != nil {
				return err
			}
		}
	}
}

// renderHomeWatch clears the screen (only on a real terminal) before redrawing,
// so --watch repaints in place instead of scrolling.
func renderHomeWatch(w io.Writer, h air.Home, limit int) {
	if colorOn {
		_, _ = io.WriteString(w, "\x1b[H\x1b[2J")
	}
	renderHome(w, h, limit)
}

// renderHome draws the terminal board. It is pure (no mesh), so it is
// unit-testable; every dynamic cell passes through sanitizeCell (via the style
// helpers / formatStreamRow), so a hostile peer FQDN, tool, or reason cannot
// inject terminal escapes. Colour is applied only when enabled.
func renderHome(w io.Writer, h air.Home, limit int) {
	you := h.You.FQDN
	if you == "" {
		you = h.You.IP
	}
	if you == "" {
		you = "you"
	}
	fmt.Fprintln(w, dim("you  ")+bold(sanitizeCell(you))+dim("  ("+sanitizeCell(h.You.IP)+")"))
	fmt.Fprintln(w, homeHero(h.Summary))

	fmt.Fprintln(w)
	fmt.Fprintln(w, dim("PEERS"))
	if len(h.Peers) == 0 {
		fmt.Fprintln(w, dim("  no peers reachable"))
	} else {
		var rows [][]cell
		for _, p := range firstN(h.Peers, limit) {
			label := p.FQDN
			if label == "" {
				label = p.IP
			}
			rows = append(rows, []cell{
				statusDot(p.Status == "connected", p.Status),
				styled(label, bold),
				plain(p.IP),
				styled(shortKey(p.PubKey), dim),
			})
		}
		renderTable(w, []string{"status", "peer", "ip", "key"}, rows)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, dim("LIVE SESSIONS"))
	if len(h.Sessions) == 0 {
		fmt.Fprintln(w, dim("  no live sessions"))
	} else {
		var rows [][]cell
		for _, s := range firstN(h.Sessions, limit) {
			rows = append(rows, []cell{
				styled(s.Backend, bold),
				styled(s.ID, cyan),
				plain(s.Peer),
				styled(humanAge(s.AgeSec), dim),
			})
		}
		renderTable(w, []string{"backend", "session", "peer", "age"}, rows)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, dim("REACHABLE"))
	if len(h.Reachable) == 0 {
		fmt.Fprintln(w, dim("  no backends you may reach"))
	} else {
		var rows [][]cell
		for _, e := range firstN(h.Reachable, limit) {
			rows = append(rows, []cell{
				styled(e.Name, bold),
				styled(catalogID(e), dim),
				plain(catalogType(e)),
				plain(catalogOwner(e)),
				styled(e.Address, cyan),
				plain(catalogState(e)),
				plain(catalogCaps(e)),
			})
		}
		renderTable(w, []string{"component", "id", "type", "owner", "address", "state", "features"}, rows)
	}

	if h.Showing != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, dim("NOW SHOWING"))
		age := humanAge(int(time.Now().Unix() - h.Showing.ModUnix))
		fmt.Fprintln(w, "  "+bold(sanitizeCell(h.Showing.Name))+dim("  · "+age))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, dim("RECENT ACTIVITY"))
	if len(h.Activity) == 0 {
		fmt.Fprintln(w, dim("  nothing recent"))
	} else {
		for _, r := range firstN(h.Activity, limit) {
			fmt.Fprintln(w, "  "+formatStreamRow(r))
		}
	}
}

// homeHero renders the one-line hero: the counts that answer the question. An
// unknown pending count (-1, this caller is not an approver) reads as a dash,
// never a misleading zero.
func homeHero(s air.HomeSummary) string {
	parts := []string{
		green(fmt.Sprintf("● %d online", s.PeersOnline)) + dim(fmt.Sprintf(" / %d peers", s.PeersTotal)),
		fmt.Sprintf("%d sessions", s.Sessions),
		fmt.Sprintf("%d reachable", s.Reachable),
	}
	switch {
	case s.Pending < 0:
		parts = append(parts, dim("— pending"))
	case s.Pending > 0:
		parts = append(parts, amber(fmt.Sprintf("⏸ %d waiting", s.Pending)))
	default:
		parts = append(parts, dim("0 waiting"))
	}
	if s.Denies1h > 0 {
		parts = append(parts, red(fmt.Sprintf("%d denied·1h", s.Denies1h)))
	}
	return strings.Join(parts, dim("  ·  "))
}

// firstN returns the first n elements of s, or all of s when n <= 0 or s is
// shorter — the per-section row cap for the terminal view.
func firstN[T any](s []T, n int) []T {
	if n > 0 && len(s) > n {
		return s[:n]
	}
	return s
}
