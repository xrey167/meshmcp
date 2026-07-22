package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/air/knowstore"
	"github.com/xrey167/meshmcp/kg"
	"github.com/xrey167/meshmcp/policy"
)

// The air-kg served endpoint hosts the single-writer knowstore.Facade over a
// local kg.Store and exposes its governed ops over mesh-HTTP: assert (write),
// query, neighbors, and k-hop subgraph. It mirrors the Air control endpoint
// (aircontrol.go): it listens only on the mesh, resolves each caller's WireGuard
// identity, and gates who may reach it on an ACL. The corpus-level authorization
// — deny-by-default, exact-literal writes — is NOT re-implemented here; it lives
// entirely in the facade, which every request is routed through with the caller's
// per-call capability claims. So there is exactly one auth path and one audit
// path, both the shared spine's.
//
// Two layers, by design:
//   - Reachability (this file's ACL): who may talk to the endpoint at all. An
//     unidentifiable or un-allowed peer is refused 403 before the store is
//     touched, and the refusal is audited on the same chain.
//   - Corpus authorization (the facade, via air/know.Allowed): what a reachable
//     caller may actually read or write, derived per-call from its granted
//     corpora — never from a tool argument or a per-session env snapshot.

// kgGrant maps a caller identity pattern to the corpora it is granted. The
// pattern matches like an acl entry: "pubkey:<key>" for an exact WireGuard key,
// otherwise an FQDN glob. The corpora become the caller's CapabilityClaims.Corpora
// for every request it makes, so know.Allowed can enforce deny-by-default (empty
// grant shares nothing) and exact-literal writes against them.
type kgGrant struct {
	pattern string
	corpora []string
}

// kgGrants is the operator's full identity→corpora policy for one endpoint. It is
// set by the operator (via --grant), never by any caller, mirroring the acl and
// TrustMap posture: authorization is policy, not payload.
type kgGrants []kgGrant

// corporaFor returns the union of corpora granted to a caller across every
// matching pattern, deny-by-default: an unidentifiable caller, or one no pattern
// matches, gets an empty grant — which know.Allowed rejects for every op.
func (g kgGrants) corporaFor(pubKey, fqdn string) []string {
	if pubKey == "" && fqdn == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range g {
		if !kgPatternMatches(e.pattern, pubKey, fqdn) {
			continue
		}
		for _, c := range e.corpora {
			if c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// kgPatternMatches reports whether one grant pattern covers a caller identity —
// the same matching acl.allows uses for a single pattern (a "pubkey:" prefix is
// an exact key match; anything else is an FQDN glob).
func kgPatternMatches(pattern, pubKey, fqdn string) bool {
	if key, ok := strings.CutPrefix(pattern, "pubkey:"); ok {
		return key != "" && key == pubKey
	}
	ok, _ := path.Match(pattern, fqdn)
	return ok
}

// kgCaller builds the verified knowstore.Caller for a resolved identity: its
// granted corpora as capability claims, and its mesh identity to stamp as
// provenance. Peer prefers the human-readable FQDN and falls back to the public
// key, so a key-only peer still stamps a non-empty asserting identity (the
// reachability gate has already rejected the fully-unidentifiable caller).
func kgCaller(pubKey, fqdn string, grants kgGrants) knowstore.Caller {
	peer := fqdn
	if peer == "" {
		peer = pubKey
	}
	return knowstore.Caller{
		Claims:  policy.CapabilityClaims{Corpora: grants.corporaFor(pubKey, fqdn)},
		Peer:    peer,
		PeerKey: pubKey,
	}
}

// kgControlHandler builds the air-kg mesh-HTTP surface over the facade. identify
// resolves the caller's (pubkey, fqdn); allow gates reachability; grants maps the
// caller to its corpora; audit records reachability refusals on the shared chain
// (the facade audits every governed op itself, so the two land on one ledger).
func kgControlHandler(f *knowstore.Facade, identify func(*http.Request) (pubkey, fqdn string), allow acl, grants kgGrants, audit policy.AuditSink) http.Handler {
	mux := http.NewServeMux()

	// reach resolves and gates the caller. On refusal it writes the 403, audits a
	// deny, and returns ok=false so the route handler stops. The corpus (if the
	// request named one) is recorded so a refused attempt is attributable to what
	// it tried to touch.
	reach := func(w http.ResponseWriter, r *http.Request, corpus string) (pubKey, fqdn string, ok bool) {
		pubKey, fqdn = identify(r)
		if !allow.allows(pubKey, fqdn) {
			if audit != nil {
				_ = audit.Append(know.Retrieve(know.Event{
					Peer: fqdnOr(fqdn), PeerKey: pubKey, Corpus: corpus,
					Decision: "deny", Reason: "air-kg endpoint ACL: caller not permitted",
				}))
			}
			http.Error(w, "not permitted", http.StatusForbidden)
			return "", "", false
		}
		return pubKey, fqdn, true
	}

	mux.HandleFunc("/v1/kg/assert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var body kgAssertBody
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.Corpus == "" || body.S == "" || body.P == "" || body.O == "" {
			http.Error(w, "corpus, s, p and o are all required", http.StatusBadRequest)
			return
		}
		pubKey, fqdn, ok := reach(w, r, body.Corpus)
		if !ok {
			return
		}
		caller := kgCaller(pubKey, fqdn, grants)
		receipt, err := f.Assert(caller, knowstore.AssertRequest{
			Corpus: body.Corpus, S: body.S, P: body.P, O: body.O,
			Source: body.Source, ValidFrom: body.ValidFrom,
		})
		if err != nil {
			writeKGError(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, receipt)
	})

	mux.HandleFunc("/v1/kg/query", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		q := r.URL.Query()
		corpus := q.Get("corpus")
		if corpus == "" {
			http.Error(w, "corpus is required", http.StatusBadRequest)
			return
		}
		pubKey, fqdn, ok := reach(w, r, corpus)
		if !ok {
			return
		}
		recs, err := f.Query(kgCaller(pubKey, fqdn, grants), corpus, q.Get("s"), q.Get("p"), q.Get("o"), kgAsOf(q.Get("as_of")))
		if err != nil {
			writeKGError(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, kgRecordsResp{Records: nonNilRecords(recs)})
	})

	mux.HandleFunc("/v1/kg/neighbors", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		q := r.URL.Query()
		corpus, node := q.Get("corpus"), q.Get("node")
		if corpus == "" || node == "" {
			http.Error(w, "corpus and node are required", http.StatusBadRequest)
			return
		}
		pubKey, fqdn, ok := reach(w, r, corpus)
		if !ok {
			return
		}
		recs, err := f.Neighbors(kgCaller(pubKey, fqdn, grants), corpus, node, kgAsOf(q.Get("as_of")))
		if err != nil {
			writeKGError(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, kgRecordsResp{Records: nonNilRecords(recs)})
	})

	mux.HandleFunc("/v1/kg/subgraph", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		q := r.URL.Query()
		corpus, seed := q.Get("corpus"), q.Get("seed")
		if corpus == "" || seed == "" {
			http.Error(w, "corpus and seed are required", http.StatusBadRequest)
			return
		}
		pubKey, fqdn, ok := reach(w, r, corpus)
		if !ok {
			return
		}
		// One governed read of the corpus's active set (audited, deny-by-default),
		// then a pure bounded k-hop assembly over it — so traversal fan-out is
		// bounded in the air layer while authorization stays entirely in the facade.
		recs, err := f.Query(kgCaller(pubKey, fqdn, grants), corpus, "", "", "", kgAsOf(q.Get("as_of")))
		if err != nil {
			writeKGError(w, err)
			return
		}
		sg := air.Subgraph(recordsToTriples(recs), seed, kgHops(q.Get("hops")), kgMax(q.Get("max")))
		writeJSONResp(w, http.StatusOK, sg)
	})

	mux.HandleFunc("/v1/kg/verify", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		if _, _, ok := reach(w, r, ""); !ok {
			return
		}
		// Ungoverned integrity check: it proves the chain is intact, revealing no
		// facts, so it needs only reachability, not a corpus grant.
		errStr := ""
		if err := f.Verify(); err != nil {
			errStr = err.Error()
		}
		writeJSONResp(w, http.StatusOK, kgVerifyResp{OK: errStr == "", Head: f.Head(), Error: errStr})
	})

	return mux
}

// writeKGError maps a facade error to a status: a capability denial is a 403 (the
// caller is reachable but not authorized for that corpus), everything else a 400
// (bad input) or 502-ish store fault surfaced as 500.
func writeKGError(w http.ResponseWriter, err error) {
	if errors.Is(err, knowstore.ErrDenied) {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// recordsToTriples projects governed kg.Records onto the pure air.KGTriple shape
// the subgraph assembler walks (dropping chain internals it must not depend on).
func recordsToTriples(recs []kg.Record) []air.KGTriple {
	out := make([]air.KGTriple, 0, len(recs))
	for _, r := range recs {
		out = append(out, air.KGTriple{S: r.S, P: r.P, O: r.O, Peer: r.Peer})
	}
	return out
}

// nonNilRecords normalizes a nil slice to an empty one so the JSON response
// always carries a [] rather than null.
func nonNilRecords(recs []kg.Record) []kg.Record {
	if recs == nil {
		return []kg.Record{}
	}
	return recs
}

// kgAsOf parses an as-of sequence cursor; a blank or malformed value means "now"
// (0), matching the store's time-travel contract (asOf <= 0 = head).
func kgAsOf(s string) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return 0
}

// kgHops parses the subgraph depth, defaulting to 2 and clamping the ceiling so a
// caller cannot request an unboundedly deep walk.
func kgHops(s string) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		if n > kgMaxHops {
			return kgMaxHops
		}
		return n
	}
	return kgDefaultHops
}

// kgMax parses the subgraph fan-out cap, defaulting when blank and clamping the
// ceiling so one call cannot return an unbounded neighborhood.
func kgMax(s string) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		if n > kgMaxFanout {
			return kgMaxFanout
		}
		return n
	}
	return kgDefaultMax
}

const (
	kgDefaultHops = 2
	kgMaxHops     = 6
	kgDefaultMax  = 200
	kgMaxFanout   = 2000
)

// cmdAirKGServe runs the governed knowledge-graph backend over the mesh: one
// serialized writer (the facade) over a local kg.jsonl, with every op audited to
// the shared ledger and gated on the caller's granted corpora.
func cmdAirKGServe(args []string) error {
	fs := flag.NewFlagSet("air kg serve", flag.ExitOnError)
	o := meshFlags(fs)
	port := fs.Int("port", 7100, "mesh port to serve the air-kg endpoint on")
	store := fs.String("store", "kg.jsonl", "path to the knowledge-graph log (created if absent)")
	auditPath := fs.String("audit", "", "audit ledger to append every governed op to (hash-chained; strongly recommended)")
	allow := multiFlag{}
	fs.Var(&allow, "allow", "identity permitted to reach the endpoint (FQDN glob or pubkey:<key>); repeatable; REQUIRED")
	grantFlags := multiFlag{}
	fs.Var(&grantFlags, "grant", "corpus grant: <id>=<corpus>[,<corpus>...] where <id> is an FQDN glob or pubkey:<key> (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Writes are privileged: without an --allow list any mesh peer could reach the
	// write surface, so require it (the per-corpus grant then decides what each
	// reachable caller may actually do). Mirrors `air serve --control` requiring
	// --allow before it exposes the relay's authority.
	if len(allow) == 0 {
		return fmt.Errorf("air kg serve: --allow is required (the identities permitted to reach the governed KG); without it any mesh peer could attempt writes")
	}
	grants, err := parseKGGrants(grantFlags)
	if err != nil {
		return fmt.Errorf("air kg serve: %w", err)
	}

	st, err := kg.Open(*store, nowRFC3339)
	if err != nil {
		return fmt.Errorf("air kg serve: open store %s: %w", *store, err)
	}

	audit, closeAudit, err := openKGAudit(*auditPath, nowRFC3339)
	if err != nil {
		return fmt.Errorf("air kg serve: %w", err)
	}
	defer closeAudit()
	if audit == nil {
		fmt.Fprintln(os.Stderr, amber("warning:")+" --audit not set; governed ops run un-recorded. Pass --audit <file> for a tamper-evident ledger.")
	}

	facade := knowstore.New(st, audit)

	o.BlockInbound = false // we listen for callers on the mesh
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	identify := func(r *http.Request) (string, string) { return peerIdentityStr(client, r.RemoteAddr) }
	h := kgControlHandler(facade, identify, newACL(allow), grants, audit)

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("air kg serve: listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "air-kg on mesh port %d (POST /v1/kg/assert · GET /v1/kg/query · /v1/kg/neighbors · /v1/kg/subgraph · /v1/kg/verify)\n", *port)
	fmt.Fprintf(os.Stderr, dim("store %s · %d grant(s) · allow %v\n"), *store, len(grants), []string(allow))
	// Read/header timeouts even on the mesh so an admitted peer cannot hold the
	// listener open with a slow request (Slowloris), matching the control endpoint.
	return newLocalHTTPServer("", h).Serve(ln)
}

// parseKGGrants parses --grant "<id>=<corpus>[,<corpus>...]" flags into the
// operator's identity→corpora policy. A malformed entry is a hard error so a
// typo'd grant never silently widens or narrows access.
func parseKGGrants(flags []string) (kgGrants, error) {
	var grants kgGrants
	for _, raw := range flags {
		id, list, ok := strings.Cut(raw, "=")
		if !ok || id == "" {
			return nil, fmt.Errorf("bad --grant %q: want <id>=<corpus>[,<corpus>...]", raw)
		}
		var corpora []string
		for _, c := range strings.Split(list, ",") {
			if c = strings.TrimSpace(c); c != "" {
				corpora = append(corpora, c)
			}
		}
		if len(corpora) == 0 {
			return nil, fmt.Errorf("bad --grant %q: no corpora listed", raw)
		}
		grants = append(grants, kgGrant{pattern: id, corpora: corpora})
	}
	return grants, nil
}

// openKGAudit opens (or continues) the hash-chained audit ledger at path,
// returning a nil sink when no path is set (the facade then no-ops audit). It
// reuses the gateway's seed-then-append pattern so restarts extend the chain
// rather than resetting it.
func openKGAudit(path string, now func() string) (policy.AuditSink, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	seq, lastHash, err := seedAuditFromExisting(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("audit ledger: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open audit ledger %s: %w", path, err)
	}
	log := policy.NewAuditLog(f, now)
	if seq > 0 {
		log.SeedFrom(seq, lastHash)
	}
	return log, func() { _ = f.Close() }, nil
}
