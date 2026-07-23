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
	"github.com/xrey167/meshmcp/federation"
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

// kgControlHandler builds the air-kg mesh-HTTP surface over the facade. identify
// resolves the caller's (pubkey, fqdn); allow gates reachability; bridge maps the
// caller to its corpora (static --grant map ∪ dynamic grant-on-request store);
// audit records reachability refusals on the shared chain (the facade audits every
// governed op itself, so the two land on one ledger). boundary (optional) is the
// cross-org federation gate for delta sync: a delta request naming an org is
// additionally checked against Boundary.CheckCorpus — deny-by-default, so with a
// nil boundary every cross-org delta is refused.
func kgControlHandler(f *knowstore.Facade, identify func(*http.Request) (pubkey, fqdn string), allow acl, bridge *kgGrantBridge, boundary *federation.Boundary, audit policy.AuditSink) http.Handler {
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
		caller := bridge.caller(pubKey, fqdn, body.Corpus, true)
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

	mux.HandleFunc("/v1/kg/supersede", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var body kgSupersedeBody
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.Corpus == "" || body.OldID == "" || body.S == "" || body.P == "" || body.O == "" {
			http.Error(w, "corpus, old_id, s, p and o are all required", http.StatusBadRequest)
			return
		}
		pubKey, fqdn, ok := reach(w, r, body.Corpus)
		if !ok {
			return
		}
		caller := bridge.caller(pubKey, fqdn, body.Corpus, true)
		receipt, err := f.Supersede(caller, body.OldID, knowstore.AssertRequest{
			Corpus: body.Corpus, S: body.S, P: body.P, O: body.O,
			Source: body.Source, ValidFrom: body.ValidFrom,
		})
		if err != nil {
			writeKGError(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, receipt)
	})

	mux.HandleFunc("/v1/kg/delta", func(w http.ResponseWriter, r *http.Request) {
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
		// Cross-org narrowing: a request that claims an org must ALSO pass the
		// federation corpus grant. Deny-by-default: naming an org with no
		// boundary configured refuses (an empty grant shares nothing); the
		// boundary self-audits its own decision when configured. The org claim
		// can only narrow — the caller's own corpus grant is still enforced by
		// the facade below.
		if org := q.Get("org"); org != "" {
			if boundary == nil {
				if audit != nil {
					_ = audit.Append(know.Retrieve(know.Event{
						Peer: fqdnOr(fqdn), PeerKey: pubKey, Corpus: corpus,
						Decision: "deny", Reason: "cross-org delta: no federation grants configured (deny-by-default)",
					}))
				}
				http.Error(w, "cross-org delta not granted", http.StatusForbidden)
				return
			}
			if allow, reason := boundary.CheckCorpus(org, corpus); !allow {
				http.Error(w, "cross-org delta not granted: "+reason, http.StatusForbidden)
				return
			}
		}
		recs, err := f.Delta(bridge.caller(pubKey, fqdn, corpus, false), corpus, kgSince(q.Get("since")))
		if err != nil {
			writeKGError(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, kgRecordsResp{Records: nonNilRecords(recs)})
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
		recs, err := f.Query(bridge.caller(pubKey, fqdn, corpus, false), corpus, q.Get("s"), q.Get("p"), q.Get("o"), kgAsOf(q.Get("as_of")))
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
		recs, err := f.Neighbors(bridge.caller(pubKey, fqdn, corpus, false), corpus, node, kgAsOf(q.Get("as_of")))
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
		recs, err := f.Query(bridge.caller(pubKey, fqdn, corpus, false), corpus, "", "", "", kgAsOf(q.Get("as_of")))
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

// kgSince parses a delta watermark; blank or malformed means 0 (the whole log).
func kgSince(s string) int {
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
	grantStorePath := fs.String("grant-store", "", "enable grant-on-request: persist dynamic grants + pending opportunities to this file (atomic, audited, revocable)")
	pairStorePath := fs.String("pair-store", "", "recognized-peer store (air pairing); only a recognized peer's denied request records a grant opportunity")
	operatorFlags := multiFlag{}
	fs.Var(&operatorFlags, "operator", "identity permitted to administer grants (allow/deny/revoke/pending); FQDN glob or pubkey:<key>; repeatable; fail-closed if empty")
	orgGrantFlags := multiFlag{}
	fs.Var(&orgGrantFlags, "org-grant", "cross-org delta grant: <org>=<corpus-glob>[,<corpus-glob>...]; repeatable; empty = no org may pull deltas (deny-by-default)")
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

	// Optional dynamic grant-on-request: a recognized peer's denied corpus request
	// becomes a pending opportunity an operator resolves with `air grant allow`.
	// It is consulted ALONGSIDE the static --grant map; deny-by-default is
	// preserved when neither grants the corpus. Recognition comes from the SAME
	// paired store the gateway's `air pair` writes (--pair-store).
	var grantStore *air.GrantStore
	if *grantStorePath != "" {
		grantStore, err = air.OpenGrantStore(*grantStorePath)
		if err != nil {
			return fmt.Errorf("air kg serve: open grant store %s: %w", *grantStorePath, err)
		}
	}
	var pairStore *air.PairedStore
	if *pairStorePath != "" {
		pairStore, err = air.OpenPairedStore(*pairStorePath)
		if err != nil {
			return fmt.Errorf("air kg serve: open paired store %s: %w", *pairStorePath, err)
		}
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

	// Cross-org federation boundary for delta sync (S3's second gate). Built
	// only from operator --org-grant flags; no flags = nil boundary = every
	// cross-org delta refused. The boundary self-audits crossings onto the same
	// ledger when the audit sink is the real AuditLog.
	var boundary *federation.Boundary
	if len(orgGrantFlags) > 0 {
		fedGrants, err := parseOrgGrants(orgGrantFlags)
		if err != nil {
			return fmt.Errorf("air kg serve: %w", err)
		}
		auditLog, _ := audit.(*policy.AuditLog)
		boundary = federation.NewBoundary(fedGrants, nil, auditLog)
	}

	o.BlockInbound = false // we listen for callers on the mesh
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	identify := func(r *http.Request) (string, string) { return peerIdentityStr(client, r.RemoteAddr) }
	bridge := &kgGrantBridge{
		static:  grants,
		dyn:     grantStore,
		paired:  pairStore,
		limiter: newRingLimiter(grantRecordRatePerMin),
		audit:   audit,
	}
	h := kgControlHandler(facade, identify, newACL(allow), bridge, boundary, audit)

	// Optional grant-on-request admin surface, mounted on the SAME listener as the
	// kg endpoint so the operator's approval and the served handler's grant
	// consultation share ONE in-memory store. Operator-gated deny-by-default,
	// fail-closed on an empty --operator ACL (mirrors air pair). Longest-prefix
	// routing: /v1/grant/ → grant admin, everything else → the kg handler.
	if grantStore != nil {
		gh := grantControlHandler(grantStore, identify, newACL(operatorFlags), grantVerbKG, audit)
		parent := http.NewServeMux()
		parent.Handle("/v1/grant/", gh)
		parent.Handle("/", h)
		h = parent
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("air kg serve: listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "air-kg on mesh port %d (POST /v1/kg/assert · /v1/kg/supersede · GET /v1/kg/query · /v1/kg/neighbors · /v1/kg/subgraph · /v1/kg/delta · /v1/kg/verify)\n", *port)
	fmt.Fprintf(os.Stderr, dim("store %s · %d grant(s) · allow %v\n"), *store, len(grants), []string(allow))
	if grantStore != nil {
		fmt.Fprintf(os.Stderr, dim("grant-on-request on (store %s · %d operator(s) · POST /v1/grant/allow|deny|revoke · GET /v1/grant/pending)\n"), *grantStorePath, len(operatorFlags))
		if pairStore == nil {
			fmt.Fprintln(os.Stderr, amber("warning:")+" --grant-store set without --pair-store; no peer is recognized, so no grant opportunities will be recorded. Point --pair-store at the gateway's pairing store.")
		}
		if len(operatorFlags) == 0 {
			fmt.Fprintln(os.Stderr, amber("warning:")+" --grant-store set without --operator; the grant admin surface is fail-closed (403 to everyone) until an --operator identity is configured.")
		}
	}
	// Read/header timeouts even on the mesh so an admitted peer cannot hold the
	// listener open with a slow request (Slowloris), matching the control endpoint.
	return serveGracefully(newLocalHTTPServer("", h), ln)
}

// parseOrgGrants parses --org-grant "<org>=<corpus-glob>[,...]" flags into
// federation grants for the cross-org delta gate. Malformed entries are hard
// errors, mirroring parseKGGrants.
func parseOrgGrants(flags []string) ([]federation.Grant, error) {
	var grants []federation.Grant
	for _, raw := range flags {
		org, list, ok := strings.Cut(raw, "=")
		if !ok || org == "" {
			return nil, fmt.Errorf("bad --org-grant %q: want <org>=<corpus-glob>[,<corpus-glob>...]", raw)
		}
		var corpora []string
		for _, c := range strings.Split(list, ",") {
			if c = strings.TrimSpace(c); c != "" {
				corpora = append(corpora, c)
			}
		}
		if len(corpora) == 0 {
			return nil, fmt.Errorf("bad --org-grant %q: no corpora listed", raw)
		}
		grants = append(grants, federation.Grant{Org: org, Corpora: corpora})
	}
	return grants, nil
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
