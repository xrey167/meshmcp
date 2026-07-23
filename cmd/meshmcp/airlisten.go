package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// Air · Listen — receive rings (and future notices) over the mesh.
//
// The receiving end of `air ring`: a mesh-only listener that admits senders
// deny-by-default (an --allow ACL), rate-limits each identity so a peer cannot
// flood your attention, renders each ring escape-safely, and audits every one
// (accepted or rate-limited) into the hash-chained ledger — so rings show up in
// `air stream`, `air bind`, and the Receipts view for free. Display-only: a
// notice is never executed and any link is shown, not fetched.
//
//	meshmcp air listen --port 9130 --allow 'laptop-*' [--audit recv.jsonl] [--bell] [--json]
func cmdAirListen(args []string) error {
	fs := flag.NewFlagSet("air listen", flag.ExitOnError)
	o := meshFlags(fs)
	port := fs.Int("port", 9130, "mesh port to receive rings on")
	allow := multiFlag{}
	fs.Var(&allow, "allow", "identity permitted to ring you (FQDN glob or pubkey:<key>); repeatable; REQUIRED")
	auditPath := fs.String("audit", "", "append every ring (accepted or denied) to this JSONL ledger")
	rate := fs.Float64("rate", 6, "max rings per identity per minute before rate-limiting")
	bell := fs.Bool("bell", false, "sound the terminal bell on an incoming ring")
	asJSON := fs.Bool("json", false, "print each ring as JSON instead of a rendered row")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Paging a human is privileged: refuse to listen for anyone, deny-by-default
	// (mirrors the drop receiver and `air serve --control` requiring --allow).
	if len(allow) == 0 {
		return errors.New("air listen: --allow <id> is required (who may ring you); deny-by-default")
	}

	o.BlockInbound = false // we listen for senders on the mesh
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	var audit *policy.AuditLog
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("air listen: open audit log: %w", err)
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("air listen: listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()

	checker := newACL(allow)
	limiter := newRingLimiter(*rate)
	fmt.Fprintln(os.Stderr, dim("listening for rings on mesh port ")+bold(fmt.Sprint(*port))+dim(" · Ctrl-C to stop"))

	handle := func(n air.Notice, meta session.Meta) {
		onRing(n, meta, limiter, audit, *bell, *asJSON, os.Stdout)
	}
	identity := func(addr net.Addr) (string, string) { return peerIdentity(client, addr) }
	runAirAcceptLoop(ln, identity, checker, newListenFactory(handle), "ring", log.Printf)
	return nil
}

// onRing validates, rate-limits, renders, and audits one received notice.
func onRing(n air.Notice, meta session.Meta, limiter *ringLimiter, audit *policy.AuditLog, bell, asJSON bool, w io.Writer) {
	n = n.Normalized()
	if err := n.Validate(); err != nil {
		log.Printf("ring from %s ignored: %v", meta.PeerFQDN, err)
		return
	}
	// Rate-limit on the VERIFIED sender key, so a sender's own framing can't
	// bypass it; an over-limit ring is dropped and audited as denied.
	key := meta.PeerKey
	if key == "" {
		key = meta.PeerFQDN
	}
	if !limiter.allow(key, time.Now()) {
		auditRing(audit, meta, n, "deny", "ring rate-limited")
		log.Printf("ring from %s rate-limited", meta.PeerFQDN)
		return
	}
	auditRing(audit, meta, n, "allow", "ring received")
	if bell {
		fmt.Fprint(os.Stderr, "\a")
	}
	if asJSON {
		_ = air.WriteNotice(w, n)
		return
	}
	fmt.Fprintln(w, formatRingRow(n, meta.PeerFQDN))
}

// formatRingRow renders one ring as an escape-safe coloured row: urgent red,
// normal accent; the message and sender go through sanitizeCell.
func formatRingRow(n air.Notice, senderFQDN string) string {
	tag := cyan("● ring")
	if n.Urgent() {
		tag = red("● URGENT")
	}
	who := senderFQDN
	if n.From != "" {
		who = sanitizeCell(n.From) + dim("("+senderFQDN+")")
	}
	row := fmt.Sprintf("%s  %s  %s", tag, bold(sanitizeCell(who)), sanitizeCell(n.Message))
	if n.Approval != "" {
		row += "  " + dim("approve: http://"+sanitizeCell(n.Approval)+"/")
	}
	return row
}

// auditRing appends a ring decision to the ledger, mirroring the drop receiver's
// audit shape so rings appear in air stream/bind/Receipts.
func auditRing(audit *policy.AuditLog, meta session.Meta, n air.Notice, decision, reason string) {
	if audit == nil {
		return
	}
	audit.Append(policy.AuditRecord{
		Backend: "ring", Peer: meta.PeerFQDN, PeerKey: meta.PeerKey, PeerAddr: meta.PeerAddr,
		Method: "air/ring", Tool: n.Priority, Decision: decision, Reason: reason, Rule: -1,
	})
}

// newListenFactory returns a session backend factory whose backends parse a
// newline-JSON notice stream and call handle for each — the same send-only
// receive shape as the drop receiver (dropSink), so a roam mid-ring resumes.
func newListenFactory(handle func(air.Notice, session.Meta)) session.BackendFactory {
	return func(meta session.Meta) (session.Backend, error) {
		pr, pw := io.Pipe()
		d := &dropSink{pw: pw, done: make(chan struct{})}
		go func() {
			err := air.ParseNotices(pr, func(n air.Notice) { handle(n, meta) })
			pr.CloseWithError(err)
			d.finish(err)
		}()
		return d, nil
	}
}

// ringLimiter is a per-identity token bucket: each verified sender gets `rate`
// rings per minute with a small burst, refilled continuously. It bounds the
// attention any one peer can demand, independent of what they send.
type ringLimiter struct {
	mu    sync.Mutex
	rate  float64 // tokens per second
	burst float64
	tok   map[string]float64
	last  map[string]time.Time
}

// newRingLimiter builds a limiter allowing perMin rings per identity per minute
// with a burst of the same size (min 1).
func newRingLimiter(perMin float64) *ringLimiter {
	if perMin <= 0 {
		perMin = 6
	}
	burst := perMin
	if burst < 1 {
		burst = 1
	}
	return &ringLimiter{
		rate: perMin / 60.0, burst: burst,
		tok: map[string]float64{}, last: map[string]time.Time{},
	}
}

// allow reports whether an identity may ring at time now, consuming a token.
func (l *ringLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, seen := l.tok[key]
	if !seen {
		t = l.burst
	} else {
		t += now.Sub(l.last[key]).Seconds() * l.rate
		if t > l.burst {
			t = l.burst
		}
	}
	l.last[key] = now
	if t < 1 {
		l.tok[key] = t
		return false
	}
	l.tok[key] = t - 1
	return true
}
