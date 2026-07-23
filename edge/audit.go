package edge

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// auditLedger is the edge's own hash-chained decision log. It is ALWAYS
// fail-closed: append returns an error if the record cannot be written, and
// callers on the allow path must treat that error as a denial. Denials that
// fail to record still return their 4xx (a denial is safe), but they surface
// the audit error to logs.
type auditLedger struct {
	mu  sync.Mutex
	log *policy.AuditLog
}

// openAuditLedger opens (or continues) the edge audit chain. When writer is
// non-nil it is used verbatim (tests); otherwise path is opened append-only and
// the chain is seeded from any existing verified tail, refusing to append to an
// unverifiable log.
func openAuditLedger(path string, writer io.Writer, now func() time.Time) (*auditLedger, error) {
	ts := func() string { return now().UTC().Format(time.RFC3339) }

	if writer != nil {
		return &auditLedger{log: policy.NewAuditLog(writer, ts).WithFailClosed(true)}, nil
	}

	seq, lastHash, err := seedEdgeAudit(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("edge: open audit_log %s: %w", path, err)
	}
	log := policy.NewAuditLog(f, ts).WithFailClosed(true)
	if seq > 0 {
		log.SeedFrom(seq, lastHash)
	}
	return &auditLedger{log: log}, nil
}

// seedEdgeAudit verifies an existing audit file and returns its tail so the
// chain continues across restart. A present-but-unverifiable log is fatal.
func seedEdgeAudit(path string) (seq int, lastHash string, err error) {
	data, rerr := os.ReadFile(path)
	if os.IsNotExist(rerr) {
		return 0, "", nil
	}
	if rerr != nil {
		return 0, "", fmt.Errorf("edge: read audit_log %s: %w", path, rerr)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return 0, "", nil
	}
	res, verr := policy.VerifyChain(bytes.NewReader(data))
	if verr != nil {
		return 0, "", fmt.Errorf("edge: verify existing audit_log %s: %w", path, verr)
	}
	if !res.OK {
		return 0, "", fmt.Errorf("edge: existing audit_log %s is unverifiable (break at seq %d: %s); refusing to append", path, res.BreakSeq, res.Reason)
	}
	return res.Count, res.LastHash, nil
}

// append records one decision. The caller sets Decision ("allow"/"deny"/"cosign")
// and the identity/tool fields; Backend is prefixed to disambiguate edge records
// from mesh-gateway records that may share an audit pipeline downstream.
func (a *auditLedger) append(rec policy.AuditRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.log.Append(rec)
}

// auditClientEvent records a client-lifecycle transition (register, approve,
// deny, revoke, deregister) under the client's synthetic identity, so the whole
// hosted-client lifecycle is attributable in the same tamper-evident ledger as
// the tool calls.
func (s *Server) auditClientEvent(rec ClientRecord, event, ip string) error {
	return s.audit.append(policy.AuditRecord{
		Backend:  "edge:" + s.cfg.Backend.Name,
		Peer:     oauthIdentity(rec.ClientID),
		PeerKey:  oauthIdentity(rec.ClientID),
		PeerAddr: ip,
		Method:   "edge/" + event,
		Decision: "allow",
		Reason:   "client " + rec.Status,
		Rule:     -1,
	})
}

// oauthIdentity is the synthetic identity string for a hosted OAuth client. It
// is used as both the policy fqdn and key (the policy engine compares it as an
// opaque string); rules reference it as pubkey:oauth:<client_id> or oauth:*.
func oauthIdentity(clientID string) string { return "oauth:" + clientID }
