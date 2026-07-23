package control

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/registry"
)

// TenantStores supplies per-tenant capability instances — each rooted at
// <root>/<tenantID> — selected only by the tenantID that authorize derives from
// the transport key. It also implements AuditSink: each control-plane decision
// is routed into ITS tenant's hash-chained audit log. A handler never sees a
// root path; the join of root + tenantID happens here, so there is no primitive
// a handler could use to address another tenant's directory.
//
// registry/ and policy/ stay generic — the tenant-prefix wrappers live here in
// control/, keeping the storage packages unaware of tenancy.
type TenantStores struct {
	polRoot   string
	regRoot   string
	auditRoot string
	now       func() string

	hasPolicy bool
	hasReg    bool
	hasEnroll bool

	// newEnroll builds a tenant's EnrollFunc from its id, its enroll_groups, and
	// its per-tenant audit chain — the SAME *policy.AuditLog the control-audit
	// router uses for that tenant, so enrollment and control actions interleave
	// into one verifiable file. Nil ⇒ enrollment unconfigured.
	newEnroll func(tenantID string, groups []string, audit *policy.AuditLog) (EnrollFunc, error)
	groupsFor func(tenantID string) []string

	// fallback receives control-audit records that carry NO tenant (a
	// deny-by-default before any tenant resolved). Such a record must never enter
	// a tenant's chain, so it routes here (the un-tenanted control-audit sink).
	fallback AuditSink

	mu        sync.Mutex
	policies  map[string]PolicyStore
	regs      map[string]registry.Registry
	auditLogs map[string]*policy.AuditLog
	enrollers map[string]EnrollFunc
	closers   []io.Closer
}

// TenantStoresConfig configures the per-tenant capability roots and how a
// tenant's enroller is built. An empty root leaves that capability unconfigured
// (its selector reports "not configured", exactly as a single-tenant deployment
// with the flag omitted).
type TenantStoresConfig struct {
	PolicyRoot   string // per-tenant policy dirs: <root>/<tenant>/<name>.yaml
	RegistryRoot string // per-tenant registry dirs: <root>/<tenant>/*.json
	AuditRoot    string // per-tenant audit chains: <root>/<tenant>.jsonl
	Now          func() string
	// Fallback receives no-tenant (Tenant:"") control-audit records.
	Fallback AuditSink
	// NewEnroll builds a tenant's EnrollFunc; nil ⇒ enrollment unconfigured.
	NewEnroll func(tenantID string, groups []string, audit *policy.AuditLog) (EnrollFunc, error)
	// Groups maps a tenant id to its enroll_groups (from the TenantSet).
	Groups func(tenantID string) []string
}

// NewTenantStores builds the per-tenant store provider. Nothing is opened here;
// each tenant's directories and audit chain are created lazily on first use, so
// a tenant that never acts leaves no files behind.
func NewTenantStores(cfg TenantStoresConfig) *TenantStores {
	now := cfg.Now
	if now == nil {
		now = func() string { return "" }
	}
	groups := cfg.Groups
	if groups == nil {
		groups = func(string) []string { return nil }
	}
	return &TenantStores{
		polRoot:   cfg.PolicyRoot,
		regRoot:   cfg.RegistryRoot,
		auditRoot: cfg.AuditRoot,
		now:       now,
		hasPolicy: cfg.PolicyRoot != "",
		hasReg:    cfg.RegistryRoot != "",
		hasEnroll: cfg.NewEnroll != nil,
		newEnroll: cfg.NewEnroll,
		groupsFor: groups,
		fallback:  cfg.Fallback,
		policies:  map[string]PolicyStore{},
		regs:      map[string]registry.Registry{},
		auditLogs: map[string]*policy.AuditLog{},
		enrollers: map[string]EnrollFunc{},
	}
}

// HasPolicy / HasRegistry / HasEnroll report whether the capability is
// configured (its root/enroller was supplied), driving the "not configured"
// (501) route responses without needing a tenant.
func (ts *TenantStores) HasPolicy() bool   { return ts != nil && ts.hasPolicy }
func (ts *TenantStores) HasRegistry() bool { return ts != nil && ts.hasReg }
func (ts *TenantStores) HasEnroll() bool   { return ts != nil && ts.hasEnroll }

// PolicyStore returns tenantID's policy store, rooted at <polRoot>/<tenantID>.
func (ts *TenantStores) PolicyStore(tenantID string) (PolicyStore, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if p, ok := ts.policies[tenantID]; ok {
		return p, nil
	}
	p, err := NewFilePolicyStore(filepath.Join(ts.polRoot, tenantID))
	if err != nil {
		return nil, err
	}
	ts.policies[tenantID] = p
	return p, nil
}

// Registry returns tenantID's registry, rooted at <regRoot>/<tenantID>. A
// lookup reads only that subdir, so one tenant's list never includes another's.
func (ts *TenantStores) Registry(tenantID string) (registry.Registry, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if r, ok := ts.regs[tenantID]; ok {
		return r, nil
	}
	r, err := registry.NewFileRegistry(filepath.Join(ts.regRoot, tenantID))
	if err != nil {
		return nil, err
	}
	ts.regs[tenantID] = r
	return r, nil
}

// Enroller returns tenantID's EnrollFunc, bound to the tenant's enroll_groups
// and its audit chain.
func (ts *TenantStores) Enroller(tenantID string) (EnrollFunc, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if e, ok := ts.enrollers[tenantID]; ok {
		return e, nil
	}
	log, err := ts.auditLocked(tenantID)
	if err != nil {
		return nil, err
	}
	e, err := ts.newEnroll(tenantID, ts.groupsFor(tenantID), log)
	if err != nil {
		return nil, err
	}
	ts.enrollers[tenantID] = e
	return e, nil
}

// Record implements AuditSink: it routes a control-plane decision into its
// tenant's hash chain, so "per-tenant audit chain" is a genuine isolated
// Seq/PrevHash — not just a stamped field. Best-effort, matching today's control
// audit (observability layered on the 403 the authorization check already
// enforced): a tenant chain that cannot be opened never fails the request.
func (ts *TenantStores) Record(rec ControlAudit) {
	if rec.Tenant == "" {
		if ts.fallback != nil {
			ts.fallback.Record(rec)
		}
		return
	}
	log, err := ts.audit(rec.Tenant)
	if err != nil || log == nil {
		// No per-tenant chain (open failed, or no AuditRoot configured): fall back
		// to the un-tenanted sink so the decision is still observed.
		if ts.fallback != nil {
			ts.fallback.Record(rec)
		}
		return
	}
	_ = log.Append(controlRecordToAudit(rec))
}

// Close releases every lazily-opened per-tenant audit file.
func (ts *TenantStores) Close() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var err error
	for _, c := range ts.closers {
		if e := c.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// audit returns (opening + seeding if needed) tenantID's hash-chained audit log.
func (ts *TenantStores) audit(tenantID string) (*policy.AuditLog, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.auditLocked(tenantID)
}

// auditLocked is audit with ts.mu already held (so Enroller can share the exact
// same *policy.AuditLog instance that Record uses — one chain, one cursor). A nil
// return with a nil error means no AuditRoot is configured: there is no
// per-tenant chain, and the caller routes to the fallback sink instead.
func (ts *TenantStores) auditLocked(tenantID string) (*policy.AuditLog, error) {
	if ts.auditRoot == "" {
		return nil, nil
	}
	if l, ok := ts.auditLogs[tenantID]; ok {
		return l, nil
	}
	path := filepath.Join(ts.auditRoot, tenantID+".jsonl")
	l, c, err := openTenantAudit(path, ts.now)
	if err != nil {
		return nil, err
	}
	ts.auditLogs[tenantID] = l
	ts.closers = append(ts.closers, c)
	return l, nil
}

// openTenantAudit opens (or creates) a tenant's audit file for append and seeds
// its chain from the existing tail, so a restart continues the SAME chain rather
// than resetting to a duplicate genesis. This is the per-tenant analogue of the
// gateway's restart seed (LastLink + SeedFrom); it reads only the tail and does
// not re-verify the interior (a possible hardening, out of v1 — the caller can
// still run VerifyChain over the file offline).
func openTenantAudit(path string, now func() string) (*policy.AuditLog, io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("tenant audit %s: %w", path, err)
	}
	seq, prev := 0, ""
	if rf, err := os.Open(path); err == nil {
		s, h, lerr := policy.LastLink(rf)
		rf.Close()
		if lerr != nil {
			return nil, nil, fmt.Errorf("tenant audit %s: %w", path, lerr)
		}
		seq, prev = s, h
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("tenant audit %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("tenant audit %s: %w", path, err)
	}
	log := policy.NewAuditLog(f, now)
	log.SeedFrom(seq, prev)
	return log, f, nil
}

// controlRecordToAudit maps a ControlAudit into the shared AuditRecord shape so
// a tenant's control chain uses the same tamper-evident format as its enrollment
// records (Backend:"control"). VerifyChain(<tenant>.jsonl) then covers both
// control actions and enrollment for that tenant — and, because the file holds
// only that tenant's records, sees no other tenant.
func controlRecordToAudit(rec ControlAudit) policy.AuditRecord {
	return policy.AuditRecord{
		Backend:  "control",
		Peer:     rec.Actor,
		Method:   rec.Action,
		Tool:     rec.Target,
		Decision: rec.Result,
		Reason:   rec.Reason,
		RPCID:    rec.Corr,
	}
}
