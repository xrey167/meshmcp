package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/control"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/registry"
)

// cmdControl runs the managed control plane: enrollment, the service registry,
// and policy distribution, served as a single mesh peer (no public port). A
// team points new nodes at it and they bootstrap themselves — the mesh without
// the operator toil.
func cmdControl(args []string) error {
	fs := flag.NewFlagSet("control", flag.ExitOnError)
	o := meshFlags(fs)
	port := fs.Int("port", 9600, "mesh port to serve the control API on")
	addr := fs.String("addr", "", "bind a plain local address instead of the mesh (dev/testing)")
	regDir := fs.String("registry", "", "service registry directory (enables /v1/registry)")
	polDir := fs.String("policies", "", "policy directory (enables /v1/policy)")
	enrollKey := fs.String("enroll-key", "", "static setup key handed to enrolling nodes ($NB_ENROLL_KEY)")
	enrollMgmt := fs.String("enroll-management-url", "", "management URL handed to enrolling nodes")
	nbToken := fs.String("netbird-token", "", "NetBird PAT to mint per-node one-off keys ($NB_API_TOKEN)")
	nbAPI := fs.String("netbird-api", "https://api.netbird.io", "NetBird management API base URL")
	nbGroups := fs.String("enroll-groups", "", "comma-separated NetBird groups to place enrolled nodes in")
	nbTTL := fs.Duration("enroll-ttl", 24*time.Hour, "issued key expiry")
	enrollAudit := fs.String("enroll-audit", "", "tamper-evident enrollment audit log (JSONL)")
	aclPath := fs.String("acl", "", "operator ACL file (YAML: grants: {<wg-pubkey>: [roles]}) — REQUIRED for privileged routes")
	controlAudit := fs.String("control-audit", "", "audit log for privileged control-plane actions (JSONL; defaults to stderr)")
	anchorWitness := fs.String("anchor-witness", "", "append-only anchor file: accept peer gateways' signed audit checkpoints on /v1/anchor (requires --anchor-signers)")
	anchorSigners := fs.String("anchor-signers", "", "comma-separated hex Ed25519 audit-signing PUBLIC keys pinned as accepted /v1/anchor signers")
	if err := fs.Parse(args); err != nil {
		return err
	}

	srv := &control.Server{}

	// Load the operator ACL. The control plane is default-deny: privileged
	// routes (enroll/registry/policy) require an ACL, so a missing or malformed
	// ACL is a startup error, never a silent fall-back to "any mesh peer". The
	// ACL also selects single- vs multi-tenant: a top-level grants: map is
	// single-tenant (today's behaviour, unchanged); a tenants: map partitions the
	// control plane, with each tenant defined ONLY by the keys it grants.
	var tenants *control.TenantSet
	if *aclPath != "" {
		raw, err := os.ReadFile(*aclPath)
		if err != nil {
			return fmt.Errorf("read control ACL %s: %w", *aclPath, err)
		}
		acl, err := control.LoadControlACL(raw)
		if err != nil {
			return fmt.Errorf("control ACL %s: %w", *aclPath, err)
		}
		if acl.Tenants != nil {
			tenants = acl.Tenants
			srv.Tenants = tenants
			log.Printf("control ACL loaded from %s: MULTI-TENANT, %d tenants %v", *aclPath, len(tenants.TenantIDs()), tenants.TenantIDs())
		} else {
			srv.Auth = acl.Flat
			log.Printf("control ACL loaded from %s (admins: %v)", *aclPath, acl.Flat.KeysWithRole(control.RoleAdmin))
		}
	}

	// Enrollment backend selection is shared by both modes: prefer real NetBird
	// key issuance (per-node one-off keys) when a PAT is available; fall back to a
	// static key otherwise. NOTE (honest scope): the PAT names ONE NetBird
	// account, so multi-tenant enrollment isolates per-tenant auto_groups and
	// audit attribution, NOT the management-plane account — a shared PAT is not
	// cryptographically isolated per tenant.
	token := *nbToken
	if token == "" {
		token = os.Getenv("NB_API_TOKEN")
	}
	staticKey := *enrollKey
	if staticKey == "" {
		staticKey = os.Getenv("NB_ENROLL_KEY")
	}
	mgmt := *enrollMgmt
	if mgmt == "" {
		mgmt = o.ManagementURL
	}
	var defaultGroups []string
	if *nbGroups != "" {
		defaultGroups = strings.Split(*nbGroups, ",")
	}

	var enrollLog *policy.AuditLog         // single-tenant enrollment chain
	var tenantStores *control.TenantStores // multi-tenant store provider (closed on shutdown)

	if tenants != nil {
		// Multi-tenant: --policies / --registry / --control-audit become ROOTS
		// under which each tenant gets its own subdir (policy, registry) or
		// <tenant>.jsonl hash chain (control+enroll audit). A handler never sees a
		// root; authorize hands it only the tenantID derived from the caller's key.
		regRoot := *regDir
		var newEnroll func(string, []string, *policy.AuditLog) (control.EnrollFunc, error)
		switch {
		case token != "":
			newEnroll = func(tid string, groups []string, audit *policy.AuditLog) (control.EnrollFunc, error) {
				if len(groups) == 0 {
					groups = defaultGroups
				}
				return (&control.NetBirdIssuer{
					APIURL:        *nbAPI,
					ManagementURL: mgmt,
					Token:         token,
					Groups:        groups,
					TTL:           *nbTTL,
					RegistryDir:   tenantRegistryEcho(regRoot, tid),
					ControlNode:   o.DeviceName,
					Audit:         audit, // shared per-tenant chain (control + enroll interleave)
				}).Enroll, nil
			}
			log.Printf("enrollment: NetBird key issuance via %s (per-tenant auto_groups; SHARED PAT — management-plane accounts are NOT per-tenant isolated)", *nbAPI)
		case staticKey != "":
			newEnroll = func(tid string, _ []string, _ *policy.AuditLog) (control.EnrollFunc, error) {
				return control.StaticEnroll(mgmt, staticKey, tenantRegistryEcho(regRoot, tid), o.DeviceName), nil
			}
			log.Printf("enrollment: static key (per-tenant registry subdir)")
		}

		stores := control.NewTenantStores(control.TenantStoresConfig{
			PolicyRoot:   *polDir,
			RegistryRoot: *regDir,
			AuditRoot:    *controlAudit, // directory of per-tenant <tenant>.jsonl chains
			Now:          func() string { return time.Now().UTC().Format(time.RFC3339) },
			// No-tenant denials (a caller in no tenant) cannot enter any tenant's
			// chain, so they log to stderr — never a tenant file.
			Fallback:  newControlAuditSink(""),
			NewEnroll: newEnroll,
			Groups:    tenants.EnrollGroups,
		})
		srv.Stores = stores
		srv.Audit = stores // per-tenant control-audit router
		tenantStores = stores
		if *controlAudit != "" {
			log.Printf("control audit: per-tenant hash chains under %s/<tenant>.jsonl", *controlAudit)
		} else {
			log.Printf("control audit: stderr (set --control-audit <dir> for per-tenant hash chains)")
		}
	} else {
		// Single-tenant: unchanged from before tenancy existed.
		srv.Audit = newControlAuditSink(*controlAudit)
		if *regDir != "" {
			reg, err := registry.NewFileRegistry(*regDir)
			if err != nil {
				return fmt.Errorf("registry %s: %w", *regDir, err)
			}
			srv.Reg = reg
		}
		if *polDir != "" {
			ps, err := control.NewFilePolicyStore(*polDir)
			if err != nil {
				return fmt.Errorf("policies %s: %w", *polDir, err)
			}
			srv.Policies = ps
		}
		if token != "" {
			if *enrollAudit != "" {
				f, err := os.OpenFile(*enrollAudit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					return fmt.Errorf("open enroll audit %s: %w", *enrollAudit, err)
				}
				defer f.Close()
				enrollLog = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
			}
			srv.Enroll = (&control.NetBirdIssuer{
				APIURL:        *nbAPI,
				ManagementURL: mgmt,
				Token:         token,
				Groups:        defaultGroups,
				TTL:           *nbTTL,
				RegistryDir:   *regDir,
				ControlNode:   o.DeviceName,
				Audit:         enrollLog,
			}).Enroll
			log.Printf("enrollment: NetBird key issuance via %s (per-node one-off keys)", *nbAPI)
		} else if staticKey != "" {
			srv.Enroll = control.StaticEnroll(mgmt, staticKey, *regDir, o.DeviceName)
			log.Printf("enrollment: static key (set --netbird-token for per-node key issuance)")
		}
	}
	if tenantStores != nil {
		defer tenantStores.Close()
	}

	// Anchor witness: record peer gateways' signed audit checkpoints in an
	// append-only, self-linked file so an insider on the peer cannot roll the
	// log and checkpoints back together undetected. Fail closed: a witness with
	// no pinned signers is refused (NewAnchorWitness errors on an empty list),
	// and enabling it without one is a startup error rather than a silent no-op.
	if *anchorWitness != "" {
		var signers []string
		for _, s := range strings.Split(*anchorSigners, ",") {
			if s = strings.TrimSpace(s); s != "" {
				signers = append(signers, s)
			}
		}
		wt, err := control.NewAnchorWitness(*anchorWitness, signers)
		if err != nil {
			return err
		}
		defer wt.Close()
		srv.Witness = wt
		log.Printf("anchor witness: recording checkpoints from %d pinned signer(s) to %s", len(signers), *anchorWitness)
	} else if *anchorSigners != "" {
		return fmt.Errorf("--anchor-signers requires --anchor-witness <file>")
	}

	// Fail closed at startup: if any privileged capability is exposed, an ACL is
	// mandatory. A control plane that serves enrollment/registry/policy without an
	// authorizer (flat Auth or a tenant resolver) would authorize every reachable
	// mesh peer.
	exposed := srv.Reg != nil || srv.Policies != nil || srv.Enroll != nil || srv.Witness != nil || srv.Stores != nil
	if exposed && srv.Auth == nil && srv.Tenants == nil {
		return fmt.Errorf("control plane exposes privileged routes but no --acl was provided: refusing to start (WireGuard membership is not authorization). Provide --acl <file> granting roles per WireGuard public key")
	}

	handler := srv.Handler()
	// Seal the enrollment ledger's final checkpoint batch on shutdown, so a
	// `systemctl stop` never strands issued-key records outside a checkpoint.
	flushEnroll := func() { enrollLog.Flush() }

	// Dev/testing path: bind a plain local port, no mesh. There is no mesh
	// transport to derive identity from here, so Identify stays nil and every
	// privileged route fails closed (403). This listener is not a substitute for
	// the mesh and must not be exposed as an administrative endpoint.
	if *addr != "" {
		log.Printf("control plane on http://%s (LOCAL, not on the mesh — privileged routes are DENIED, no transport identity)", *addr)
		return serveGracefully(&http.Server{Addr: *addr, Handler: handler}, nil, flushEnroll)
	}

	o.BlockInbound = false
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	// Derive the caller identity from the authenticated mesh transport (source
	// address -> WireGuard public key), never from headers or the request body.
	srv.Identify = func(remote string) (control.Identity, bool) {
		pubKey, fqdn := peerIdentityStr(client, remote)
		if pubKey == "" {
			return control.Identity{}, false
		}
		return control.Identity{PubKey: pubKey, FQDN: fqdn}, true
	}

	if st, err := client.Status(); err == nil {
		ip := strings.SplitN(st.LocalPeerState.IP, "/", 2)[0]
		log.Printf("control plane up: %s (%s) on mesh port %d", ip, st.LocalPeerState.FQDN, *port)
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()
	return serveGracefully(&http.Server{Handler: handler}, ln, flushEnroll)
}

// tenantRegistryEcho is the registry directory a multi-tenant enroller echoes
// back to a joining node: the tenant's OWN subdir under the registry root, so an
// enrolled node registers into its tenant's partition (not the shared root). An
// empty root echoes empty (no centralized registry), never a bare relative id.
func tenantRegistryEcho(regRoot, tenantID string) string {
	if regRoot == "" {
		return ""
	}
	return filepath.Join(regRoot, tenantID)
}

// controlAuditSink writes privileged control-plane decisions as JSON lines to a
// file (or stderr). It is best-effort observability layered on the 403 that the
// authorization check already enforced.
type controlAuditSink struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
}

func newControlAuditSink(path string) *controlAuditSink {
	var w io.Writer = os.Stderr
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Printf("control audit: cannot open %s (%v); logging privileged actions to stderr", path, err)
		} else {
			w = f
		}
	}
	return &controlAuditSink{w: w, enc: json.NewEncoder(w)}
}

func (s *controlAuditSink) Record(rec control.ControlAudit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(rec)
}
