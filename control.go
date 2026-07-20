package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	srv := &control.Server{}

	// Load the operator ACL. The control plane is default-deny: privileged
	// routes (enroll/registry/policy) require an ACL, so a missing or malformed
	// ACL is a startup error, never a silent fall-back to "any mesh peer".
	if *aclPath != "" {
		raw, err := os.ReadFile(*aclPath)
		if err != nil {
			return fmt.Errorf("read control ACL %s: %w", *aclPath, err)
		}
		auth, err := control.LoadAuthorizer(raw)
		if err != nil {
			return fmt.Errorf("control ACL %s: %w", *aclPath, err)
		}
		srv.Auth = auth
		log.Printf("control ACL loaded from %s (admins: %v)", *aclPath, auth.KeysWithRole(control.RoleAdmin))
	}
	// Privileged control-plane audit sink.
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
	// Enrollment: prefer real NetBird key issuance (per-node one-off keys) when
	// a PAT is available; fall back to a static key otherwise.
	token := *nbToken
	if token == "" {
		token = os.Getenv("NB_API_TOKEN")
	}
	if token != "" {
		var enrollLog *policy.AuditLog
		if *enrollAudit != "" {
			f, err := os.OpenFile(*enrollAudit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				return fmt.Errorf("open enroll audit %s: %w", *enrollAudit, err)
			}
			defer f.Close()
			enrollLog = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
		}
		var groups []string
		if *nbGroups != "" {
			groups = strings.Split(*nbGroups, ",")
		}
		mgmt := *enrollMgmt
		if mgmt == "" {
			mgmt = o.ManagementURL
		}
		srv.Enroll = (&control.NetBirdIssuer{
			APIURL:        *nbAPI,
			ManagementURL: mgmt,
			Token:         token,
			Groups:        groups,
			TTL:           *nbTTL,
			RegistryDir:   *regDir,
			ControlNode:   o.DeviceName,
			Audit:         enrollLog,
		}).Enroll
		log.Printf("enrollment: NetBird key issuance via %s (per-node one-off keys)", *nbAPI)
	} else {
		key := *enrollKey
		if key == "" {
			key = os.Getenv("NB_ENROLL_KEY")
		}
		if key != "" {
			mgmt := *enrollMgmt
			if mgmt == "" {
				mgmt = o.ManagementURL
			}
			srv.Enroll = control.StaticEnroll(mgmt, key, *regDir, o.DeviceName)
			log.Printf("enrollment: static key (set --netbird-token for per-node key issuance)")
		}
	}

	// Fail closed at startup: if any privileged capability is exposed, an ACL is
	// mandatory. A control plane that serves enrollment/registry/policy without
	// an authorizer would authorize every reachable mesh peer.
	if (srv.Reg != nil || srv.Policies != nil || srv.Enroll != nil) && srv.Auth == nil {
		return fmt.Errorf("control plane exposes privileged routes but no --acl was provided: refusing to start (WireGuard membership is not authorization). Provide --acl <file> granting roles per WireGuard public key")
	}

	handler := srv.Handler()

	// Dev/testing path: bind a plain local port, no mesh. There is no mesh
	// transport to derive identity from here, so Identify stays nil and every
	// privileged route fails closed (403). This listener is not a substitute for
	// the mesh and must not be exposed as an administrative endpoint.
	if *addr != "" {
		log.Printf("control plane on http://%s (LOCAL, not on the mesh — privileged routes are DENIED, no transport identity)", *addr)
		return http.ListenAndServe(*addr, handler)
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
	return http.Serve(ln, handler)
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
