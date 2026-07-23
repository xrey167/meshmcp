// Package control is the meshmcp managed control plane: a single mesh service
// that hands a new node everything it needs to join and behave — enrollment
// (management URL + setup key), the service registry (who is on the mesh), and
// policy distribution (the rules a gateway should enforce). It is what lets a
// team adopt the mesh without each operator hand-wiring NetBird, registries,
// and policy files.
//
// The control plane itself runs as an ordinary mesh peer, so it is subject to
// the same zero-exposure and identity guarantees as everything else: it has no
// public port, and every caller is a cryptographically identified mesh peer.
package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/registry"
)

// EnrollRequest is a node asking to join the mesh.
type EnrollRequest struct {
	Node string `json:"node"`
}

// EnrollResponse is everything a node needs to bootstrap.
type EnrollResponse struct {
	ManagementURL string `json:"management_url"`
	SetupKey      string `json:"setup_key"`
	Registry      string `json:"registry,omitempty"` // shared registry dir, if centralized
	ControlNode   string `json:"control_node,omitempty"`
}

// EnrollFunc issues enrollment credentials for a node. The default
// implementation returns statically configured credentials; a production
// deployment plugs in one that mints a scoped, short-lived NetBird setup key
// via the management API.
type EnrollFunc func(req EnrollRequest) (EnrollResponse, error)

// PolicyStore reads and writes named policies.
type PolicyStore interface {
	Get(name string) ([]byte, error)
	Put(name string, raw []byte) error
	List() ([]string, error)
}

// maxControlBody caps a privileged request body so a caller cannot exhaust
// memory on the control plane.
const maxControlBody = 1 << 20 // 1 MiB

// ControlAudit is one privileged-action record: who (actor WireGuard key), what
// (action + target), the result, and a correlation id tying an allow/deny to a
// specific request.
type ControlAudit struct {
	Actor  string `json:"actor_key"`
	FQDN   string `json:"actor_fqdn,omitempty"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Result string `json:"result"` // "allow" | "deny"
	Reason string `json:"reason,omitempty"`
	Corr   string `json:"correlation_id"`
}

// AuditSink records privileged control-plane actions. Implementations must not
// block the request path.
type AuditSink interface {
	Record(ControlAudit)
}

// Server bundles the control-plane capabilities. Any capability field (Reg,
// Policies, Enroll) may be nil, in which case its routes report 501.
//
// Auth and Identify are the authorization controls. The control plane is
// default-deny: with either nil, every privileged route fails closed (403),
// because WireGuard membership authenticates a peer but does not authorize
// administration. Identify derives the caller's WireGuard key from the
// transport; Auth maps that key to roles. Caller identity supplied in headers or
// the request body is ignored.
type Server struct {
	Reg      registry.Registry
	Policies PolicyStore
	Enroll   EnrollFunc
	Auth     Authorizer
	Identify IdentityResolver
	Audit    AuditSink
	// Witness accepts peer gateways' signed audit checkpoints on /v1/anchor and
	// records them in this host's own append-only anchor file (external audit
	// anchoring). Nil ⇒ the route reports 501.
	Witness *AnchorWitness
}

// Handler returns the control-plane HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", s.handleEnroll)
	mux.HandleFunc("/v1/registry", s.handleRegistry)
	mux.HandleFunc("/v1/policy/", s.handlePolicy)
	mux.HandleFunc("/v1/policies", s.handlePolicyList)
	mux.HandleFunc("/v1/anchor", s.handleAnchor)
	// healthz is an unauthenticated liveness probe: it reveals no state.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	return mux
}

func (s *Server) audit(rec ControlAudit) {
	if s.Audit != nil {
		s.Audit.Record(rec)
	}
}

// authorize enforces default-deny RBAC for a privileged action. It derives the
// caller identity from the transport (never headers/body), checks the required
// role, audits the allow or deny with a correlation id, and writes a 403 on
// denial. It returns the identity and true only when the caller is authorized.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, role Role, action, target string) (Identity, bool) {
	corr := newCorrelationID()
	w.Header().Set("X-Control-Correlation-Id", corr)

	// Fail closed on a misconfigured control plane: without both an identity
	// resolver and an authorizer we cannot make an authorization decision, so we
	// must deny rather than admit every reachable peer.
	if s.Identify == nil || s.Auth == nil {
		s.audit(ControlAudit{Action: action, Target: target, Result: "deny", Reason: "control authorization not configured", Corr: corr})
		http.Error(w, "forbidden: control authorization not configured (fail-closed)", http.StatusForbidden)
		return Identity{}, false
	}
	id, ok := s.Identify(r.RemoteAddr)
	if !ok || id.PubKey == "" {
		s.audit(ControlAudit{Action: action, Target: target, Result: "deny", Reason: "caller could not be attributed to a mesh peer", Corr: corr})
		http.Error(w, "forbidden: unattributable caller", http.StatusForbidden)
		return Identity{}, false
	}
	if !s.Auth.HasRole(id.PubKey, role) {
		s.audit(ControlAudit{Actor: id.PubKey, FQDN: id.FQDN, Action: action, Target: target, Result: "deny", Reason: "missing role " + string(role), Corr: corr})
		http.Error(w, "forbidden: caller lacks role "+string(role), http.StatusForbidden)
		return Identity{}, false
	}
	s.audit(ControlAudit{Actor: id.PubKey, FQDN: id.FQDN, Action: action, Target: target, Result: "allow", Corr: corr})
	return id, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if s.Enroll == nil {
		http.Error(w, "enrollment not configured", http.StatusNotImplemented)
		return
	}
	// Issuing a setup key hands a caller the credential to join the mesh — a
	// privileged action gated by enrollment.issue, not something any reachable
	// peer may do. (A true unjoined-node bootstrap uses a separate one-time
	// credential flow; that redesign is tracked in the router/enrollment spec.)
	req := EnrollRequest{}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxControlBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid enroll request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Node == "" {
		http.Error(w, "node is required", http.StatusBadRequest)
		return
	}
	// The node label is caller-supplied and is NOT identity; authorize the
	// transport-proven caller before issuing anything.
	if _, ok := s.authorize(w, r, RoleEnrollmentIssue, "enroll.issue", req.Node); !ok {
		return
	}
	resp, err := s.Enroll(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRegistry serves the service registry: GET lists name->addrs; POST
// {name,addr} registers; DELETE {name,addr} deregisters.
func (s *Server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	if s.Reg == nil {
		http.Error(w, "registry not configured", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.authorize(w, r, RoleRegistryRead, "registry.list", ""); !ok {
			return
		}
		m, err := s.Reg.Lookup()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, m)
	case http.MethodPost, http.MethodDelete:
		var e struct {
			Name string `json:"name"`
			Addr string `json:"addr"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxControlBody))
		dec.DisallowUnknownFields()
		if dec.Decode(&e) != nil || e.Name == "" || e.Addr == "" {
			http.Error(w, "name and addr are required", http.StatusBadRequest)
			return
		}
		action := "registry.register"
		if r.Method == http.MethodDelete {
			action = "registry.deregister"
		}
		if _, ok := s.authorize(w, r, RoleRegistryWrite, action, e.Name+" "+e.Addr); !ok {
			return
		}
		var err error
		if r.Method == http.MethodPost {
			err = s.Reg.Register(e.Name, e.Addr)
		} else {
			err = s.Reg.Deregister(e.Name, e.Addr)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}

// handlePolicy serves GET/PUT for /v1/policy/<name>. PUT validates the body
// parses as a policy before storing, so the control plane never distributes a
// policy a gateway would reject.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if s.Policies == nil {
		http.Error(w, "policy distribution not configured", http.StatusNotImplemented)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/policy/")
	if err := validPolicyName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.authorize(w, r, RolePolicyRead, "policy.get", name); !ok {
			return
		}
		raw, err := s.Policies.Get(name)
		if err != nil {
			http.Error(w, "no such policy", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		_, _ = w.Write(raw)
	case http.MethodPut:
		if _, ok := s.authorize(w, r, RolePolicyWrite, "policy.put", name); !ok {
			return
		}
		buf, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxControlBody))
		if err != nil {
			http.Error(w, "policy body too large or unreadable", http.StatusBadRequest)
			return
		}
		// Run the COMPLETE policy validation (not just YAML unmarshalling), with
		// strict decoding, so the control plane never distributes a policy a
		// gateway would reject or that contains a silently-disabled rule.
		if err := ValidatePolicy(buf); err != nil {
			http.Error(w, "invalid policy: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.Policies.Put(name, buf); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "stored", "policy": name})
	default:
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePolicyList(w http.ResponseWriter, r *http.Request) {
	if s.Policies == nil {
		http.Error(w, "policy distribution not configured", http.StatusNotImplemented)
		return
	}
	// Listing policy names is sensitive administrative state.
	if _, ok := s.authorize(w, r, RolePolicyRead, "policy.list", ""); !ok {
		return
	}
	names, err := s.Policies.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, names)
}

// validPolicyName rejects empty names and any name that could escape the policy
// store (path separators, "..", NUL, leading dots, or unusual characters).
func validPolicyName(name string) error {
	if name == "" {
		return fmt.Errorf("policy name required")
	}
	if len(name) > 128 {
		return fmt.Errorf("policy name too long")
	}
	if name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid policy name")
	}
	if strings.ContainsAny(name, "/\\\x00") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid policy name")
	}
	for _, c := range name {
		if !(c == '-' || c == '_' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid policy name: only [A-Za-z0-9._-] are allowed")
		}
	}
	return nil
}

// ValidatePolicy strictly decodes raw YAML into a policy.Policy (rejecting
// unknown fields) and runs the complete policy validation, so a mistyped or
// unenforceable policy is rejected before storage rather than failing open at a
// gateway later.
func ValidatePolicy(raw []byte) error {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var p policy.Policy
	if err := dec.Decode(&p); err != nil {
		return err
	}
	return p.Validate()
}
