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
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"meshmcp/policy"
	"meshmcp/registry"
)

// EnrollRequest is a node asking to join the mesh.
type EnrollRequest struct {
	Node string `json:"node"`
}

// EnrollResponse is everything a node needs to bootstrap.
type EnrollResponse struct {
	ManagementURL string `json:"management_url"`
	SetupKey      string `json:"setup_key"`
	Registry      string `json:"registry,omitempty"`  // shared registry dir, if centralized
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

// Server bundles the control-plane capabilities. Any field may be nil, in
// which case the corresponding routes report 501.
type Server struct {
	Reg      registry.Registry
	Policies PolicyStore
	Enroll   EnrollFunc
}

// Handler returns the control-plane HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", s.handleEnroll)
	mux.HandleFunc("/v1/registry", s.handleRegistry)
	mux.HandleFunc("/v1/policy/", s.handlePolicy)
	mux.HandleFunc("/v1/policies", s.handlePolicyList)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	return mux
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
	var req EnrollRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Node == "" {
		http.Error(w, "node is required", http.StatusBadRequest)
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
		m, err := s.Reg.Lookup()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, m)
	case http.MethodPost, http.MethodDelete:
		var e struct{ Name, Addr string }
		if json.NewDecoder(r.Body).Decode(&e) != nil || e.Name == "" || e.Addr == "" {
			http.Error(w, "name and addr are required", http.StatusBadRequest)
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
	if name == "" || strings.Contains(name, "/") {
		http.Error(w, "policy name required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		raw, err := s.Policies.Get(name)
		if err != nil {
			http.Error(w, "no such policy", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		_, _ = w.Write(raw)
	case http.MethodPut:
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 4096)
		for {
			n, err := r.Body.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
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
	names, err := s.Policies.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, names)
}

// ValidatePolicy checks that raw YAML parses into a policy.Policy.
func ValidatePolicy(raw []byte) error {
	var p policy.Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return err
	}
	return nil
}
