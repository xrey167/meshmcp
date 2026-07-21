package control

import (
	"net/http"
	"path/filepath"
	"sync"

	"meshmcp/registry"
)

// F25 · Multi-tenant control plane.
//
// TenantServer serves many isolated control planes over one dark endpoint. Each
// request is resolved to a tenant by the caller's CRYPTOGRAPHIC IDENTITY (not a
// path or header the caller chooses) and dispatched to that tenant's own Server
// — its own policy store, registry, and enrollment. A caller can only ever
// reach its own tenant's namespace, so tenant A can neither read nor write
// tenant B's policies or registry: isolation is by construction. An identity
// that maps to no tenant is refused (deny is the safe default).
type TenantServer struct {
	// Identify resolves the caller's (pubkey, fqdn) from the request — the mesh
	// transport identity, exactly as the Air control endpoint does.
	Identify func(*http.Request) (pubkey, fqdn string)
	// Resolve maps a caller identity to a tenant id; "" denies the request.
	Resolve func(pubkey, fqdn string) string
	// Build constructs a tenant's scoped Server. Called once per tenant, cached.
	Build func(tenant string) (*Server, error)

	mu    sync.Mutex
	cache map[string]*Server
}

// server returns the tenant's Server, building and caching it on first use.
func (t *TenantServer) server(tenant string) (*Server, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cache == nil {
		t.cache = map[string]*Server{}
	}
	if s, ok := t.cache[tenant]; ok {
		return s, nil
	}
	s, err := t.Build(tenant)
	if err != nil {
		return nil, err
	}
	t.cache[tenant] = s
	return s, nil
}

// Handler resolves each request to the caller's tenant and dispatches to that
// tenant's scoped Server. No route can cross a tenant boundary.
func (t *TenantServer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pub, fqdn := t.Identify(r)
		tenant := t.Resolve(pub, fqdn)
		if tenant == "" {
			http.Error(w, "caller is not enrolled in any tenant", http.StatusForbidden)
			return
		}
		s, err := t.server(tenant)
		if err != nil {
			http.Error(w, "tenant unavailable: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.Handler().ServeHTTP(w, r)
	})
}

// NewFileTenantServer builds a TenantServer whose per-tenant Servers keep their
// policy store and registry under baseDir/<tenant>/… — giving each tenant
// physically separate storage (and therefore separate audit/enrollment state).
// enroll is optional and applied to every tenant Server (nil ⇒ enrollment 501).
func NewFileTenantServer(baseDir string, identify func(*http.Request) (string, string), resolve func(pubkey, fqdn string) string, enroll EnrollFunc) *TenantServer {
	return &TenantServer{
		Identify: identify,
		Resolve:  resolve,
		Build: func(tenant string) (*Server, error) {
			ps, err := NewFilePolicyStore(filepath.Join(baseDir, tenant, "policies"))
			if err != nil {
				return nil, err
			}
			reg, err := registry.NewFileRegistry(filepath.Join(baseDir, tenant, "registry"))
			if err != nil {
				return nil, err
			}
			return &Server{Policies: ps, Reg: reg, Enroll: enroll}, nil
		},
	}
}
