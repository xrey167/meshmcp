package main

import (
	_ "embed"
	"net/http"
)

//go:embed site/agent-os.css
var agentOSCSS []byte

// registerAgentOSAssets installs the shared, same-origin visual foundation on
// each independent web surface. Authorization/Host/CSRF wrappers remain owned
// by the parent surface and therefore cover this route exactly like its page.
func registerAgentOSAssets(mux *http.ServeMux) {
	mux.HandleFunc("/assets/agent-os.css", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(agentOSCSS)
	})
}
