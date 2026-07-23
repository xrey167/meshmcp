package air

// Live-view types over the mesh: the rows a gateway's control endpoint and the
// served page render. Pure data — the mesh queries that populate them live in
// the main package.

// Session is one live resumable session in a gateway's control view (Air ·
// Steer): the backend it belongs to, its durable id, the peer that opened it,
// and its age in seconds.
type Session struct {
	Backend string `json:"backend"`
	ID      string `json:"id"`
	Peer    string `json:"peer"`
	PeerKey string `json:"peer_key,omitempty"`
	AgeSec  int    `json:"age_sec"`
}

// PeerRow is one reachable mesh identity in the served Air page's Nearby view:
// a WireGuard identity + mesh FQDN, never a claim.
type PeerRow struct {
	Status string `json:"status"`
	IP     string `json:"ip"`
	FQDN   string `json:"fqdn"`
	PubKey string `json:"pubkey"`
}
