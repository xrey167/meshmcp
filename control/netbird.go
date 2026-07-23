package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// Doer is the subset of *http.Client the issuer needs (injectable for tests).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// NetBirdIssuer turns enrollment into real, scoped, short-lived key issuance by
// calling the NetBird management API. Each enrollment mints a one-off,
// ephemeral setup key scoped to configured groups — so a node gets exactly one
// join, auto-expiring, revocable — and appends an entry to a tamper-evident
// enrollment audit trail. This is what makes "managed control plane" a reason
// to adopt meshmcp rather than hand-managing NetBird keys.
type NetBirdIssuer struct {
	APIURL        string        // e.g. https://api.netbird.io
	ManagementURL string        // handed to enrollees (defaults to APIURL)
	Token         string        // NetBird PAT
	Groups        []string      // auto_groups to place the node in
	TTL           time.Duration // key expiry (default 24h)
	RegistryDir   string        // echoed to the node
	ControlNode   string        // this control node's name

	Client Doer             // defaults to http.DefaultClient
	Audit  *policy.AuditLog // enrollment audit trail (optional; carries its own clock)
}

// setupKeyRequest is the NetBird create-setup-key payload.
type setupKeyRequest struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	ExpiresIn  int      `json:"expires_in"` // seconds
	AutoGroups []string `json:"auto_groups"`
	UsageLimit int      `json:"usage_limit"`
	Ephemeral  bool     `json:"ephemeral"`
}

// setupKeyResponse is the subset of the NetBird response we use.
type setupKeyResponse struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	Name    string `json:"name"`
	Expires string `json:"expires"`
}

// Enroll implements EnrollFunc: it mints a one-off key for the node.
func (n *NetBirdIssuer) Enroll(req EnrollRequest) (EnrollResponse, error) {
	ttl := n.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	body, _ := json.Marshal(setupKeyRequest{
		Name:       "meshmcp-enroll-" + req.Node,
		Type:       "one-off",
		ExpiresIn:  int(ttl.Seconds()),
		AutoGroups: n.Groups,
		UsageLimit: 1,
		Ephemeral:  true,
	})
	httpReq, err := http.NewRequest(http.MethodPost, n.APIURL+"/api/setup-keys", bytes.NewReader(body))
	if err != nil {
		return EnrollResponse{}, err
	}
	httpReq.Header.Set("Authorization", "Token "+n.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	client := n.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		n.auditEnroll(req.Node, "deny", "netbird API unreachable: "+err.Error())
		return EnrollResponse{}, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		n.auditEnroll(req.Node, "deny", fmt.Sprintf("netbird API %d", resp.StatusCode))
		return EnrollResponse{}, fmt.Errorf("netbird setup-key create failed (%d): %s", resp.StatusCode, string(rb))
	}
	var sk setupKeyResponse
	if err := json.Unmarshal(rb, &sk); err != nil || sk.Key == "" {
		n.auditEnroll(req.Node, "deny", "netbird API returned no key")
		return EnrollResponse{}, fmt.Errorf("netbird returned no usable key: %s", string(rb))
	}

	n.auditEnroll(req.Node, "allow", "issued one-off key "+sk.ID+" (expires "+sk.Expires+")")

	mgmt := n.ManagementURL
	if mgmt == "" {
		mgmt = n.APIURL
	}
	return EnrollResponse{
		ManagementURL: mgmt,
		SetupKey:      sk.Key,
		Registry:      n.RegistryDir,
		ControlNode:   n.ControlNode,
	}, nil
}

// auditEnroll appends an entry to the tamper-evident enrollment audit trail.
func (n *NetBirdIssuer) auditEnroll(node, decision, reason string) {
	n.auditPeer(node, "enroll", decision, reason)
}

// auditPeer appends a control-plane peer action (enroll / deregister) to the
// tamper-evident audit trail.
func (n *NetBirdIssuer) auditPeer(node, method, decision, reason string) {
	if n.Audit == nil {
		return
	}
	n.Audit.Append(policy.AuditRecord{
		Backend:  "control",
		Peer:     node,
		Method:   method,
		Decision: decision,
		Reason:   reason,
	})
}

// peerSummary is the subset of a NetBird /api/peers entry we use.
type peerSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
}

// PeerIDByName resolves a peer's NetBird id from its name or hostname. It is the
// lookup half of deregistration: a node knows its own device name, but peer
// removal is keyed by the management-assigned id. It returns a clear error when
// no peer matches, so a caller never deletes the wrong peer on a stale name.
func (n *NetBirdIssuer) PeerIDByName(name string) (string, error) {
	httpReq, err := http.NewRequest(http.MethodGet, n.APIURL+"/api/peers", nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Token "+n.Token)

	client := n.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("netbird list peers failed (%d): %s", resp.StatusCode, string(rb))
	}
	var peers []peerSummary
	if err := json.Unmarshal(rb, &peers); err != nil {
		return "", fmt.Errorf("netbird returned an unparseable peer list: %w", err)
	}
	for _, p := range peers {
		if p.Name == name || p.Hostname == name {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("no NetBird peer named %q", name)
}

// DeletePeer removes a peer from the NetBird account via the management API
// (DELETE /api/peers/{id}), mirroring Enroll's auth + audit discipline. Peer
// removal originates only here — the control node is the sole holder of the PAT —
// so a node that has torn down its local state can also be deregistered from the
// management plane, closing the "deleted binary, still-enrolled identity" gap.
func (n *NetBirdIssuer) DeletePeer(peerID string) error {
	if peerID == "" {
		return fmt.Errorf("netbird delete peer: empty peer id")
	}
	httpReq, err := http.NewRequest(http.MethodDelete, n.APIURL+"/api/peers/"+url.PathEscape(peerID), nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Token "+n.Token)

	client := n.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		n.auditPeer(peerID, "deregister", "deny", "netbird API unreachable: "+err.Error())
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		n.auditPeer(peerID, "deregister", "deny", fmt.Sprintf("netbird API %d", resp.StatusCode))
		return fmt.Errorf("netbird delete peer failed (%d): %s", resp.StatusCode, string(rb))
	}
	n.auditPeer(peerID, "deregister", "allow", "removed peer "+peerID)
	return nil
}

// Deregister looks up a node by name and removes it from the NetBird account —
// the convenience path a control operator uses to finish `air remove` on the
// management side.
func (n *NetBirdIssuer) Deregister(node string) error {
	id, err := n.PeerIDByName(node)
	if err != nil {
		n.auditPeer(node, "deregister", "deny", err.Error())
		return err
	}
	return n.DeletePeer(id)
}
