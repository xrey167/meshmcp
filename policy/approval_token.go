package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Request-bound approvals (Phase 3). Unlike the ambient (peer, tool) co-sign,
// an ApprovalToken authorizes exactly ONE operation: a specific requesting peer
// calling a specific tool on a specific backend with a specific argument set,
// within a short TTL, exactly once. Changing the arguments, the backend, or the
// peer produces a different binding and the approval no longer matches.

// defaultApprovalTTL / maxApprovalTTL bound how long an approval is valid. The
// TTL cannot be accidentally disabled: a zero/negative configured TTL falls back
// to the default rather than "never expires".
const (
	defaultApprovalTTL = 5 * time.Minute
	maxApprovalTTL     = 1 * time.Hour
)

// canonicalArgsHash returns a stable hash of a tool call's arguments. JSON
// objects are canonicalized (Go's encoding/json sorts map keys), so semantically
// identical arguments hash equally regardless of key order or insignificant
// whitespace; arrays keep their order. Non-JSON bytes are hashed as-is.
func canonicalArgsHash(args []byte) string {
	var v any
	if len(args) > 0 && json.Unmarshal(args, &v) == nil {
		if canon, err := json.Marshal(v); err == nil {
			sum := sha256.Sum256(canon)
			return hex.EncodeToString(sum[:])
		}
	}
	sum := sha256.Sum256(args)
	return hex.EncodeToString(sum[:])
}

// ApprovalRequest is the exact operation being authorized. ArgsHash is the
// canonical hash of the tool call arguments.
type ApprovalRequest struct {
	PeerKey  string // requesting peer WireGuard public key (transport-proven)
	Backend  string
	Tool     string
	ArgsHash string
	Session  string // optional session id
}

// NewApprovalRequest builds a request from a caller, tool, and raw arguments.
func NewApprovalRequest(peerKey, backend, tool string, args []byte, session string) ApprovalRequest {
	return ApprovalRequest{
		PeerKey: peerKey, Backend: backend, Tool: tool,
		ArgsHash: canonicalArgsHash(args), Session: session,
	}
}

// bindingKey is the storage/lookup key: any change to peer, backend, tool, or
// arguments yields a different key, so an approval for one operation cannot be
// found for another.
func (r ApprovalRequest) bindingKey() string {
	h := sha256.Sum256([]byte(r.PeerKey + "\x00" + r.Backend + "\x00" + r.Tool + "\x00" + r.ArgsHash))
	return hex.EncodeToString(h[:])
}

// ApprovalToken is a signed, single-use, request-bound approval or denial.
type ApprovalToken struct {
	Version    int    `json:"v"`
	Nonce      string `json:"nonce"` // unique per approval (replay identifier)
	PeerKey    string `json:"peer_key"`
	Backend    string `json:"backend"`
	Tool       string `json:"tool"`
	ArgsHash   string `json:"args_hash"`
	Session    string `json:"session,omitempty"`
	Decision   string `json:"decision"` // "approve" | "deny"
	Approver   string `json:"approver"` // approving peer WireGuard key/identity
	PolicyHash string `json:"policy_hash,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
	PubKey     string `json:"pubkey"`        // signer (gateway) hex public key
	Sig        string `json:"sig,omitempty"` // Ed25519 over signingBytes
}

func (t ApprovalToken) signingBytes() []byte {
	t.Sig = ""
	b, _ := json.Marshal(t)
	return b
}

func (t ApprovalToken) request() ApprovalRequest {
	return ApprovalRequest{PeerKey: t.PeerKey, Backend: t.Backend, Tool: t.Tool, ArgsHash: t.ArgsHash, Session: t.Session}
}

// RequestApprovalStore atomically consumes a single-use, argument-bound
// approval. It must be safe for concurrent use: at most one caller may
// successfully consume a given approval.
type RequestApprovalStore interface {
	// ConsumeApproval reports whether a valid, non-expired, matching approval
	// existed and atomically consumes it (single-use). The reason explains a
	// false result. A nil store is treated as "no approvals".
	ConsumeApproval(req ApprovalRequest, now time.Time) (bool, string)
}

// FileApprovalStore is a RequestApprovalStore backed by a directory of signed,
// 0600 approval files, one per binding. Consumption is a single atomic rename,
// so a granted approval is honored exactly once even under concurrent callers.
type FileApprovalStore struct {
	Dir       string
	TTL       time.Duration
	signer    *Signer
	expectPub string // pinned signer public key (hex); required to trust a token
}

// NewFileApprovalStore builds a store. signer signs granted tokens (required to
// Grant). expectPub pins the trusted signer for consumption; if empty, the
// signer's own key is pinned. TTL is clamped to (0, maxApprovalTTL]; a
// non-positive TTL falls back to the default so it can never be disabled.
func NewFileApprovalStore(dir string, ttl time.Duration, signer *Signer) *FileApprovalStore {
	if ttl <= 0 {
		ttl = defaultApprovalTTL
	}
	if ttl > maxApprovalTTL {
		ttl = maxApprovalTTL
	}
	s := &FileApprovalStore{Dir: dir, TTL: ttl, signer: signer}
	if signer != nil {
		s.expectPub = signer.PubKeyHex()
	}
	return s
}

// PinSigner sets the pinned expected signer public key used at consume time
// (so a store that only verifies — no private key — can still pin trust).
func (s *FileApprovalStore) PinSigner(pubHex string) { s.expectPub = pubHex }

func (s *FileApprovalStore) file(bindingKey string) string {
	return filepath.Join(s.Dir, "approval-"+bindingKey+".json")
}

func newNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Grant signs and stores a single-use approval for req, attributed to approver.
// It fails if the store has no signer.
func (s *FileApprovalStore) Grant(req ApprovalRequest, approver, policyHash string, now time.Time) (ApprovalToken, error) {
	if s.signer == nil {
		return ApprovalToken{}, fmt.Errorf("approval store has no signing key")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return ApprovalToken{}, err
	}
	tok := ApprovalToken{
		Version: 1, Nonce: newNonce(),
		PeerKey: req.PeerKey, Backend: req.Backend, Tool: req.Tool, ArgsHash: req.ArgsHash, Session: req.Session,
		Decision: "approve", Approver: approver, PolicyHash: policyHash,
		CreatedAt: now.Unix(), ExpiresAt: now.Add(s.TTL).Unix(),
	}
	tok.PubKey = s.signer.PubKeyHex()
	tok.Sig = hex.EncodeToString(ed25519.Sign(s.signer.priv, tok.signingBytes()))
	b, _ := json.MarshalIndent(tok, "", "  ")
	// 0600: an approval is a bearer-ish authorization; restrict it.
	if err := os.WriteFile(s.file(req.bindingKey()), b, 0o600); err != nil {
		return ApprovalToken{}, err
	}
	return tok, nil
}

// verify checks a token's signature against the pinned key and its field
// integrity. A token with no pinned key is untrusted (returns false).
func (s *FileApprovalStore) verify(t ApprovalToken) bool {
	if s.expectPub == "" || t.PubKey != s.expectPub {
		return false
	}
	pub, err := hex.DecodeString(t.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(t.Sig)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), t.signingBytes(), sig)
}

// ConsumeApproval atomically claims and validates the approval bound to req.
// The claim is an os.Rename, which is atomic on POSIX, so exactly one concurrent
// caller can consume a given approval; the rest see no file (replay/double-use
// protection). A claimed file is always removed — an approval is spent whether
// or not it turned out valid.
func (s *FileApprovalStore) ConsumeApproval(req ApprovalRequest, now time.Time) (bool, string) {
	if s == nil {
		return false, "no approval store"
	}
	src := s.file(req.bindingKey())
	dst := src + ".used-" + newNonce()
	if err := os.Rename(src, dst); err != nil {
		// No file for this exact (peer, backend, tool, args): not approved. A
		// changed argument/backend/peer lands here because the binding key differs.
		return false, "no matching approval for this exact request"
	}
	defer os.Remove(dst) // single-use: the claimed approval is spent
	b, err := os.ReadFile(dst)
	if err != nil {
		return false, "approval unreadable"
	}
	var tok ApprovalToken
	if json.Unmarshal(b, &tok) != nil {
		return false, "approval malformed"
	}
	if !s.verify(tok) {
		return false, "approval signature invalid or signer not pinned"
	}
	if tok.Decision != "approve" {
		return false, "operation was explicitly denied"
	}
	// Defense in depth: the token's own fields must match the request (the
	// filename already binds them, this catches tampering/collisions).
	if tok.request().bindingKey() != req.bindingKey() {
		return false, "approval does not match this request"
	}
	if now.Unix() > tok.ExpiresAt {
		return false, "approval expired"
	}
	return true, ""
}
