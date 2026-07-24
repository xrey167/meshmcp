package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Checkpoint is a signed commitment to a contiguous run of audit records. It
// carries the Merkle root over the records' hashes and the chain head, is
// signed with the gateway's Ed25519 key, and links to the previous checkpoint.
// Checkpoints are what make the log NON-REPUDIABLE and EXTERNALLY VERIFIABLE:
// a third party holding only the gateway public key can confirm the log is
// complete and unedited, and an insider with write access to the file cannot
// forge one without the private key.
type Checkpoint struct {
	Version    int    `json:"version"`
	Seq        int    `json:"checkpoint_seq"` // 1-based checkpoint ordinal
	FromSeq    int    `json:"from_seq"`       // first record seq covered
	ToSeq      int    `json:"to_seq"`         // last record seq covered
	Count      int    `json:"count"`
	MerkleRoot string `json:"merkle_root"`     // hex, over record hashes [from,to]
	ChainHead  string `json:"chain_head"`      // hex, hash of record ToSeq
	PrevCP     string `json:"prev_checkpoint"` // hex, hash of the previous checkpoint ("" for the first)
	Time       string `json:"time"`
	PubKey     string `json:"pubkey"`    // hex Ed25519 public key of the signer
	Sig        string `json:"signature"` // hex Ed25519 signature over the checkpoint sans Sig
}

// signingBytes is the canonical byte string a checkpoint's signature covers:
// the JSON of the checkpoint with Sig cleared (PubKey is included, binding the
// signer identity into the signature).
func (c Checkpoint) signingBytes() []byte {
	c.Sig = ""
	b, _ := json.Marshal(c)
	return b
}

// Hash is the checkpoint's own hash (over its signed bytes plus signature),
// used to link the next checkpoint.
func (c Checkpoint) Hash() string {
	h := sha256.New()
	h.Write(c.signingBytes())
	h.Write([]byte(c.Sig))
	return hex.EncodeToString(h.Sum(nil))
}

// Signer holds a gateway Ed25519 key pair for signing checkpoints.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// GenerateSigner creates a fresh gateway signing key.
func GenerateSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv, pub: pub}, nil
}

// PubKeyHex is the hex-encoded public key others use to verify.
func (s *Signer) PubKeyHex() string { return hex.EncodeToString(s.pub) }

// PubKeyRaw returns a copy of the raw Ed25519 public key.
func (s *Signer) PubKeyRaw() []byte { return append([]byte(nil), s.pub...) }

// SignRaw returns an Ed25519 signature over msg. It is for out-of-band
// challenge-response (e.g. proving key possession when registering with a
// beacon), distinct from the checkpoint signing above.
func (s *Signer) SignRaw(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

// sign fills in PubKey and Sig on a checkpoint.
func (s *Signer) sign(c Checkpoint) Checkpoint {
	c.PubKey = s.PubKeyHex()
	c.Sig = hex.EncodeToString(ed25519.Sign(s.priv, c.signingBytes()))
	return c
}

// keyFile is the on-disk form of a signing key.
type keyFile struct {
	Private string `json:"private"` // hex Ed25519 seed (64-byte private key)
	Public  string `json:"public"`
}

// SaveSigner writes the key pair to path (0600).
func (s *Signer) SaveSigner(path string) error {
	kf := keyFile{
		Private: hex.EncodeToString(s.priv),
		Public:  s.PubKeyHex(),
	}
	b, _ := json.MarshalIndent(kf, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// LoadSigner reads a key pair written by SaveSigner.
func LoadSigner(path string) (*Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, err
	}
	priv, err := hex.DecodeString(kf.Private)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid signing key in %s", path)
	}
	p := ed25519.PrivateKey(priv)
	return &Signer{priv: p, pub: p.Public().(ed25519.PublicKey)}, nil
}

// VerifyCheckpoint checks a checkpoint's Ed25519 signature. If expectPub is
// non-empty, it must match the checkpoint's embedded PubKey (so a verifier
// pins the expected signer rather than trusting whatever key signed it).
func VerifyCheckpoint(c Checkpoint, expectPub string) error {
	if expectPub != "" && c.PubKey != expectPub {
		return fmt.Errorf("checkpoint %d signed by unexpected key %s", c.Seq, short(c.PubKey))
	}
	pub, err := hex.DecodeString(c.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("checkpoint %d has an invalid public key", c.Seq)
	}
	sig, err := hex.DecodeString(c.Sig)
	if err != nil {
		return fmt.Errorf("checkpoint %d has an invalid signature encoding", c.Seq)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), c.signingBytes(), sig) {
		return fmt.Errorf("checkpoint %d signature does not verify", c.Seq)
	}
	return nil
}
