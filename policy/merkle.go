package policy

import "crypto/sha256"

// Merkle tree with domain separation (RFC 6962 style): leaves are prefixed
// 0x00 and interior nodes 0x01, so a leaf can never be reinterpreted as an
// interior node. An odd node is promoted (not duplicated) to the next level.
// The audit checkpoints commit to the Merkle root of a batch of record hashes,
// so a single edited record changes the root and invalidates the signature.

var (
	leafPrefix = []byte{0x00}
	nodePrefix = []byte{0x01}
)

func leafHash(b []byte) [32]byte {
	h := sha256.New()
	h.Write(leafPrefix)
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write(nodePrefix)
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot returns the root over leaves (each leaf is arbitrary bytes, e.g. a
// record hash). The root of an empty list is the hash of the empty leaf, so a
// checkpoint over zero records is still well-defined.
func MerkleRoot(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return leafHash(nil)
	}
	level := make([][32]byte, len(leaves))
	for i, l := range leaves {
		level[i] = leafHash(l)
	}
	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // promote the odd node
			} else {
				next = append(next, nodeHash(level[i], level[i+1]))
			}
		}
		level = next
	}
	return level[0]
}
