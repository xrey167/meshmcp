package policy

import (
	"crypto/sha256"
	"testing"
)

// refLeaf / refNode recompute the RFC 6962 hashes byte-for-byte in the test,
// independent of merkle.go's helpers, so a dropped domain prefix or a changed
// tree shape shows up as a root mismatch.
func refLeaf(b []byte) [32]byte {
	return sha256.Sum256(append([]byte{0x00}, b...))
}

func refNode(l, r [32]byte) [32]byte {
	buf := append([]byte{0x01}, l[:]...)
	return sha256.Sum256(append(buf, r[:]...))
}

// TestMerkleRootMatchesHandComputed pins the exact tree shape for the small
// sizes: single leaf, a full pair, the odd 3-leaf tree (whose third leaf is
// PROMOTED to the top level, not duplicated), and a power-of-two 4-leaf tree.
func TestMerkleRootMatchesHandComputed(t *testing.T) {
	a, b, c, d := []byte("a"), []byte("b"), []byte("c"), []byte("d")
	la, lb, lc, ld := refLeaf(a), refLeaf(b), refLeaf(c), refLeaf(d)

	tests := []struct {
		name   string
		leaves [][]byte
		want   [32]byte
	}{
		{"single leaf is its own root", [][]byte{a}, la},
		{"two leaves", [][]byte{a, b}, refNode(la, lb)},
		// Odd tree: level1 = [node(la,lb), lc] — lc promoted unchanged — then
		// root = node(node(la,lb), lc). The duplicate-last variant would
		// instead compute node(node(la,lb), node(lc,lc)).
		{"three leaves promote the odd node", [][]byte{a, b, c}, refNode(refNode(la, lb), lc)},
		{"four leaves", [][]byte{a, b, c, d}, refNode(refNode(la, lb), refNode(lc, ld))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MerkleRoot(tc.leaves); got != tc.want {
				t.Fatalf("root = %x, want %x", got, tc.want)
			}
		})
	}
}

// TestMerkleEmptyLeaves: the empty log has the well-defined root leafHash(nil),
// and nil vs empty slice agree.
func TestMerkleEmptyLeaves(t *testing.T) {
	want := refLeaf(nil)
	if got := MerkleRoot(nil); got != want {
		t.Fatalf("empty root = %x, want leafHash(nil) = %x", got, want)
	}
	if MerkleRoot([][]byte{}) != MerkleRoot(nil) {
		t.Fatal("nil and empty leaf lists must share a root")
	}
}

// TestMerkleOddNodePromotedNotDuplicated: if the implementation duplicated the
// odd node (the Bitcoin-style bug enabling CVE-2012-2459-class mutation),
// [a,b,c] and [a,b,c,c] would collide. Promotion keeps them distinct.
func TestMerkleOddNodePromotedNotDuplicated(t *testing.T) {
	odd := MerkleRoot([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	dup := MerkleRoot([][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("c")})
	if odd == dup {
		t.Fatal("a 3-leaf tree must not share its root with the duplicated 4-leaf tree")
	}
}

// TestMerkleLeafNodeDomainSeparation: without the 0x00/0x01 prefixes, a single
// leaf whose bytes equal the concatenated child hashes of [a, b] would produce
// the same root as [a, b] — a second-preimage forgery. Domain separation keeps
// the two roots distinct.
func TestMerkleLeafNodeDomainSeparation(t *testing.T) {
	la, lb := refLeaf([]byte("a")), refLeaf([]byte("b"))
	forged := append(append([]byte{}, la[:]...), lb[:]...) // 64 bytes: la || lb
	if MerkleRoot([][]byte{forged}) == MerkleRoot([][]byte{[]byte("a"), []byte("b")}) {
		t.Fatal("a leaf crafted from two child hashes must not collide with the 2-leaf tree")
	}
}
