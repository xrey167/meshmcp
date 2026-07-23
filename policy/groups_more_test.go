package policy

import "testing"

// TestStaticGroupsMembership pins the member-pattern forms directly: a
// "pubkey:" pattern matches ONLY the key (never the FQDN), FQDN patterns match
// exact/wildcard/glob, matching is case-sensitive, an unknown group or empty
// resolver matches nothing, and one malformed glob does not poison later
// patterns in the same group.
func TestStaticGroupsMembership(t *testing.T) {
	g := StaticGroups{
		"admins": {"pubkey:alice-key", "ops-*.netbird.cloud"},
		"all":    {"*"},
		"exact":  {"db.netbird.cloud"},
		// A malformed glob ("[" never closes) followed by a valid member: the
		// bad pattern is skipped, not fatal for the whole group.
		"mixed": {"[bad-glob", "pubkey:carol-key"},
		"empty": {},
	}

	tests := []struct {
		name             string
		key, fqdn, group string
		want             bool
	}{
		{"pubkey member matches by key", "alice-key", "whatever.host", "admins", true},
		{"pubkey pattern never matches an FQDN", "", "pubkey:alice-key", "admins", false},
		{"non-member key falls through to fqdn glob", "bob-key", "ops-3.netbird.cloud", "admins", true},
		{"fqdn glob non-match", "bob-key", "intern.netbird.cloud", "admins", false},
		{"glob is case-sensitive", "bob-key", "OPS-3.netbird.cloud", "admins", false},
		{"star matches anyone", "", "anything.at.all", "all", true},
		{"exact fqdn matches", "", "db.netbird.cloud", "exact", true},
		{"exact fqdn is not a prefix match", "", "db.netbird.cloud.evil", "exact", false},
		{"unknown group matches nobody", "alice-key", "ops-1.netbird.cloud", "ghosts", false},
		{"empty group matches nobody", "alice-key", "ops-1.netbird.cloud", "empty", false},
		{"malformed glob is skipped, later member still matches", "carol-key", "x", "mixed", true},
		{"malformed glob does not glob-match anything", "", "[bad-glob-x", "mixed", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.InGroup(tc.key, tc.fqdn, tc.group); got != tc.want {
				t.Fatalf("InGroup(%q, %q, %q) = %v, want %v", tc.key, tc.fqdn, tc.group, got, tc.want)
			}
		})
	}

	// A nil/empty resolver value matches nothing at all.
	var none StaticGroups
	if none.InGroup("alice-key", "ops-1.netbird.cloud", "admins") {
		t.Fatal("empty resolver must match nobody")
	}
}
