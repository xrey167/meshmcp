package policy

import (
	"testing"
	"time"
)

func TestPolicyValidateRejectsSilentFailures(t *testing.T) {
	cases := []struct {
		name string
		pol  Policy
		bad  bool
	}{
		{"good", Policy{Rules: []Rule{{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true, Rate: &RateLimit{Max: 5, Per: "1m"}}}}, false},
		{"bad glob", Policy{Rules: []Rule{{Tools: []string{"read_["}, Allow: true}}}, true},
		{"rate max<=0", Policy{Rules: []Rule{{Tools: []string{"x"}, Allow: true, Rate: &RateLimit{Max: 0, Per: "1m"}}}}, true},
		{"bad per", Policy{Rules: []Rule{{Tools: []string{"x"}, Allow: true, Rate: &RateLimit{Max: 5, Per: "banana"}}}}, true},
		{"bad tz", Policy{Rules: []Rule{{Tools: []string{"x"}, Allow: true, When: &Window{TZ: "Mars/Olympus"}}}}, true},
		{"bad hours", Policy{Rules: []Rule{{Tools: []string{"x"}, Allow: true, When: &Window{Hours: "9 to 5"}}}}, true},
		{"bad day", Policy{Rules: []Rule{{Tools: []string{"x"}, Allow: true, When: &Window{Days: []string{"funday"}}}}}, true},
		{"empty rule", Policy{Rules: []Rule{{Peers: []string{"*"}, Allow: true}}}, true},
	}
	for _, c := range cases {
		err := c.pol.Validate()
		if c.bad && err == nil {
			t.Errorf("%s: expected validation error, got nil", c.name)
		}
		if !c.bad && err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
	}
}

// TestMalformedWindowFailsClosed proves a malformed hours range makes the
// window inactive (rule falls through), not always-on (S16).
func TestMalformedWindowFailsClosed(t *testing.T) {
	w := &Window{Hours: "not-a-range"}
	if w.active(time.Now()) {
		t.Fatal("malformed window is active (fail-open)")
	}
}
