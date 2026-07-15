package insight

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"meshmcp/policy"
)

// DetectOptions tunes anomaly scoring.
type DetectOptions struct {
	RateFactor        float64 // spike threshold = baseline p99 × factor (default 3.0)
	DenyRateThreshold float64 // deny fraction over the recent window to flag (default 0.5)
	Window            int     // recent-record window for the deny-rate check (default 20)
}

func (o DetectOptions) withDefaults() DetectOptions {
	if o.RateFactor <= 0 {
		o.RateFactor = 3.0
	}
	if o.DenyRateThreshold <= 0 {
		o.DenyRateThreshold = 0.5
	}
	if o.Window <= 0 {
		o.Window = 20
	}
	return o
}

// Anomaly is a scored deviation from the learned baseline.
type Anomaly struct {
	Peer     string  `json:"peer"`
	PeerKey  string  `json:"peer_key,omitempty"`
	Tool     string  `json:"tool,omitempty"`
	Kind     string  `json:"kind"` // unknown-identity | new-tool | rate-spike | off-hours | deny-spike | label-egress
	Detail   string  `json:"detail"`
	Score    float64 `json:"score"`
	Time     string  `json:"time,omitempty"`
	Response string  `json:"response"` // recommended action
}

// baselineID is the precomputed baseline view of one identity.
type baselineID struct {
	tools    map[string]bool
	toolP99  map[string]int
	emitsLab bool
	minH     int
	maxH     int
	bounded  bool // baseline has a clean weekday hour window
}

// Detect streams new audit records against a learned baseline and scores
// deviations. Crucially, an anomaly on an otherwise-allowed call is routed to a
// human co-sign, not a hard block — detection is fail-to-human, not fail-closed,
// so a false positive slows an agent down rather than breaking it. This is the
// "detect + respond" layer that turns prevent-and-record into a platform.
func Detect(baseline Corpus, newR io.Reader, opts DetectOptions) ([]Anomaly, error) {
	opts = opts.withDefaults()

	base := map[string]*baselineID{}
	for k, ip := range baseline.Identities {
		b := &baselineID{tools: map[string]bool{}, toolP99: map[string]int{}, emitsLab: len(ip.EmittedLabels) > 0}
		for _, tp := range ip.Tools {
			b.tools[tp.Tool] = true
			b.toolP99[tp.Tool] = tp.PerMinP99
		}
		b.minH, b.maxH, b.bounded = ip.activeHourBounds()
		base[k] = b
	}

	var out []Anomaly
	seenNewTool := map[string]bool{}
	seenUnknown := map[string]bool{}
	perMinute := map[string]int{}    // id+tool+minute -> count
	seenSpike := map[string]bool{}   // id+tool+minute already flagged
	denyRecent := map[string][]bool{} // id -> recent allow(false)/deny(true) window

	sc := bufio.NewScanner(newR)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec policy.AuditRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		k := idKey(rec.Peer, rec.PeerKey)
		b := base[k]

		// Deny-rate tracking (all decided records for this identity).
		if rec.Decision == "allow" || rec.Decision == "deny" || rec.Decision == "cosign" {
			w := append(denyRecent[k], rec.Decision == "deny")
			if len(w) > opts.Window {
				w = w[len(w)-opts.Window:]
			}
			denyRecent[k] = w
			if len(w) >= opts.Window {
				denies := 0
				for _, d := range w {
					if d {
						denies++
					}
				}
				if frac := float64(denies) / float64(len(w)); frac >= opts.DenyRateThreshold {
					key := "deny:" + k
					if !seenUnknown[key] { // reuse dedupe set to emit once per burst
						seenUnknown[key] = true
						out = append(out, Anomaly{Peer: rec.Peer, PeerKey: rec.PeerKey, Kind: "deny-spike", Score: 0.85,
							Detail: fmt.Sprintf("%.0f%% of recent calls denied — misconfigured or compromised agent", frac*100),
							Time: rec.Time, Response: "investigate; consider suspending the identity"})
					}
				}
			}
		}

		if b == nil {
			if !seenUnknown[k] {
				seenUnknown[k] = true
				out = append(out, Anomaly{Peer: rec.Peer, PeerKey: rec.PeerKey, Kind: "unknown-identity", Score: 1.0,
					Detail: "identity has no baseline — never seen before", Time: rec.Time, Response: "open co-sign / require enrollment"})
			}
			continue
		}
		if rec.Tool == "" {
			continue
		}

		// New tool for this identity.
		if !b.tools[rec.Tool] {
			ntk := k + "\x00" + rec.Tool
			if !seenNewTool[ntk] {
				seenNewTool[ntk] = true
				out = append(out, Anomaly{Peer: rec.Peer, PeerKey: rec.PeerKey, Tool: rec.Tool, Kind: "new-tool", Score: 0.8,
					Detail: "tool never used by this identity in the baseline", Time: rec.Time, Response: "open co-sign"})
			}
		}

		// Rate spike vs baseline p99.
		if min, ok := minuteOf(rec.Time); ok {
			mk := fmt.Sprintf("%s\x00%s\x00%d", k, rec.Tool, min)
			perMinute[mk]++
			p99 := b.toolP99[rec.Tool]
			thresh := int(float64(p99)*opts.RateFactor + 0.5)
			if p99 > 0 && perMinute[mk] > thresh && !seenSpike[mk] {
				seenSpike[mk] = true
				out = append(out, Anomaly{Peer: rec.Peer, PeerKey: rec.PeerKey, Tool: rec.Tool, Kind: "rate-spike", Score: 0.7,
					Detail: fmt.Sprintf("%d calls this minute vs baseline p99 %d", perMinute[mk], p99), Time: rec.Time, Response: "rate-limit / open co-sign"})
			}
		}

		// Off-hours vs a bounded baseline window.
		if b.bounded {
			if t, err := time.Parse(time.RFC3339, rec.Time); err == nil {
				h := t.UTC().Hour()
				if h < b.minH || h > b.maxH {
					out = append(out, Anomaly{Peer: rec.Peer, PeerKey: rec.PeerKey, Tool: rec.Tool, Kind: "off-hours", Score: 0.5,
						Detail: fmt.Sprintf("active at %02d:00 UTC, baseline window %02d:00-%02d:00", h, b.minH, b.maxH+1), Time: rec.Time, Response: "open co-sign"})
				}
			}
		}

		// A label-emitting identity using an egress tool.
		if b.emitsLab && looksEgress(rec.Tool) && rec.Decision == "allow" {
			out = append(out, Anomaly{Peer: rec.Peer, PeerKey: rec.PeerKey, Tool: rec.Tool, Kind: "label-egress", Score: 0.9,
				Detail: "identity that emits sensitive labels called an external-egress tool", Time: rec.Time, Response: "open co-sign; consider a block_labels guard"})
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out, nil
}

// activeHourBounds returns the [min,max] active UTC hours if the identity has a
// clean weekday-only footprint, else bounded=false.
func (ip *IdentityProfile) activeHourBounds() (minH, maxH int, bounded bool) {
	if !ip.HasTimes || ip.Days[0] > 0 || ip.Days[6] > 0 {
		return 0, 0, false
	}
	minH, maxH = -1, -1
	for h := 0; h < 24; h++ {
		if ip.Hours[h] > 0 {
			if minH < 0 {
				minH = h
			}
			maxH = h
		}
	}
	if minH < 0 || (minH == 0 && maxH == 23) {
		return 0, 0, false
	}
	return minH, maxH, true
}

func minuteOf(ts string) (int64, bool) {
	if ts == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return t.UTC().Truncate(time.Minute).Unix(), true
}
