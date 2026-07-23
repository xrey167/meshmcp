package air

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var presenceTestNow = time.Date(2026, time.July, 22, 12, 30, 0, 0, time.UTC)

func validAnnouncement(name string) Announcement {
	return Announcement{
		Version:    PresenceSchema,
		Name:       name,
		Kind:       NodeAgent,
		Status:     StatusAvailable,
		TTLSeconds: 60,
		Services: []Service{{
			Kind:         ServiceSteer,
			Port:         9120,
			Protocol:     "tcp",
			Capabilities: []string{"nudge", "task"},
		}},
	}
}

func mustUpsert(t *testing.T, r *Registry, id VerifiedIdentity, ip string, a Announcement, now time.Time) Presence {
	t.Helper()
	p, _, err := r.Upsert(id, ip, a, now)
	if err != nil {
		t.Fatalf("Upsert(%q): %v", a.Name, err)
	}
	return p
}

func mustParsePresenceTime(t *testing.T, value string) time.Time {
	t.Helper()
	got, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("parse presence time %q: %v", value, err)
	}
	return got
}

func tokens(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%03d", prefix, i)
	}
	return out
}

func TestAnnouncementNormalizedDefaultsOrderingAndDeepCopy(t *testing.T) {
	progress := 25
	raw := Announcement{
		Name:       "analyst",
		Kind:       NodeAgent,
		TTLSeconds: 1,
		Labels:     []string{"zeta", "alpha", "zeta"},
		Services: []Service{
			{Kind: ServiceSteer, Port: 9120, Capabilities: []string{"task", "nudge", "task"}},
			{Kind: ServiceMCP, Port: 8080, Protocol: "http", Capabilities: []string{"tools"}},
		},
		Activity: &Activity{Progress: &progress},
	}

	got := raw.Normalized()
	if got.Version != PresenceSchema || got.Status != StatusAvailable {
		t.Fatalf("defaults not applied: %+v", got)
	}
	if got.TTLSeconds != MinPresenceTTLSeconds {
		t.Fatalf("TTL = %d, want clamp to %d", got.TTLSeconds, MinPresenceTTLSeconds)
	}
	if want := []string{"alpha", "zeta"}; !reflect.DeepEqual(got.Labels, want) {
		t.Fatalf("labels = %q, want %q", got.Labels, want)
	}
	if len(got.Services) != 2 || got.Services[0].Kind != ServiceMCP || got.Services[1].Kind != ServiceSteer {
		t.Fatalf("services not sorted by kind: %+v", got.Services)
	}
	if got.Services[1].Protocol != "tcp" {
		t.Fatalf("default protocol = %q, want tcp", got.Services[1].Protocol)
	}
	if want := []string{"nudge", "task"}; !reflect.DeepEqual(got.Services[1].Capabilities, want) {
		t.Fatalf("capabilities = %q, want %q", got.Services[1].Capabilities, want)
	}

	got.Labels[0] = "changed"
	got.Services[1].Capabilities[0] = "changed"
	got.Activity.Title = "changed"
	*got.Activity.Progress = 99
	if !reflect.DeepEqual(raw.Labels, []string{"zeta", "alpha", "zeta"}) {
		t.Fatalf("Normalized aliased input labels: %q", raw.Labels)
	}
	if !reflect.DeepEqual(raw.Services[0].Capabilities, []string{"task", "nudge", "task"}) {
		t.Fatalf("Normalized aliased input capabilities: %q", raw.Services[0].Capabilities)
	}
	if raw.Activity.Title != "" || progress != 25 {
		t.Fatalf("Normalized aliased input activity: %+v progress=%d", raw.Activity, progress)
	}
	if raw.Version != "" || raw.Status != "" || raw.TTLSeconds != 1 {
		t.Fatalf("Normalized mutated scalar input: %+v", raw)
	}

	high := validAnnouncement("high")
	high.TTLSeconds = MaxPresenceTTLSeconds + 1
	if got := high.Normalized().TTLSeconds; got != MaxPresenceTTLSeconds {
		t.Fatalf("high TTL = %d, want clamp to %d", got, MaxPresenceTTLSeconds)
	}
	defaults := Announcement{Name: "defaults", Kind: NodeDevice}
	if got := defaults.Normalized().TTLSeconds; got != DefaultPresenceTTLSeconds {
		t.Fatalf("default TTL = %d, want %d", got, DefaultPresenceTTLSeconds)
	}
}

func TestAnnouncementValidateEnumsAndProtocols(t *testing.T) {
	for _, kind := range []NodeKind{NodeAgent, NodeDevice, NodeGateway, NodeService} {
		t.Run("node_"+string(kind), func(t *testing.T) {
			a := validAnnouncement("node")
			a.Kind = kind
			if err := a.Validate(); err != nil {
				t.Fatalf("valid node kind %q rejected: %v", kind, err)
			}
		})
	}
	for _, status := range []PresenceStatus{StatusAvailable, StatusBusy, StatusFocus, StatusAway} {
		t.Run("status_"+string(status), func(t *testing.T) {
			a := validAnnouncement("node")
			a.Status = status
			if err := a.Validate(); err != nil {
				t.Fatalf("valid status %q rejected: %v", status, err)
			}
		})
	}

	serviceKinds := []ServiceKind{
		ServiceMCP, ServiceControl, ServiceSteer, ServiceInbox, ServiceRing,
		ServiceCast, ServiceScreen, ServiceApprovals, ServiceHome,
	}
	all := validAnnouncement("all-services")
	all.Services = make([]Service, len(serviceKinds))
	for i, kind := range serviceKinds {
		all.Services[i] = Service{Kind: kind, Port: 8000 + i}
	}
	if err := all.Validate(); err != nil {
		t.Fatalf("valid service kinds rejected: %v", err)
	}

	for _, protocol := range []string{"", "tcp", "http", "https"} {
		t.Run("protocol_"+protocol, func(t *testing.T) {
			a := validAnnouncement("protocol")
			a.Services[0].Protocol = protocol
			if err := a.Validate(); err != nil {
				t.Fatalf("valid protocol %q rejected: %v", protocol, err)
			}
		})
	}

	for _, kind := range []ActivityKind{ActivitySession, ActivityTask, ActivityWorkflow, ActivityApproval, ActivityKnowledge} {
		for _, state := range []ActivityState{
			ActivityQueued, ActivityRunning, ActivityBlocked, ActivityCompleted, ActivityFailed, ActivityCancelled,
		} {
			t.Run("activity_"+string(kind)+"_"+string(state), func(t *testing.T) {
				a := validAnnouncement("activity")
				a.Activity = &Activity{
					Schema: ActivitySchema,
					ID:     "activity-1",
					Kind:   kind,
					Title:  "Safe activity",
					State:  state,
				}
				if err := a.Validate(); err != nil {
					t.Fatalf("valid activity enum rejected: %v", err)
				}
			})
		}
	}
}

func TestAnnouncementValidateRejectsUnsafeAndOversizedInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Announcement)
	}{
		{"wrong version", func(a *Announcement) { a.Version = "air.presence/v2" }},
		{"empty name", func(a *Announcement) { a.Name = "" }},
		{"whitespace name", func(a *Announcement) { a.Name = "   " }},
		{"leading name whitespace", func(a *Announcement) { a.Name = " analyst" }},
		{"trailing name whitespace", func(a *Announcement) { a.Name = "analyst " }},
		{"long name", func(a *Announcement) { a.Name = strings.Repeat("n", maxPresenceName+1) }},
		{"control in name", func(a *Announcement) { a.Name = "node\x1b[31m" }},
		{"unknown node kind", func(a *Announcement) { a.Kind = "computer" }},
		{"unknown status", func(a *Announcement) { a.Status = "offline" }},
		{"negative TTL", func(a *Announcement) { a.TTLSeconds = -1 }},
		{"too many labels", func(a *Announcement) { a.Labels = tokens("label", maxPresenceLabels+1) }},
		{"long label", func(a *Announcement) { a.Labels = []string{strings.Repeat("l", maxPresenceLabel+1)} }},
		{"empty label", func(a *Announcement) { a.Labels = []string{""} }},
		{"unsafe label", func(a *Announcement) { a.Labels = []string{"terminal\x1b"} }},
		{"too many services", func(a *Announcement) {
			a.Services = make([]Service, maxPresenceServices+1)
			for i := range a.Services {
				a.Services[i] = Service{Kind: ServiceMCP, Port: 8000 + i}
			}
		}},
		{"unknown service", func(a *Announcement) { a.Services[0].Kind = "shell" }},
		{"zero port", func(a *Announcement) { a.Services[0].Port = 0 }},
		{"high port", func(a *Announcement) { a.Services[0].Port = 65536 }},
		{"unsupported protocol", func(a *Announcement) { a.Services[0].Protocol = "udp" }},
		{"duplicate service", func(a *Announcement) {
			a.Services = append(a.Services, Service{Kind: ServiceSteer, Port: 9121})
		}},
		{"claimed address", func(a *Announcement) { a.Services[0].Address = "203.0.113.8:9120" }},
		{"too many capabilities", func(a *Announcement) {
			a.Services[0].Capabilities = tokens("cap", maxServiceCapabilities+1)
		}},
		{"long capability", func(a *Announcement) {
			a.Services[0].Capabilities = []string{strings.Repeat("c", maxServiceCapability+1)}
		}},
		{"empty capability", func(a *Announcement) { a.Services[0].Capabilities = []string{""} }},
		{"unsafe capability", func(a *Announcement) { a.Services[0].Capabilities = []string{"task\nrun"} }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := validAnnouncement("valid")
			tc.mutate(&a)
			if err := a.Validate(); err == nil {
				t.Fatalf("unsafe announcement accepted: %+v", a)
			}
		})
	}

	atLimits := validAnnouncement(strings.Repeat("n", maxPresenceName))
	atLimits.Labels = tokens("label", maxPresenceLabels)
	atLimits.Services[0].Port = 65535
	atLimits.Services[0].Capabilities = tokens("cap", maxServiceCapabilities)
	if err := atLimits.Validate(); err != nil {
		t.Fatalf("values at documented limits rejected: %v", err)
	}

	// Duplicate presentation hints are harmlessly canonicalized rather than
	// producing unstable cards or material-change noise.
	duplicates := validAnnouncement("duplicates")
	duplicates.Labels = []string{"blue", "blue", "green"}
	duplicates.Services[0].Capabilities = []string{"task", "task", "nudge"}
	if err := duplicates.Validate(); err != nil {
		t.Fatalf("canonicalizable duplicates rejected: %v", err)
	}
	n := duplicates.Normalized()
	if !reflect.DeepEqual(n.Labels, []string{"blue", "green"}) ||
		!reflect.DeepEqual(n.Services[0].Capabilities, []string{"nudge", "task"}) {
		t.Fatalf("duplicates not canonicalized: labels=%q capabilities=%q", n.Labels, n.Services[0].Capabilities)
	}
}

func TestActivityValidateSchemaContextTargetAndBounds(t *testing.T) {
	progress := 40
	hexDigest := strings.Repeat("a", 64)
	base := Activity{
		Schema:     ActivitySchema,
		ID:         "work_01",
		Kind:       ActivityTask,
		Title:      "Review the plan",
		Summary:    "A privacy-safe description",
		State:      ActivityRunning,
		Progress:   &progress,
		Target:     "task:work-01",
		ContextRef: "sha256:" + hexDigest,
		Handoff:    true,
		Revision:   7,
		UpdatedAt:  "2026-07-22T12:30:00+02:00",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid activity rejected: %v", err)
	}
	for _, target := range []string{"agent:analyst", "session:session-1", "task:work-01", "group:reviewers"} {
		t.Run("target_"+target, func(t *testing.T) {
			a := base
			a.Target = target
			if err := a.Validate(); err != nil {
				t.Fatalf("valid target %q rejected: %v", target, err)
			}
		})
	}
	atTargetLimit := base
	atTargetLimit.Target = "task:" + strings.Repeat("x", maxActivityTarget-len("task:"))
	if err := atTargetLimit.Validate(); err != nil {
		t.Fatalf("target at %d-byte limit rejected: %v", maxActivityTarget, err)
	}
	for _, ref := range []string{"sha256:" + hexDigest, "blake3:" + hexDigest, "kh_" + hexDigest, ""} {
		t.Run("context_"+strings.SplitN(ref, ":", 2)[0], func(t *testing.T) {
			a := base
			a.ContextRef = ref
			if err := a.Validate(); err != nil {
				t.Fatalf("valid context ref %q rejected: %v", ref, err)
			}
		})
	}

	tests := []struct {
		name   string
		mutate func(*Activity)
	}{
		{"wrong schema", func(a *Activity) { a.Schema = "air.activity/v2" }},
		{"empty id", func(a *Activity) { a.ID = "" }},
		{"unsafe id", func(a *Activity) { a.ID = "work/id" }},
		{"long id", func(a *Activity) { a.ID = strings.Repeat("a", maxActivityID+1) }},
		{"unknown kind", func(a *Activity) { a.Kind = "command" }},
		{"empty title", func(a *Activity) { a.Title = "" }},
		{"long title", func(a *Activity) { a.Title = strings.Repeat("t", maxActivityTitle+1) }},
		{"control in title", func(a *Activity) { a.Title = "title\x1b[2J" }},
		{"long summary", func(a *Activity) { a.Summary = strings.Repeat("s", maxActivitySummary+1) }},
		{"control in summary", func(a *Activity) { a.Summary = "summary\nsecret" }},
		{"unknown state", func(a *Activity) { a.State = "paused" }},
		{"negative progress", func(a *Activity) { p := -1; a.Progress = &p }},
		{"high progress", func(a *Activity) { p := 101; a.Progress = &p }},
		{"malformed target", func(a *Activity) { a.Target = "task" }},
		{"empty target value", func(a *Activity) { a.Target = "task:" }},
		{"unknown target kind", func(a *Activity) { a.Target = "pod:work-01" }},
		{"control in target", func(a *Activity) { a.Target = "task:work\x1b[31m" }},
		{"unbounded target", func(a *Activity) {
			a.Target = "task:" + strings.Repeat("x", maxActivityTarget-len("task:")+1)
		}},
		{"context prefix", func(a *Activity) { a.ContextRef = "md5:" + hexDigest }},
		{"context length", func(a *Activity) { a.ContextRef = "sha256:" + strings.Repeat("a", 63) }},
		{"context non-hex", func(a *Activity) { a.ContextRef = "sha256:" + strings.Repeat("z", 64) }},
		{"long context", func(a *Activity) { a.ContextRef = "sha256:" + strings.Repeat("a", maxActivityContextRef) }},
		{"bad update time", func(a *Activity) { a.UpdatedAt = "yesterday" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			tc.mutate(&a)
			if err := a.Validate(); err == nil {
				t.Fatalf("invalid activity accepted: %+v", a)
			}
		})
	}

	for _, p := range []int{0, 100} {
		a := base
		a.Progress = &p
		if err := a.Validate(); err != nil {
			t.Fatalf("boundary progress %d rejected: %v", p, err)
		}
	}
	withoutOptional := base
	withoutOptional.Progress = nil
	withoutOptional.Target = ""
	withoutOptional.ContextRef = ""
	withoutOptional.UpdatedAt = ""
	if err := withoutOptional.Validate(); err != nil {
		t.Fatalf("omitted optional activity fields rejected: %v", err)
	}
}

func TestRegistryUpsertStampsIdentityIPAndDerivedAddress(t *testing.T) {
	// Unknown identity-shaped JSON fields are not part of Announcement and do
	// not influence the identity stamped by the authenticated transport.
	wire := []byte(`{
		"version":"air.presence/v1",
		"name":"analyst",
		"kind":"agent",
		"services":[{"kind":"control","port":8443,"protocol":"https"}],
		"public_key":"forged-key",
		"fqdn":"attacker.example",
		"ip":"203.0.113.66"
	}`)
	var raw Announcement
	if err := json.Unmarshal(wire, &raw); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		ip      string
		address string
	}{
		{"IPv4", "192.0.2.44", "192.0.2.44:8443"},
		{"IPv6", "2001:db8::44", "[2001:db8::44]:8443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry(4)
			id := VerifiedIdentity{PublicKey: "verified-key", FQDN: "analyst.mesh.example"}
			p, changed, err := r.Upsert(id, tc.ip, raw, presenceTestNow)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Fatal("first Upsert reported unchanged")
			}
			if p.PublicKey != id.PublicKey || p.FQDN != id.FQDN || p.IP != tc.ip {
				t.Fatalf("transport identity not stamped: %+v", p)
			}
			if p.Version != PresenceSchema || p.Status != StatusAvailable {
				t.Fatalf("announcement defaults not materialized: %+v", p)
			}
			if len(p.Services) != 1 || p.Services[0].Address != tc.address {
				t.Fatalf("derived address = %+v, want %q", p.Services, tc.address)
			}
			if p.Services[0].Address != net.JoinHostPort(tc.ip, "8443") {
				t.Fatalf("address is not host/port safe: %q", p.Services[0].Address)
			}
			if raw.Services[0].Address != "" {
				t.Fatalf("Upsert mutated caller's service address: %+v", raw.Services[0])
			}
			if got := mustParsePresenceTime(t, p.SeenAt); !got.Equal(presenceTestNow) {
				t.Fatalf("SeenAt = %s, want %s", got, presenceTestNow)
			}
			wantExpiry := presenceTestNow.Add(DefaultPresenceTTLSeconds * time.Second)
			if got := mustParsePresenceTime(t, p.ExpiresAt); !got.Equal(wantExpiry) {
				t.Fatalf("ExpiresAt = %s, want %s", got, wantExpiry)
			}
		})
	}
}

func TestRegistryRejectsInvalidVerifiedIdentityAndObservedIP(t *testing.T) {
	tests := []struct {
		name string
		id   VerifiedIdentity
		ip   string
	}{
		{"empty public key", VerifiedIdentity{FQDN: "node.mesh"}, "192.0.2.1"},
		{"long public key", VerifiedIdentity{PublicKey: strings.Repeat("k", maxPresenceIdentityText+1)}, "192.0.2.1"},
		{"control in public key", VerifiedIdentity{PublicKey: "key\nforged"}, "192.0.2.1"},
		{"long FQDN", VerifiedIdentity{PublicKey: "key", FQDN: strings.Repeat("f", maxPresenceIdentityText+1)}, "192.0.2.1"},
		{"control in FQDN", VerifiedIdentity{PublicKey: "key", FQDN: "node\x1b.mesh"}, "192.0.2.1"},
		{"empty IP", VerifiedIdentity{PublicKey: "key"}, ""},
		{"host instead of IP", VerifiedIdentity{PublicKey: "key"}, "node.mesh"},
		{"IP with port", VerifiedIdentity{PublicKey: "key"}, "192.0.2.1:80"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry(1)
			if _, _, err := r.Upsert(tc.id, tc.ip, validAnnouncement("node"), presenceTestNow); err == nil {
				t.Fatal("invalid verified identity or observed IP accepted")
			}
			if got := r.List(presenceTestNow); len(got) != 0 {
				t.Fatalf("failed Upsert changed registry: %+v", got)
			}
		})
	}
}

func TestRegistryTTLClampAndExactExpiry(t *testing.T) {
	// Fractional time catches accidental RFC3339 second truncation, which would
	// make a minimum-TTL card expire almost one second early.
	now := presenceTestNow.Add(987654321 * time.Nanosecond)
	tests := []struct {
		name string
		ttl  int
		want int
	}{
		{"default", 0, DefaultPresenceTTLSeconds},
		{"low clamp", 1, MinPresenceTTLSeconds},
		{"minimum", MinPresenceTTLSeconds, MinPresenceTTLSeconds},
		{"maximum", MaxPresenceTTLSeconds, MaxPresenceTTLSeconds},
		{"high clamp", MaxPresenceTTLSeconds + 200, MaxPresenceTTLSeconds},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry(1)
			a := validAnnouncement("ttl")
			a.TTLSeconds = tc.ttl
			p := mustUpsert(t, r, VerifiedIdentity{PublicKey: "ttl-key"}, "192.0.2.9", a, now)
			if got := mustParsePresenceTime(t, p.SeenAt); !got.Equal(now) {
				t.Fatalf("SeenAt = %s, want exact %s", got, now)
			}
			deadline := now.Add(time.Duration(tc.want) * time.Second)
			if got := mustParsePresenceTime(t, p.ExpiresAt); !got.Equal(deadline) {
				t.Fatalf("ExpiresAt = %s, want exact %s", got, deadline)
			}
			if got := r.List(deadline.Add(-time.Nanosecond)); len(got) != 1 {
				t.Fatalf("card expired before deadline: %+v", got)
			}
			if got := r.List(deadline); len(got) != 0 {
				t.Fatalf("card remained at expiry deadline: %+v", got)
			}
		})
	}

	r := NewRegistry(1)
	a := validAnnouncement("negative")
	a.TTLSeconds = -1
	if _, _, err := r.Upsert(VerifiedIdentity{PublicKey: "negative-key"}, "192.0.2.1", a, now); err == nil {
		t.Fatal("negative TTL accepted through Upsert")
	}
}

func TestRegistryHeartbeatChangedFlag(t *testing.T) {
	r := NewRegistry(2)
	id := VerifiedIdentity{PublicKey: "heartbeat-key", FQDN: "heartbeat.mesh"}
	raw := validAnnouncement("Heartbeat")
	raw.Labels = []string{"zeta", "alpha", "zeta"}
	raw.Services = []Service{
		{Kind: ServiceSteer, Port: 9120, Capabilities: []string{"task", "nudge", "task"}},
		{Kind: ServiceMCP, Port: 8080, Protocol: "http"},
	}
	first, changed, err := r.Upsert(id, "192.0.2.10", raw, presenceTestNow)
	if err != nil || !changed {
		t.Fatalf("initial Upsert changed=%v err=%v", changed, err)
	}

	heartbeat := validAnnouncement("Heartbeat")
	heartbeat.Labels = []string{"alpha", "zeta"}
	heartbeat.Services = []Service{
		{Kind: ServiceMCP, Port: 8080, Protocol: "http"},
		{Kind: ServiceSteer, Port: 9120, Protocol: "tcp", Capabilities: []string{"nudge", "task"}},
	}
	second, changed, err := r.Upsert(id, "192.0.2.10", heartbeat, presenceTestNow.Add(5*time.Second))
	if err != nil || changed {
		t.Fatalf("canonical-equivalent heartbeat changed=%v err=%v", changed, err)
	}
	if first.SeenAt == second.SeenAt || first.ExpiresAt == second.ExpiresAt {
		t.Fatalf("heartbeat did not refresh timestamps: first=%+v second=%+v", first, second)
	}

	material := heartbeat
	material.Status = StatusBusy
	_, changed, err = r.Upsert(id, "192.0.2.10", material, presenceTestNow.Add(10*time.Second))
	if err != nil || !changed {
		t.Fatalf("material status update changed=%v err=%v", changed, err)
	}
	_, changed, err = r.Upsert(
		VerifiedIdentity{PublicKey: id.PublicKey, FQDN: "renamed.mesh"},
		"192.0.2.10", material, presenceTestNow.Add(15*time.Second),
	)
	if err != nil || !changed {
		t.Fatalf("verified FQDN update changed=%v err=%v", changed, err)
	}
}

func TestRegistryCopiesCallerAndReturnedCards(t *testing.T) {
	progress := 20
	raw := validAnnouncement("copy-safe")
	raw.Labels = []string{"green", "blue"}
	raw.Activity = &Activity{
		Schema:   ActivitySchema,
		ID:       "copy-1",
		Kind:     ActivityTask,
		Title:    "Copy test",
		State:    ActivityRunning,
		Progress: &progress,
	}
	r := NewRegistry(1)
	id := VerifiedIdentity{PublicKey: "copy-key", FQDN: "copy.mesh"}
	card := mustUpsert(t, r, id, "192.0.2.20", raw, presenceTestNow)

	// Neither caller-owned input nor the returned card may alias registry state.
	raw.Labels[0] = "raw-mutated"
	raw.Services[0].Capabilities[0] = "raw-mutated"
	*raw.Activity.Progress = 91
	card.Labels[0] = "return-mutated"
	card.Services[0].Capabilities[0] = "return-mutated"
	card.Activity.Title = "return-mutated"
	*card.Activity.Progress = 92

	listed := r.List(presenceTestNow)
	if len(listed) != 1 {
		t.Fatalf("List = %+v", listed)
	}
	wantLabels := []string{"blue", "green"}
	wantCapabilities := []string{"nudge", "task"}
	if !reflect.DeepEqual(listed[0].Labels, wantLabels) ||
		!reflect.DeepEqual(listed[0].Services[0].Capabilities, wantCapabilities) ||
		listed[0].Activity.Title != "Copy test" || *listed[0].Activity.Progress != 20 {
		t.Fatalf("registry was mutated through input/return alias: %+v", listed[0])
	}

	// List and Resolve each return independent deep copies too.
	listed[0].Labels[0] = "list-mutated"
	listed[0].Services[0].Capabilities[0] = "list-mutated"
	*listed[0].Activity.Progress = 93
	resolved, err := r.Resolve("copy-safe", ServiceSteer, presenceTestNow)
	if err != nil {
		t.Fatal(err)
	}
	resolved.Node.Labels[0] = "resolved-node-mutated"
	resolved.Node.Services[0].Capabilities[0] = "resolved-node-mutated"
	resolved.Service.Capabilities[0] = "resolved-service-mutated"
	*resolved.Node.Activity.Progress = 94

	again := r.List(presenceTestNow)
	if !reflect.DeepEqual(again[0].Labels, wantLabels) ||
		!reflect.DeepEqual(again[0].Services[0].Capabilities, wantCapabilities) ||
		again[0].Activity.Title != "Copy test" || *again[0].Activity.Progress != 20 {
		t.Fatalf("registry was mutated through List/Resolve alias: %+v", again[0])
	}
	if resolved.Node.Services[0].Capabilities[0] == resolved.Service.Capabilities[0] {
		t.Fatalf("resolved Node and Service share capability storage: %+v", resolved)
	}
}

func TestRegistryCapacityRemovalAndExpiredSlotReuse(t *testing.T) {
	if got := NewRegistry(0).max; got != DefaultPresenceRegistryMax {
		t.Fatalf("zero max = %d, want default %d", got, DefaultPresenceRegistryMax)
	}
	if got := NewRegistry(-1).max; got != DefaultPresenceRegistryMax {
		t.Fatalf("negative max = %d, want default %d", got, DefaultPresenceRegistryMax)
	}
	empty := NewRegistry(2).List(presenceTestNow)
	if empty == nil || len(empty) != 0 {
		t.Fatalf("empty List = %#v, want non-nil empty slice", empty)
	}

	r := NewRegistry(2)
	a := validAnnouncement("one")
	mustUpsert(t, r, VerifiedIdentity{PublicKey: "key-one"}, "192.0.2.1", a, presenceTestNow)
	a.Name = "two"
	mustUpsert(t, r, VerifiedIdentity{PublicKey: "key-two"}, "192.0.2.2", a, presenceTestNow)
	a.Name = "three"
	if _, _, err := r.Upsert(VerifiedIdentity{PublicKey: "key-three"}, "192.0.2.3", a, presenceTestNow); err == nil {
		t.Fatal("registry accepted a new record beyond capacity")
	}

	update := validAnnouncement("one-updated")
	if _, changed, err := r.Upsert(VerifiedIdentity{PublicKey: "key-one"}, "192.0.2.1", update, presenceTestNow); err != nil || !changed {
		t.Fatalf("existing owner could not update at capacity: changed=%v err=%v", changed, err)
	}
	if r.Remove("missing") {
		t.Fatal("Remove reported a missing key as removed")
	}
	if !r.Remove("key-two") || r.Remove("key-two") {
		t.Fatal("Remove did not report first/second deletion correctly")
	}
	mustUpsert(t, r, VerifiedIdentity{PublicKey: "key-three"}, "192.0.2.3", a, presenceTestNow)

	// Upsert prunes before enforcing capacity, so a crashed node's expired slot
	// can be reused without a separate List call.
	r = NewRegistry(1)
	expiring := validAnnouncement("expiring")
	expiring.TTLSeconds = MinPresenceTTLSeconds
	mustUpsert(t, r, VerifiedIdentity{PublicKey: "old-key"}, "192.0.2.10", expiring, presenceTestNow)
	replacement := validAnnouncement("replacement")
	mustUpsert(
		t, r, VerifiedIdentity{PublicKey: "new-key"}, "192.0.2.11", replacement,
		presenceTestNow.Add(MinPresenceTTLSeconds*time.Second),
	)
	got := r.List(presenceTestNow.Add(MinPresenceTTLSeconds * time.Second))
	if len(got) != 1 || got[0].PublicKey != "new-key" {
		t.Fatalf("expired slot was not reused: %+v", got)
	}
}

func TestRegistryConcurrentCapacityEnforced(t *testing.T) {
	const (
		capacity = 16
		workers  = 64
	)
	r := NewRegistry(capacity)
	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := r.Upsert(
				VerifiedIdentity{PublicKey: fmt.Sprintf("capacity-key-%03d", i)},
				fmt.Sprintf("192.0.2.%d", i+1),
				validAnnouncement(fmt.Sprintf("capacity-node-%03d", i)),
				presenceTestNow,
			)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, rejected int
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			rejected++
		}
	}
	if succeeded != capacity || rejected != workers-capacity {
		t.Fatalf("concurrent capacity: succeeded=%d rejected=%d, want %d/%d", succeeded, rejected, capacity, workers-capacity)
	}
	if got := len(r.List(presenceTestNow)); got != capacity {
		t.Fatalf("registry contains %d concurrent records, want capacity %d", got, capacity)
	}
}

func TestRegistryConcurrentUpsertListAndResolve(t *testing.T) {
	const (
		workers    = 48
		iterations = 20
	)
	r := NewRegistry(workers)
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("node-%03d", i)
			key := fmt.Sprintf("key-%03d", i)
			ip := fmt.Sprintf("192.0.2.%d", i+1)
			_, _, err := r.Upsert(
				VerifiedIdentity{PublicKey: key, FQDN: name + ".mesh"}, ip,
				validAnnouncement(name), presenceTestNow,
			)
			if err != nil {
				errs <- fmt.Errorf("initial worker %d: %w", i, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	if got := r.List(presenceTestNow); len(got) != workers {
		t.Fatalf("concurrent inserts produced %d cards, want %d", len(got), workers)
	}

	// Exercise readers alongside heartbeat writers. Each writer owns one key,
	// while all synchronization of shared registry state remains internal.
	errCount := workers + 4
	errs = make(chan error, errCount)
	start = make(chan struct{})
	wg = sync.WaitGroup{}
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("node-%03d", i)
			key := fmt.Sprintf("key-%03d", i)
			ip := fmt.Sprintf("192.0.2.%d", i+1)
			for j := 1; j <= iterations; j++ {
				if _, changed, err := r.Upsert(
					VerifiedIdentity{PublicKey: key, FQDN: name + ".mesh"}, ip,
					validAnnouncement(name), presenceTestNow.Add(time.Duration(j)*time.Second),
				); err != nil || changed {
					errs <- fmt.Errorf("heartbeat worker %d iteration %d: changed=%v err=%v", i, j, changed, err)
					return
				}
			}
		}()
	}
	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				if got := r.List(presenceTestNow.Add(30 * time.Second)); len(got) != workers {
					errs <- fmt.Errorf("concurrent List returned %d cards, want %d", len(got), workers)
					return
				}
				if _, err := r.Resolve("node-000", ServiceSteer, presenceTestNow.Add(30*time.Second)); err != nil {
					errs <- fmt.Errorf("concurrent Resolve: %w", err)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestRegistryListStableOrdering(t *testing.T) {
	r := NewRegistry(8)
	entries := []struct {
		key  string
		fqdn string
		name string
	}{
		{"key-5", "z.mesh", "Zulu"},
		{"key-2", "b.mesh", "Bravo"},
		{"key-4", "a.mesh", "bravo"},
		{"key-1", "z.mesh", "alpha"},
		{"key-3", "a.mesh", "Bravo"},
	}
	for i, entry := range entries {
		mustUpsert(
			t, r, VerifiedIdentity{PublicKey: entry.key, FQDN: entry.fqdn},
			fmt.Sprintf("192.0.2.%d", i+1), validAnnouncement(entry.name), presenceTestNow,
		)
	}
	want := []string{"key-1", "key-3", "key-4", "key-2", "key-5"}
	for attempt := 0; attempt < 3; attempt++ {
		gotCards := r.List(presenceTestNow)
		got := make([]string, len(gotCards))
		for i := range gotCards {
			got[i] = gotCards[i].PublicKey
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("List order attempt %d = %q, want %q", attempt, got, want)
		}
	}
}

func TestResolvePresenceSelectorsServicesAndErrors(t *testing.T) {
	r := NewRegistry(4)
	analyst := validAnnouncement("Analyst")
	analyst.Services = []Service{
		{Kind: ServiceMCP, Port: 8080, Protocol: "http", Capabilities: []string{"tools"}},
		{Kind: ServiceSteer, Port: 9120},
	}
	analystCard := mustUpsert(
		t, r, VerifiedIdentity{PublicKey: "full-analyst-key", FQDN: "analyst.mesh.example"},
		"192.0.2.40", analyst, presenceTestNow,
	)
	builder := validAnnouncement("Builder")
	builder.Services = []Service{{Kind: ServiceMCP, Port: 8081}}
	mustUpsert(
		t, r, VerifiedIdentity{PublicKey: "full-builder-key", FQDN: "builder.mesh.example"},
		"192.0.2.41", builder, presenceTestNow,
	)

	selectors := []string{
		"full-analyst-key",
		"pubkey:full-analyst-key",
		"ANALYST.MESH.EXAMPLE",
		"analyst",
		"  Analyst  ",
	}
	for _, selector := range selectors {
		t.Run("selector_"+strings.ReplaceAll(selector, " ", "_"), func(t *testing.T) {
			got, err := r.Resolve(selector, ServiceSteer, presenceTestNow)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", selector, err)
			}
			if got.Node.PublicKey != "full-analyst-key" || got.Service.Kind != ServiceSteer || got.Service.Port != 9120 {
				t.Fatalf("Resolve(%q) = %+v", selector, got)
			}
			if got.Service.Address != "192.0.2.40:9120" {
				t.Fatalf("Resolve(%q) address = %q", selector, got.Service.Address)
			}
		})
	}

	errors := []struct {
		name     string
		selector string
		kind     ServiceKind
	}{
		{"empty selector", "", ServiceSteer},
		{"whitespace selector", "   ", ServiceSteer},
		{"empty prefixed key", "pubkey:", ServiceSteer},
		{"short key", "full-analyst", ServiceSteer},
		{"missing node", "missing", ServiceSteer},
		{"missing service", "Builder", ServiceSteer},
		{"invalid service kind", "Analyst", "shell"},
	}
	for _, tc := range errors {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := r.Resolve(tc.selector, tc.kind, presenceTestNow); err == nil {
				t.Fatalf("Resolve(%q, %q) unexpectedly succeeded", tc.selector, tc.kind)
			}
		})
	}

	duplicateName := clonePresence(analystCard)
	duplicateName.PublicKey = "other-key"
	duplicateName.FQDN = "other.mesh.example"
	if _, err := ResolvePresence([]Presence{analystCard, duplicateName}, "analyst", ServiceSteer); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate name did not fail as ambiguous: %v", err)
	}

	// The explicit pubkey: form must be key-only. A node cannot claim a name or
	// FQDN that hijacks, or even makes ambiguous, an exact public-key lookup.
	spoof := clonePresence(analystCard)
	spoof.Name = "pubkey:full-analyst-key"
	spoof.FQDN = "spoof.mesh.example"
	spoof.PublicKey = "attacker-key"
	got, err := ResolvePresence([]Presence{spoof, analystCard}, "pubkey:full-analyst-key", ServiceSteer)
	if err != nil || got.Node.PublicKey != analystCard.PublicKey {
		t.Fatalf("prefixed key was confused by a claimed name: got=%+v err=%v", got, err)
	}
	spoof.Name = "pubkey:missing-key"
	if got, err := ResolvePresence([]Presence{spoof}, "pubkey:missing-key", ServiceSteer); err == nil {
		t.Fatalf("prefixed missing key resolved by claimed name: %+v", got)
	}

	// Transport-stamped identity selectors outrank client-authored friendly
	// names. A peer may choose a confusing name, but it must not shadow or make
	// ambiguous a real key or FQDN that is present in the directory.
	shadow := clonePresence(analystCard)
	shadow.PublicKey = "attacker-key"
	shadow.FQDN = "attacker.mesh.example"
	shadow.Name = analystCard.PublicKey
	got, err = ResolvePresence([]Presence{shadow, analystCard}, analystCard.PublicKey, ServiceSteer)
	if err != nil || got.Node.PublicKey != analystCard.PublicKey {
		t.Fatalf("friendly name shadowed raw public key: got=%+v err=%v", got, err)
	}
	shadow.Name = "Other"
	shadow.FQDN = analystCard.PublicKey
	got, err = ResolvePresence([]Presence{shadow, analystCard}, analystCard.PublicKey, ServiceSteer)
	if err != nil || got.Node.PublicKey != analystCard.PublicKey {
		t.Fatalf("verified FQDN shadowed raw public key: got=%+v err=%v", got, err)
	}
	shadow.FQDN = "attacker.mesh.example"
	shadow.Name = strings.ToUpper(analystCard.FQDN)
	got, err = ResolvePresence([]Presence{shadow, analystCard}, analystCard.FQDN, ServiceSteer)
	if err != nil || got.Node.PublicKey != analystCard.PublicKey {
		t.Fatalf("friendly name shadowed verified FQDN: got=%+v err=%v", got, err)
	}

	// Ambiguity is still rejected, but only among matches in the selected trust
	// tier. This also defends callers of ResolvePresence that supply an arbitrary
	// projection rather than Registry.List's one-card-per-key output.
	duplicateKey := clonePresence(analystCard)
	duplicateKey.Name = "Other"
	duplicateKey.FQDN = "other.mesh.example"
	if _, err := ResolvePresence([]Presence{analystCard, duplicateKey}, analystCard.PublicKey, ServiceSteer); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate key did not fail as ambiguous: %v", err)
	}
	duplicateFQDN := clonePresence(analystCard)
	duplicateFQDN.PublicKey = "other-key"
	duplicateFQDN.Name = "Other"
	if _, err := ResolvePresence([]Presence{analystCard, duplicateFQDN}, analystCard.FQDN, ServiceSteer); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate verified FQDN did not fail as ambiguous: %v", err)
	}
}

func TestResolvePresenceBoundsAndDoesNotReflectSelectors(t *testing.T) {
	atLimit := strings.Repeat("k", MaxPresenceSelectorBytes)
	card := Presence{
		Name:      "Safe node",
		PublicKey: atLimit,
		Services:  []Service{{Kind: ServiceSteer, Port: 9120}},
	}
	if got, err := ResolvePresence([]Presence{card}, atLimit, ServiceSteer); err != nil || got.Node.PublicKey != atLimit {
		t.Fatalf("selector at %d-byte limit: got=%+v err=%v", MaxPresenceSelectorBytes, got, err)
	}

	tests := []struct {
		name     string
		selector string
	}{
		{name: "empty", selector: ""},
		{name: "trimmed empty", selector: "\u2003  \u2003"},
		{name: "oversized", selector: "SENSITIVE-" + strings.Repeat("x", MaxPresenceSelectorBytes)},
		{name: "invalid utf8", selector: "SENSITIVE-" + string([]byte{0xff})},
		{name: "C0 control", selector: "SENSITIVE\nselector"},
		{name: "DEL control", selector: "SENSITIVE\x7fselector"},
		{name: "C1 control", selector: "SENSITIVE\u0085selector"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolvePresence([]Presence{card}, tc.selector, ServiceSteer)
			if err == nil {
				t.Fatalf("unsafe selector was accepted")
			}
			if (tc.selector != "" && strings.Contains(err.Error(), tc.selector)) || strings.Contains(err.Error(), "SENSITIVE") {
				t.Fatalf("resolver reflected selector in error %q", err)
			}
		})
	}

	for _, tc := range []struct {
		name string
		list []Presence
		kind ServiceKind
	}{
		{name: "not found", kind: ServiceSteer},
		{name: "missing service", list: []Presence{{Name: "SENSITIVE", PublicKey: "key"}}, kind: ServiceSteer},
		{
			name: "ambiguous",
			list: []Presence{
				{Name: "SENSITIVE", PublicKey: "key-1", Services: []Service{{Kind: ServiceSteer, Port: 9120}}},
				{Name: "SENSITIVE", PublicKey: "key-2", Services: []Service{{Kind: ServiceSteer, Port: 9121}}},
			},
			kind: ServiceSteer,
		},
	} {
		t.Run("non-reflection "+tc.name, func(t *testing.T) {
			_, err := ResolvePresence(tc.list, "SENSITIVE", tc.kind)
			if err == nil {
				t.Fatalf("expected resolver error")
			}
			if strings.Contains(err.Error(), "SENSITIVE") {
				t.Fatalf("resolver reflected selector in error %q", err)
			}
		})
	}
}

// TestGroupSelectorPrefixReserved proves no single-target resolver can ever
// resolve a `group:`-prefixed selector — even when a presence card literally
// names itself "group:x" — so the group fan-out grammar cannot be shadowed by
// client-authored presentation metadata. Fail closed, like the pubkey: carve-out.
func TestGroupSelectorPrefixReserved(t *testing.T) {
	shadow := Presence{
		Name:      "group:oncall",
		FQDN:      "shadow.mesh.example",
		PublicKey: "shadow-key",
		Services:  []Service{{Kind: ServiceRing, Port: 9120, Address: "192.0.2.9:9120"}},
	}

	for _, selector := range []string{"group:oncall", "group:", "  group:oncall  "} {
		t.Run("selector "+strings.TrimSpace(selector), func(t *testing.T) {
			if err := ValidatePresenceSelector(selector); err == nil || !strings.Contains(err.Error(), "reserved for group fan-out") {
				t.Fatalf("ValidatePresenceSelector(%q) = %v, want reserved-prefix error", selector, err)
			}
			if _, err := ResolvePresence([]Presence{shadow}, selector, ServiceRing); err == nil || !strings.Contains(err.Error(), "reserved for group fan-out") {
				t.Fatalf("ResolvePresence(%q) = %v, want reserved-prefix error", selector, err)
			}
			if _, err := ResolvePresenceIdentity([]Presence{shadow}, selector); err == nil || !strings.Contains(err.Error(), "reserved for group fan-out") {
				t.Fatalf("ResolvePresenceIdentity(%q) = %v, want reserved-prefix error", selector, err)
			}
		})
	}

	// The registry resolver shares the same validation, so the reservation
	// holds even for a card the registry accepted under that name.
	r := NewRegistry(4)
	a := validAnnouncement("group:oncall")
	mustUpsert(t, r, VerifiedIdentity{PublicKey: "shadow-key", FQDN: "shadow.mesh.example"}, "192.0.2.9", a, presenceTestNow)
	if _, err := r.Resolve("group:oncall", ServiceSteer, presenceTestNow); err == nil || !strings.Contains(err.Error(), "reserved for group fan-out") {
		t.Fatalf("Registry.Resolve(group:oncall) = %v, want reserved-prefix error", err)
	}
}
