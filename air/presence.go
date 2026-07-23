package air

// Presence is the identity-stamped connective layer for Air. An agent or
// device announces only product metadata (name, status, service ports, and an
// optional privacy-safe Activity card). The Air control endpoint supplies the
// network identity and observed IP from the authenticated mesh transport.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// PresenceSchema and ActivitySchema version the two portable JSON contracts.
	PresenceSchema = "air.presence/v1"
	ActivitySchema = "air.activity/v1"

	DefaultPresenceTTLSeconds  = 90
	MinPresenceTTLSeconds      = 15
	MaxPresenceTTLSeconds      = 300
	DefaultPresenceRegistryMax = 2048

	// MaxPresenceSelectorBytes bounds the untrusted name, FQDN, or full-key
	// selector accepted by ResolvePresence before it scans the directory.
	MaxPresenceSelectorBytes = 512

	maxPresenceName         = 128
	maxPresenceLabels       = 16
	maxPresenceLabel        = 64
	maxPresenceServices     = 16
	maxServiceCapabilities  = 16
	maxServiceCapability    = 64
	maxActivityID           = 64
	maxActivityTitle        = 160
	maxActivitySummary      = 512
	maxActivityTarget       = 256
	maxActivityContextRef   = 128
	maxPresenceIdentityText = MaxPresenceSelectorBytes
)

// NodeKind describes what a Presence card represents. It affects presentation,
// never authorization.
type NodeKind string

const (
	NodeAgent   NodeKind = "agent"
	NodeDevice  NodeKind = "device"
	NodeGateway NodeKind = "gateway"
	NodeService NodeKind = "service"
)

func (k NodeKind) valid() bool {
	switch k {
	case NodeAgent, NodeDevice, NodeGateway, NodeService:
		return true
	default:
		return false
	}
}

// PresenceStatus is the node's coarse availability. Focus is explicit so a
// caller can avoid interrupting a busy human or agent without learning private
// details about the work.
type PresenceStatus string

const (
	StatusAvailable PresenceStatus = "available"
	StatusBusy      PresenceStatus = "busy"
	StatusFocus     PresenceStatus = "focus"
	StatusAway      PresenceStatus = "away"
)

func (s PresenceStatus) valid() bool {
	switch s {
	case StatusAvailable, StatusBusy, StatusFocus, StatusAway:
		return true
	default:
		return false
	}
}

// ServiceKind is one Air interaction a node knows how to receive. A service
// card advertises discoverability only; the receiver's ACL/policy still decides
// whether an action is allowed.
type ServiceKind string

const (
	ServiceMCP       ServiceKind = "mcp"
	ServiceControl   ServiceKind = "control"
	ServiceSteer     ServiceKind = "steer"
	ServiceInbox     ServiceKind = "inbox"
	ServiceRing      ServiceKind = "ring"
	ServiceCast      ServiceKind = "cast"
	ServiceScreen    ServiceKind = "screen"
	ServiceApprovals ServiceKind = "approvals"
	ServiceHome      ServiceKind = "home"

	// InboxCompletionCapabilityV1 advertises the application-level completion
	// handshake used by resolved Send/Drop. It is protocol compatibility
	// metadata, never an authorization grant.
	InboxCompletionCapabilityV1 = "drop.complete.v1"
)

func (k ServiceKind) valid() bool {
	switch k {
	case ServiceMCP, ServiceControl, ServiceSteer, ServiceInbox, ServiceRing,
		ServiceCast, ServiceScreen, ServiceApprovals, ServiceHome:
		return true
	default:
		return false
	}
}

// Service announces one receiver by kind and port. Address is output-only: the
// registry constructs it from the transport-observed peer IP, never from the
// request body. Capabilities are presentation hints, not grants.
type Service struct {
	Kind         ServiceKind `json:"kind"`
	Port         int         `json:"port"`
	Protocol     string      `json:"protocol,omitempty"`
	Capabilities []string    `json:"capabilities,omitempty"`
	Address      string      `json:"address,omitempty"`
}

// ActivityKind is the portable, read-only work shape a card may summarize.
type ActivityKind string

const (
	ActivitySession   ActivityKind = "session"
	ActivityTask      ActivityKind = "task"
	ActivityWorkflow  ActivityKind = "workflow"
	ActivityApproval  ActivityKind = "approval"
	ActivityKnowledge ActivityKind = "knowledge"
)

func (k ActivityKind) valid() bool {
	switch k {
	case ActivitySession, ActivityTask, ActivityWorkflow, ActivityApproval, ActivityKnowledge:
		return true
	default:
		return false
	}
}

// ActivityState deliberately has no arbitrary action payload. Existing
// governed steer/approve tools perform actions separately.
type ActivityState string

const (
	ActivityQueued    ActivityState = "queued"
	ActivityRunning   ActivityState = "running"
	ActivityBlocked   ActivityState = "blocked"
	ActivityCompleted ActivityState = "completed"
	ActivityFailed    ActivityState = "failed"
	ActivityCancelled ActivityState = "cancelled"
)

func (s ActivityState) valid() bool {
	switch s {
	case ActivityQueued, ActivityRunning, ActivityBlocked, ActivityCompleted,
		ActivityFailed, ActivityCancelled:
		return true
	default:
		return false
	}
}

var safeActivityID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var safeToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

// Activity is a privacy-safe summary suitable for Home/Nearby. ContextRef may
// point to content-addressed state; raw prompts, credentials, commands, URLs,
// and arbitrary parameters do not belong in this contract.
type Activity struct {
	Schema     string        `json:"schema"`
	ID         string        `json:"id"`
	Kind       ActivityKind  `json:"kind"`
	Title      string        `json:"title"`
	Summary    string        `json:"summary,omitempty"`
	State      ActivityState `json:"state"`
	Progress   *int          `json:"progress,omitempty"`
	Target     string        `json:"target,omitempty"`
	ContextRef string        `json:"context_ref,omitempty"`
	Handoff    bool          `json:"handoff,omitempty"`
	Revision   uint64        `json:"revision,omitempty"`
	UpdatedAt  string        `json:"updated_at,omitempty"`
}

// Validate checks Activity's bounded, non-executable schema.
func (a Activity) Validate() error {
	if a.Schema != ActivitySchema {
		return fmt.Errorf("activity schema must be %q", ActivitySchema)
	}
	if !safeActivityID.MatchString(a.ID) || len(a.ID) > maxActivityID {
		return fmt.Errorf("activity id must match [A-Za-z0-9_-]{1,%d}", maxActivityID)
	}
	if !a.Kind.valid() {
		return fmt.Errorf("unknown activity kind %q", a.Kind)
	}
	if err := boundedText("activity title", a.Title, 1, maxActivityTitle); err != nil {
		return err
	}
	if err := boundedText("activity summary", a.Summary, 0, maxActivitySummary); err != nil {
		return err
	}
	if !a.State.valid() {
		return fmt.Errorf("unknown activity state %q", a.State)
	}
	if a.Progress != nil && (*a.Progress < 0 || *a.Progress > 100) {
		return fmt.Errorf("activity progress must be between 0 and 100")
	}
	if a.Target != "" {
		if err := boundedText("activity target", a.Target, 1, maxActivityTarget); err != nil {
			return err
		}
		t, err := ParseTarget(a.Target)
		if err != nil || t.Empty() || t.String() != a.Target {
			return fmt.Errorf("activity target: %w", errOr(err, errors.New("target must use the canonical <kind>:<value> form")))
		}
		if !safeToken.MatchString(t.Value) {
			return fmt.Errorf("activity target value must use a safe, non-executable token")
		}
	}
	if a.ContextRef != "" && !validContextRef(a.ContextRef) {
		return fmt.Errorf("activity context_ref must be sha256:<hex>, blake3:<hex>, or kh_<hex>")
	}
	if len(a.ContextRef) > maxActivityContextRef {
		return fmt.Errorf("activity context_ref is too long")
	}
	if a.UpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339, a.UpdatedAt); err != nil {
			return fmt.Errorf("activity updated_at: %w", err)
		}
	}
	return nil
}

func errOr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

func validContextRef(s string) bool {
	var raw string
	switch {
	case strings.HasPrefix(s, "sha256:"):
		raw = strings.TrimPrefix(s, "sha256:")
	case strings.HasPrefix(s, "blake3:"):
		raw = strings.TrimPrefix(s, "blake3:")
	case strings.HasPrefix(s, "kh_"):
		raw = strings.TrimPrefix(s, "kh_")
	default:
		return false
	}
	if len(raw) != 64 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

// Announcement is the only client-authored Presence payload. It intentionally
// has no public-key, FQDN, IP, or host field.
type Announcement struct {
	Version    string         `json:"version"`
	Name       string         `json:"name"`
	Kind       NodeKind       `json:"kind"`
	Status     PresenceStatus `json:"status,omitempty"`
	Labels     []string       `json:"labels,omitempty"`
	TTLSeconds int            `json:"ttl_seconds,omitempty"`
	Services   []Service      `json:"services,omitempty"`
	Activity   *Activity      `json:"activity,omitempty"`
}

// Normalized applies harmless defaults, clamps the requested TTL to the
// server-owned range, and returns a deep copy with stable ordering.
func (a Announcement) Normalized() Announcement {
	if a.Version == "" {
		a.Version = PresenceSchema
	}
	if a.Status == "" {
		a.Status = StatusAvailable
	}
	if a.TTLSeconds == 0 {
		a.TTLSeconds = DefaultPresenceTTLSeconds
	}
	if a.TTLSeconds < MinPresenceTTLSeconds {
		a.TTLSeconds = MinPresenceTTLSeconds
	}
	if a.TTLSeconds > MaxPresenceTTLSeconds {
		a.TTLSeconds = MaxPresenceTTLSeconds
	}
	a.Labels = sortedUnique(a.Labels)
	a.Services = cloneServices(a.Services)
	for i := range a.Services {
		if a.Services[i].Protocol == "" {
			a.Services[i].Protocol = "tcp"
		}
		a.Services[i].Capabilities = sortedUnique(a.Services[i].Capabilities)
	}
	sort.Slice(a.Services, func(i, j int) bool { return a.Services[i].Kind < a.Services[j].Kind })
	if a.Activity != nil {
		a.Activity = cloneActivity(a.Activity)
	}
	return a
}

// Validate checks an announcement after normalization. Address is forbidden on
// input because only the gateway may derive it from the observed source IP.
func (a Announcement) Validate() error {
	if a.TTLSeconds < 0 {
		return fmt.Errorf("presence ttl_seconds cannot be negative")
	}
	a = a.Normalized()
	if a.Version != PresenceSchema {
		return fmt.Errorf("presence version must be %q", PresenceSchema)
	}
	if err := boundedText("presence name", a.Name, 1, maxPresenceName); err != nil {
		return err
	}
	if strings.TrimSpace(a.Name) != a.Name {
		return fmt.Errorf("presence name must not have leading or trailing whitespace")
	}
	if !a.Kind.valid() {
		return fmt.Errorf("unknown node kind %q", a.Kind)
	}
	if !a.Status.valid() {
		return fmt.Errorf("unknown presence status %q", a.Status)
	}
	if len(a.Labels) > maxPresenceLabels {
		return fmt.Errorf("presence has %d labels; max is %d", len(a.Labels), maxPresenceLabels)
	}
	for _, label := range a.Labels {
		if len(label) > maxPresenceLabel || !safeToken.MatchString(label) || hasControl(label) {
			return fmt.Errorf("invalid presence label %q", label)
		}
	}
	if len(a.Services) > maxPresenceServices {
		return fmt.Errorf("presence has %d services; max is %d", len(a.Services), maxPresenceServices)
	}
	seen := map[ServiceKind]bool{}
	for _, svc := range a.Services {
		if !svc.Kind.valid() {
			return fmt.Errorf("unknown service kind %q", svc.Kind)
		}
		if seen[svc.Kind] {
			return fmt.Errorf("duplicate service kind %q", svc.Kind)
		}
		seen[svc.Kind] = true
		if svc.Port < 1 || svc.Port > 65535 {
			return fmt.Errorf("service %s port must be between 1 and 65535", svc.Kind)
		}
		if svc.Protocol != "tcp" && svc.Protocol != "http" && svc.Protocol != "https" {
			return fmt.Errorf("service %s has unsupported protocol %q", svc.Kind, svc.Protocol)
		}
		if svc.Address != "" {
			return fmt.Errorf("service %s must not claim an address; the gateway derives it", svc.Kind)
		}
		if len(svc.Capabilities) > maxServiceCapabilities {
			return fmt.Errorf("service %s has too many capabilities", svc.Kind)
		}
		for _, cap := range svc.Capabilities {
			if len(cap) > maxServiceCapability || !safeToken.MatchString(cap) || hasControl(cap) {
				return fmt.Errorf("service %s has invalid capability %q", svc.Kind, cap)
			}
		}
	}
	if a.Activity != nil {
		if err := a.Activity.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func boundedText(field, s string, min, max int) error {
	n := len(s)
	if n < min || n > max {
		return fmt.Errorf("%s must contain between %d and %d bytes", field, min, max)
	}
	if hasControl(s) {
		return fmt.Errorf("%s must not contain control characters", field)
	}
	return nil
}

// VerifiedIdentity is supplied by the server from the authenticated transport.
type VerifiedIdentity struct {
	PublicKey string
	FQDN      string
}

// Presence is the materialized card returned to clients. Network identity,
// observed IP, service addresses, and lifetime are server-owned fields.
type Presence struct {
	Version   string         `json:"version"`
	Name      string         `json:"name"`
	Kind      NodeKind       `json:"kind"`
	Status    PresenceStatus `json:"status"`
	Labels    []string       `json:"labels"`
	Services  []Service      `json:"services"`
	Activity  *Activity      `json:"activity,omitempty"`
	PublicKey string         `json:"public_key"`
	FQDN      string         `json:"fqdn,omitempty"`
	IP        string         `json:"ip"`
	SeenAt    string         `json:"seen_at"`
	ExpiresAt string         `json:"expires_at"`
}

// Registry is a bounded, concurrency-safe, TTL presence projection. It is
// intentionally ephemeral: heartbeats restore it; expiry removes crashed
// nodes; no new durable authority is introduced.
type Registry struct {
	mu      sync.Mutex
	entries map[string]Presence
	max     int
}

func NewRegistry(max int) *Registry {
	if max <= 0 {
		max = DefaultPresenceRegistryMax
	}
	return &Registry{entries: make(map[string]Presence), max: max}
}

// Upsert stamps and stores one card. changed is false when only heartbeat
// timestamps moved, allowing the caller to avoid audit-log heartbeat noise.
func (r *Registry) Upsert(id VerifiedIdentity, observedIP string, raw Announcement, now time.Time) (Presence, bool, error) {
	if err := validateIdentity(id, observedIP); err != nil {
		return Presence{}, false, err
	}
	if err := raw.Validate(); err != nil {
		return Presence{}, false, err
	}
	a := raw.Normalized()
	now = now.UTC()
	p := Presence{
		Version: a.Version, Name: a.Name, Kind: a.Kind, Status: a.Status,
		Labels: append([]string(nil), a.Labels...), Services: cloneServices(a.Services),
		Activity: cloneActivity(a.Activity), PublicKey: id.PublicKey, FQDN: id.FQDN,
		IP: observedIP, SeenAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Duration(a.TTLSeconds) * time.Second).Format(time.RFC3339Nano),
	}
	for i := range p.Services {
		p.Services[i].Address = net.JoinHostPort(observedIP, strconv.Itoa(p.Services[i].Port))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	old, exists := r.entries[id.PublicKey]
	if !exists && len(r.entries) >= r.max {
		return Presence{}, false, fmt.Errorf("presence registry is full (%d records)", r.max)
	}
	changed := !exists || !samePresenceMaterial(old, p)
	r.entries[id.PublicKey] = clonePresence(p)
	return clonePresence(p), changed, nil
}

// Remove deletes the card owned by publicKey.
func (r *Registry) Remove(publicKey string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[publicKey]; !ok {
		return false
	}
	delete(r.entries, publicKey)
	return true
}

// List returns unexpired cards in stable name/FQDN/key order.
func (r *Registry) List(now time.Time) []Presence {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now.UTC())
	out := make([]Presence, 0, len(r.entries))
	for _, p := range r.entries {
		out = append(out, clonePresence(p))
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if ai != aj {
			return ai < aj
		}
		if out[i].FQDN != out[j].FQDN {
			return out[i].FQDN < out[j].FQDN
		}
		return out[i].PublicKey < out[j].PublicKey
	})
	return out
}

// Resolve returns one advertised service by exact name, FQDN, full public key,
// or "pubkey:<full-key>". Shortened keys are intentionally not accepted.
func (r *Registry) Resolve(selector string, kind ServiceKind, now time.Time) (ResolvedService, error) {
	return ResolvePresence(r.List(now), selector, kind)
}

func (r *Registry) pruneLocked(now time.Time) {
	for key, p := range r.entries {
		expires, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
		if err != nil || !expires.After(now) {
			delete(r.entries, key)
		}
	}
}

// ResolvedService pairs the selected verified node with one derived address.
type ResolvedService struct {
	Node    Presence `json:"node"`
	Service Service  `json:"service"`
}

// ResolvePresence is the transport-independent resolver used by Registry and
// clients that fetched a Presence list from the control endpoint.
func ResolvePresence(list []Presence, selector string, kind ServiceKind) (ResolvedService, error) {
	var err error
	selector, err = validatedPresenceSelector(selector)
	if err != nil {
		return ResolvedService{}, err
	}
	if !kind.valid() {
		return ResolvedService{}, fmt.Errorf("unknown service kind %q", kind)
	}
	keySelector, explicitKey := strings.CutPrefix(selector, "pubkey:")
	var matches []Presence
	if explicitKey {
		// The typed form is key-only. In particular, a friendly name beginning
		// with "pubkey:" must never participate in this lookup.
		if keySelector != "" {
			for _, p := range list {
				if p.PublicKey == keySelector {
					matches = append(matches, p)
				}
			}
		}
	} else {
		// Resolve identity tiers in trust order. Public keys and FQDNs are
		// transport-stamped, while Name is client-authored presentation metadata;
		// combining them into one OR-match would let a friendly name shadow a
		// verified selector or make it spuriously ambiguous.
		for _, p := range list {
			if p.PublicKey == selector {
				matches = append(matches, p)
			}
		}
		if len(matches) == 0 {
			for _, p := range list {
				if p.FQDN != "" && strings.EqualFold(p.FQDN, selector) {
					matches = append(matches, p)
				}
			}
		}
		if len(matches) == 0 {
			for _, p := range list {
				if strings.EqualFold(p.Name, selector) {
					matches = append(matches, p)
				}
			}
		}
	}
	if len(matches) == 0 {
		return ResolvedService{}, errors.New("no nearby node matches the selector")
	}
	if len(matches) > 1 {
		return ResolvedService{}, fmt.Errorf("nearby selector is ambiguous (%d matches); use the FQDN or full public key", len(matches))
	}
	p := matches[0]
	for _, svc := range p.Services {
		if svc.Kind == kind {
			return ResolvedService{Node: clonePresence(p), Service: cloneService(svc)}, nil
		}
	}
	return ResolvedService{}, fmt.Errorf("selected nearby node does not advertise service %q", kind)
}

// ValidatePresenceSelector checks the public selector input contract without
// performing a lookup. ResolvePresence applies the same validation itself.
func ValidatePresenceSelector(selector string) error {
	_, err := validatedPresenceSelector(selector)
	return err
}

func validatedPresenceSelector(selector string) (string, error) {
	if len(selector) > MaxPresenceSelectorBytes || !utf8.ValidString(selector) {
		return "", errors.New("presence selector is invalid")
	}
	for _, r := range selector {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return "", errors.New("presence selector is invalid")
		}
	}
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", errors.New("presence selector is required")
	}
	return selector, nil
}

func validateIdentity(id VerifiedIdentity, observedIP string) error {
	if id.PublicKey == "" || len(id.PublicKey) > maxPresenceIdentityText || hasControl(id.PublicKey) {
		return fmt.Errorf("presence requires a valid transport-verified public key")
	}
	if len(id.FQDN) > maxPresenceIdentityText || hasControl(id.FQDN) {
		return fmt.Errorf("presence has an invalid transport-verified FQDN")
	}
	if net.ParseIP(observedIP) == nil {
		return fmt.Errorf("presence requires a transport-observed IP address")
	}
	return nil
}

func samePresenceMaterial(a, b Presence) bool {
	if a.Version != b.Version || a.Name != b.Name || a.Kind != b.Kind ||
		a.Status != b.Status || a.PublicKey != b.PublicKey || a.FQDN != b.FQDN || a.IP != b.IP {
		return false
	}
	if strings.Join(a.Labels, "\x00") != strings.Join(b.Labels, "\x00") || len(a.Services) != len(b.Services) {
		return false
	}
	for i := range a.Services {
		as, bs := a.Services[i], b.Services[i]
		if as.Kind != bs.Kind || as.Port != bs.Port || as.Protocol != bs.Protocol ||
			as.Address != bs.Address || strings.Join(as.Capabilities, "\x00") != strings.Join(bs.Capabilities, "\x00") {
			return false
		}
	}
	return sameActivity(a.Activity, b.Activity)
}

func sameActivity(a, b *Activity) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Progress == nil || b.Progress == nil {
		return a.Schema == b.Schema && a.ID == b.ID && a.Kind == b.Kind &&
			a.Title == b.Title && a.Summary == b.Summary && a.State == b.State &&
			a.Progress == nil && b.Progress == nil && a.Target == b.Target &&
			a.ContextRef == b.ContextRef && a.Handoff == b.Handoff &&
			a.Revision == b.Revision && a.UpdatedAt == b.UpdatedAt
	}
	return *a.Progress == *b.Progress && a.Schema == b.Schema && a.ID == b.ID &&
		a.Kind == b.Kind && a.Title == b.Title && a.Summary == b.Summary &&
		a.State == b.State && a.Target == b.Target && a.ContextRef == b.ContextRef &&
		a.Handoff == b.Handoff && a.Revision == b.Revision && a.UpdatedAt == b.UpdatedAt
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	n := 0
	for _, s := range out {
		if n == 0 || out[n-1] != s {
			out[n] = s
			n++
		}
	}
	return out[:n]
}

func cloneServices(in []Service) []Service {
	if len(in) == 0 {
		return []Service{}
	}
	out := make([]Service, len(in))
	for i, svc := range in {
		out[i] = cloneService(svc)
	}
	return out
}

func cloneService(in Service) Service {
	in.Capabilities = append([]string(nil), in.Capabilities...)
	if in.Capabilities == nil {
		in.Capabilities = []string{}
	}
	return in
}

func cloneActivity(in *Activity) *Activity {
	if in == nil {
		return nil
	}
	out := *in
	if in.Progress != nil {
		p := *in.Progress
		out.Progress = &p
	}
	return &out
}

func clonePresence(in Presence) Presence {
	in.Labels = append([]string(nil), in.Labels...)
	if in.Labels == nil {
		in.Labels = []string{}
	}
	in.Services = cloneServices(in.Services)
	in.Activity = cloneActivity(in.Activity)
	return in
}
