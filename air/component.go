package air

// This file defines the portable component-card vocabulary carried by an Air
// catalog. A card is discovery metadata, never an authorization assertion:
// Owner identifies who advertised the component and Features describe protocol
// support, while the gateway's transport identity, ACL, policy, and signed
// capability verifier remain authoritative for every operation.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CatalogSchemaV1 is the additive component-card schema. Schema is optional on
// Catalog so catalogs emitted before component cards continue to decode and
// validate; when present it must name a schema this package understands.
const CatalogSchemaV1 = "com.meshmcp.air.catalog/v1"

// ComponentKind is the role a discoverable component plays in the ecosystem.
// CatalogEntry historically described only backends; an empty kind therefore
// remains valid for a legacy entry.
type ComponentKind string

const (
	ComponentGateway  ComponentKind = "gateway"
	ComponentBackend  ComponentKind = "backend"
	ComponentAgent    ComponentKind = "agent"
	ComponentWorkflow ComponentKind = "workflow"
	ComponentBus      ComponentKind = "bus"
	ComponentStore    ComponentKind = "store"
)

func validComponentKind(k ComponentKind) bool {
	switch k {
	case ComponentGateway, ComponentBackend, ComponentAgent, ComponentWorkflow, ComponentBus, ComponentStore:
		return true
	default:
		return false
	}
}

// IdentityRef is the identity advertised for a component. PubKey is the
// durable WireGuard key; FQDN is display-only; SPIFFE is an additive label.
// A card is unsigned discovery data, so none of these fields may be used as a
// replacement for the identity proven by the live transport.
type IdentityRef struct {
	PubKey string `json:"pubkey,omitempty"`
	FQDN   string `json:"fqdn,omitempty"`
	SPIFFE string `json:"spiffe,omitempty"`
}

// Empty reports whether the card carries no advertised owner identity.
func (i IdentityRef) Empty() bool {
	return i.PubKey == "" && i.FQDN == "" && i.SPIFFE == ""
}

// IsZero lets encoding/json omit an empty identity when the omitzero tag is
// used, preserving the compact wire shape of pre-card catalog entries.
func (i IdentityRef) IsZero() bool { return i.Empty() }

func (i IdentityRef) normalized() IdentityRef {
	i.PubKey = strings.TrimSpace(i.PubKey)
	i.FQDN = strings.ToLower(strings.TrimSpace(i.FQDN))
	i.SPIFFE = strings.TrimSpace(i.SPIFFE)
	return i
}

func (i IdentityRef) validate() error {
	if err := validDisplayText("owner pubkey", i.PubKey, 1024); err != nil {
		return err
	}
	if err := validDisplayText("owner fqdn", i.FQDN, 255); err != nil {
		return err
	}
	if err := validDisplayText("owner SPIFFE id", i.SPIFFE, 2048); err != nil {
		return err
	}
	if i.SPIFFE != "" {
		u, err := url.Parse(i.SPIFFE)
		if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/") {
			return fmt.Errorf("owner SPIFFE id %q is not a valid spiffe:// URI", i.SPIFFE)
		}
	}
	return nil
}

// Feature is one versioned protocol/product feature a component advertises.
// It describes support only; it does not grant the caller that feature.
type Feature struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Standard feature identifiers. New features may use names outside this set as
// long as they satisfy the feature-name grammar; the catalog stays extensible.
const (
	FeatureMCP20250618  = "mcp.2025-06-18"
	FeatureAirBrowseV1  = "air.browse.v1"
	FeatureAirResumeV1  = "air.resume.v1"
	FeatureAirSteerV1   = "air.steer.v1"
	FeatureCapabilityV1 = "authz.capability.v1"
)

var (
	componentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	featureNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	featureVerPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$`)
)

// NormalizeFeatures trims and canonicalizes feature names, removes exact
// duplicates, rejects conflicting versions for one name, and sorts by name.
// This gives every consumer one deterministic representation regardless of the
// order in which a component assembled its feature set.
func NormalizeFeatures(features []Feature) ([]Feature, error) {
	if len(features) == 0 {
		return nil, nil
	}
	byName := make(map[string]Feature, len(features))
	for _, raw := range features {
		f := Feature{
			Name:    strings.ToLower(strings.TrimSpace(raw.Name)),
			Version: strings.TrimSpace(raw.Version),
		}
		if !featureNamePattern.MatchString(f.Name) {
			return nil, fmt.Errorf("feature name %q must match %s", raw.Name, featureNamePattern)
		}
		if f.Version != "" && !featureVerPattern.MatchString(f.Version) {
			return nil, fmt.Errorf("feature %q version %q is invalid", f.Name, f.Version)
		}
		if prev, ok := byName[f.Name]; ok {
			if prev.Version != f.Version {
				return nil, fmt.Errorf("feature %q advertises conflicting versions %q and %q", f.Name, prev.Version, f.Version)
			}
			continue
		}
		byName[f.Name] = f
	}
	out := make([]Feature, 0, len(byName))
	for _, f := range byName {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

// LifecycleState is the coarse, portable lifecycle advertised by a component.
// "serving" means the component's mesh surface is accepting traffic; it does
// not claim that an arbitrary downstream dependency is healthy.
type LifecycleState string

const (
	LifecycleStarting LifecycleState = "starting"
	LifecycleServing  LifecycleState = "serving"
	LifecycleBusy     LifecycleState = "busy"
	LifecycleDraining LifecycleState = "draining"
	LifecycleOffline  LifecycleState = "offline"
	LifecycleUnknown  LifecycleState = "unknown"
)

// Lifecycle is the current advertised state of a component. Generation is a
// monotonic producer-owned revision, useful for suppressing stale updates.
type Lifecycle struct {
	State      LifecycleState `json:"state,omitempty"`
	Since      string         `json:"since,omitempty"`
	Generation uint64         `json:"generation,omitempty"`
}

func (l Lifecycle) normalized() Lifecycle {
	l.State = LifecycleState(strings.ToLower(strings.TrimSpace(string(l.State))))
	l.Since = strings.TrimSpace(l.Since)
	return l
}

func (l Lifecycle) empty() bool {
	return l.State == "" && l.Since == "" && l.Generation == 0
}

// IsZero lets encoding/json omit an empty lifecycle from a legacy entry.
func (l Lifecycle) IsZero() bool { return l.empty() }

func (l Lifecycle) validate() error {
	if l.empty() {
		return nil
	}
	switch l.State {
	case LifecycleStarting, LifecycleServing, LifecycleBusy, LifecycleDraining, LifecycleOffline, LifecycleUnknown:
	default:
		return fmt.Errorf("unknown lifecycle state %q", l.State)
	}
	if l.Since != "" {
		if _, err := time.Parse(time.RFC3339Nano, l.Since); err != nil {
			return fmt.Errorf("lifecycle since %q is not RFC3339: %w", l.Since, err)
		}
	}
	return nil
}

// StableComponentID derives an opaque stable id for a configured component.
// Callers should prefer an explicit operator-configured id when one exists;
// this deterministic fallback survives address changes and process restarts.
func StableComponentID(ownerPubKey string, kind ComponentKind, name string) (string, error) {
	ownerPubKey = strings.TrimSpace(ownerPubKey)
	name = strings.TrimSpace(name)
	if ownerPubKey == "" || name == "" || !validComponentKind(kind) {
		return "", fmt.Errorf("stable component id needs an owner pubkey, known kind, and name")
	}
	sum := sha256.Sum256([]byte(ownerPubKey + "\x1f" + string(kind) + "\x1f" + name))
	return "cmp_" + hex.EncodeToString(sum[:]), nil
}

// ValidateComponentID checks an explicit operator-provided component id. It is
// exported so strict gateway config validation can reject a bad id before the
// gateway joins the mesh or builds a card.
func ValidateComponentID(id string) error {
	trimmed := strings.TrimSpace(id)
	if id != trimmed || !componentIDPattern.MatchString(trimmed) {
		return fmt.Errorf("component id %q must match %s", id, componentIDPattern)
	}
	return nil
}

// Normalized returns a validated copy of the card. On full component cards it
// mirrors the legacy Resumable/Steerable booleans into the standard feature
// list, and it always mirrors those features back into the booleans. A legacy
// boolean-only entry stays legacy on the wire, keeping normalization idempotent
// without inventing a partial card that has features but no ID or Kind.
func (e CatalogEntry) Normalized() (CatalogEntry, error) {
	// Legacy Resumable/Steerable booleans are not component-card fields. Capture
	// card mode before those booleans are mirrored into Features below.
	cardFields := e.ID != "" || e.Kind != "" || e.Version != "" || !e.Owner.Empty() || len(e.Features) > 0 || !e.Lifecycle.empty()

	e.ID = strings.TrimSpace(e.ID)
	e.Kind = ComponentKind(strings.ToLower(strings.TrimSpace(string(e.Kind))))
	e.Name = strings.TrimSpace(e.Name)
	e.Version = strings.TrimSpace(e.Version)
	e.Owner = e.Owner.normalized()
	e.Address = strings.TrimSpace(e.Address)
	e.Transport = strings.ToLower(strings.TrimSpace(e.Transport))
	e.Lifecycle = e.Lifecycle.normalized()

	features := append([]Feature(nil), e.Features...)
	if cardFields {
		if e.Resumable {
			features = append(features, Feature{Name: FeatureAirResumeV1})
		}
		if e.Steerable {
			features = append(features, Feature{Name: FeatureAirSteerV1})
		}
	}
	var err error
	e.Features, err = NormalizeFeatures(features)
	if err != nil {
		return CatalogEntry{}, fmt.Errorf("catalog entry %q: %w", e.Name, err)
	}
	for _, f := range e.Features {
		switch f.Name {
		case FeatureAirResumeV1:
			e.Resumable = true
		case FeatureAirSteerV1:
			e.Steerable = true
		}
	}
	if err := e.validateNormalized(cardFields); err != nil {
		return CatalogEntry{}, err
	}
	return e, nil
}

// Validate reports whether the entry is a valid legacy endpoint or a complete
// component card. Legacy entries may omit all additive card fields; once an ID
// or any other card field is supplied, ID and Kind are both required.
func (e CatalogEntry) Validate() error {
	_, err := e.Normalized()
	return err
}

func (e CatalogEntry) validateNormalized(cardFields bool) error {
	if e.Name == "" || e.Address == "" {
		return fmt.Errorf("catalog entry needs a name and address (got %+v)", e)
	}
	if err := validDisplayText("catalog entry name", e.Name, 256); err != nil {
		return err
	}
	if err := validDisplayText("catalog entry version", e.Version, 128); err != nil {
		return err
	}
	if err := validMeshAddress(e.Address); err != nil {
		return fmt.Errorf("catalog entry %q: %w", e.Name, err)
	}
	switch e.Transport {
	case TransportStdio, TransportHTTP, TransportRemote:
	default:
		return fmt.Errorf("catalog entry %q: unknown transport %q", e.Name, e.Transport)
	}

	if cardFields {
		if e.ID == "" || e.Kind == "" {
			return fmt.Errorf("catalog entry %q: component cards require both id and kind", e.Name)
		}
		if err := ValidateComponentID(e.ID); err != nil {
			return fmt.Errorf("catalog entry %q: %w", e.Name, err)
		}
		if !validComponentKind(e.Kind) {
			return fmt.Errorf("catalog entry %q: unknown component kind %q", e.Name, e.Kind)
		}
	}
	if err := e.Owner.validate(); err != nil {
		return fmt.Errorf("catalog entry %q: %w", e.Name, err)
	}
	if err := e.Lifecycle.validate(); err != nil {
		return fmt.Errorf("catalog entry %q: %w", e.Name, err)
	}
	return nil
}

// Supports reports whether the component advertises a feature. Legacy
// booleans are honored even before a caller normalizes the entry.
func (e CatalogEntry) Supports(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	if name == FeatureAirResumeV1 && e.Resumable {
		return true
	}
	if name == FeatureAirSteerV1 && e.Steerable {
		return true
	}
	for _, f := range e.Features {
		if strings.ToLower(strings.TrimSpace(f.Name)) == name {
			return true
		}
	}
	return false
}

func validMeshAddress(addr string) error {
	if err := validDisplayText("catalog entry address", addr, 512); err != nil {
		return err
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("address %q must be host:port", addr)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("address %q has an invalid port", addr)
	}
	return nil
}

func validDisplayText(field, value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%s exceeds %d bytes", field, max)
	}
	for _, r := range value {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

// featureKey is a stable representation used by catalog diffs and Home's
// state signature. Invalid, unnormalized input remains visible instead of
// collapsing to an empty key, while valid input is order- and duplicate-stable.
func featureKey(features []Feature) string {
	normalized, err := NormalizeFeatures(features)
	if err != nil {
		var raw []string
		for _, f := range features {
			raw = append(raw, f.Name+"@"+f.Version)
		}
		sort.Strings(raw)
		return "invalid:" + strings.Join(raw, "\x1e")
	}
	var b strings.Builder
	for _, f := range normalized {
		b.WriteString(f.Name)
		b.WriteByte('@')
		b.WriteString(f.Version)
		b.WriteByte('\x1e')
	}
	return b.String()
}
