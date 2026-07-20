// Package caching models the draft result caching hints (protocol revision
// 2026-07-28): CacheableResult and its cache scope. These apply to every
// cacheable verb — tools/list, resources/list, prompts/list, resources/read
// and server/discover — so they live in a shared package.
//
// Reflects the DRAFT revision. The SDK-side ergonomics (per-registration
// cacheHint, ServerOptions.cacheHints, client cacheMode, ResponseCacheStore)
// are library constructs, not wire types, and are not modelled here.
package caching

import "github.com/xrey167/meshmcp/protocol/base"

// Result-type discriminator values carried on a draft Result's resultType field.
const (
	ResultTypeComplete      = "complete"
	ResultTypeInputRequired = "input_required"
)

// CacheScope indicates the intended scope of a cached response (analogous to
// HTTP Cache-Control public vs private).
type CacheScope string

const (
	// CachePublic: the response holds no user-specific data and MAY be shared
	// across authorization contexts.
	CachePublic CacheScope = "public"
	// CachePrivate: the response MAY be reused only within the same
	// authorization context.
	CachePrivate CacheScope = "private"
)

// CacheableResult is the base of results that carry a client-side caching hint
// (draft CacheableResult, extending the draft Result with resultType).
type CacheableResult struct {
	// Meta is the open `_meta` object.
	Meta base.Meta `json:"_meta,omitempty"`
	// ResultType lets the client decide how to parse the result. Servers on this
	// revision MUST include it; an absent value is treated as "complete".
	ResultType string `json:"resultType"`
	// TTLMs is how long (ms) the client MAY cache this response. 0 means
	// immediately stale.
	TTLMs float64 `json:"ttlMs"`
	// CacheScope is the caching scope, "public" or "private".
	CacheScope CacheScope `json:"cacheScope"`
}
