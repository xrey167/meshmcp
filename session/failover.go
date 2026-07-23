package session

import (
	"math/rand"
	"time"
)

// This file is the lease-maintenance side of session HA. Three pieces:
//
//   - a renewal heartbeat that keeps a live session's lease expiry meaning
//     "the owner is alive" (without it, expiry lapses at session-age TTL and
//     only the fencing generation protects the session — safe, but useless as
//     a liveness signal for a standby);
//   - Shutdown, which releases every lease on a clean stop so a peer gateway
//     can claim the sessions instantly instead of waiting out the expiry;
//   - an opt-in standby sweep that claims sessions whose owner stopped
//     renewing (crashed, or paused far past the margin) and respawns their
//     backends BEFORE the client returns.
//
// Safety never rests on any timing here: every operation below is an ordinary
// lease op serialized by the store's generation compare-and-swap, so no
// interleaving — including a wrongly-early sweep against a paused-not-dead
// owner — can produce two unfenced writers. The margin and intervals tune
// availability only. Identity binding on client reattach (attach's creatorKey
// checks) is untouched: the sweep never talks to a client at all.

// FailoverConfig configures the standby sweep on a Server. Renewal and
// release-on-shutdown are always on when the store supports leases; only the
// sweep (adopting other gateways' expired-lease sessions) is opt-in.
type FailoverConfig struct {
	// Enabled turns on the standby sweep.
	Enabled bool
	// SweepInterval is how often the store is scanned for adoptable sessions
	// (default 30s).
	SweepInterval time.Duration
}

// defaultSweepInterval is how often the standby sweep scans the store when the
// config does not say otherwise.
const defaultSweepInterval = 30 * time.Second

// WithFailover configures the standby sweep. Call before StartLeaseMaintenance.
func (s *Server) WithFailover(cfg FailoverConfig) *Server {
	s.failover = cfg
	return s
}

// sweepMargin is how long past its lease expiry a session must sit before the
// sweep may adopt it. Expiry already trails the last successful renewal by a
// full TTL (~3 missed ticks); adding 2×TTL means adoption only after ≥3×TTL of
// total owner silence, which absorbs store outages and cross-gateway clock
// skew. Deliberately derived, not configurable: adopting "too early" cannot
// violate safety ON A GENUINE-CAS STORE (the claim is one generation CAS and
// the paused owner is fenced at its next renew/checkpoint) — it merely forces
// a live-but-slow owner to yield a healthy backend, so the margin only trades
// availability, never correctness. No margin can absorb a store whose CAS
// itself breaks under a paused holder (FileStore's stealable lock), which is
// why the sweep refuses to run over FileStore at all — see
// StartLeaseMaintenance.
func (s *Server) sweepMargin() time.Duration { return 2 * s.ttl }

func (s *Server) renewInterval() time.Duration { return s.ttl / 3 }

func (s *Server) sweepInterval() time.Duration {
	if s.failover.SweepInterval > 0 {
		return s.failover.SweepInterval
	}
	return defaultSweepInterval
}

// maintenanceJitter spreads a tick ±20% so many gateways sharing one store do
// not renew or sweep in lockstep.
func maintenanceJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Millisecond
	}
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// StartLeaseMaintenance starts the per-server maintenance goroutine: the
// renewal heartbeat (every ttl/3), plus the standby sweep when configured via
// WithFailover. It stops when stop is closed; Shutdown then waits for it to
// exit. A no-op without a lease-capable store — there is nothing to renew and
// adopting would be unfenceable.
func (s *Server) StartLeaseMaintenance(stop <-chan struct{}) {
	if s.lease == nil {
		if s.failover.Enabled {
			s.logf("session failover: store has no CAS lease support; standby sweep disabled")
		}
		return
	}
	// The FileStore's cross-process lock can be stolen as stale from a
	// paused-not-dead holder mid-critical-section, which would let a resumed
	// holder regress the generation the sweep's adoption committed — exactly
	// the split-brain the sweep must never create. Its CAS is sound only for
	// crash-or-alive holders, so the autonomous sweep refuses to run over it
	// (config validation rejects the combination too; this guards embedders).
	// The renewal heartbeat stays on: it is plain lease upkeep with no new
	// writer, and the pre-rename lock-token check bounds its exposure.
	if _, isFile := s.lease.(*FileStore); isFile && s.failover.Enabled {
		s.logf("session failover: FileStore's lock is not steal-proof for paused processes; standby sweep disabled (use a PostgreSQL session store)")
		s.failover.Enabled = false
	}
	done := make(chan struct{})
	s.maintDone = done
	go func() {
		defer close(done)
		s.maintenanceLoop(stop)
	}()
}

// maintenanceLoop is a thin timer shell: all decisions live in renewOnce /
// sweepOnce, which take an explicit now so tests drive time deterministically.
func (s *Server) maintenanceLoop(stop <-chan struct{}) {
	renew := time.NewTimer(maintenanceJitter(s.renewInterval()))
	defer renew.Stop()
	var sweepC <-chan time.Time
	var sweep *time.Timer
	if s.failover.Enabled {
		sweep = time.NewTimer(maintenanceJitter(s.sweepInterval()))
		defer sweep.Stop()
		sweepC = sweep.C
	}
	for {
		select {
		case <-stop:
			return
		case <-renew.C:
			s.renewOnce(time.Now())
			renew.Reset(maintenanceJitter(s.renewInterval()))
		case <-sweepC:
			s.sweepOnce(time.Now())
			sweep.Reset(maintenanceJitter(s.sweepInterval()))
		}
	}
}

// renewOnce extends the lease of every live leased session. A fenced renewal
// means another gateway took the session over — the same event a fenced
// checkpoint detects, handled the same way: yield. A store ERROR, by contrast,
// retains the session and retries next tick: an unavailable store must not
// mass-kill healthy sessions, and it is symmetric-safe because a sweeper's
// claim goes through the same unavailable store while the margin absorbs
// several missed ticks.
func (s *Server) renewOnce(now time.Time) {
	if s.lease == nil {
		return
	}
	type target struct {
		id  sessionID
		gen uint64
	}
	// Snapshot under s.mu, then store calls outside it: the FileStore's
	// cross-process lock can block for seconds and must never be held under
	// the session mutex.
	s.mu.Lock()
	targets := make([]target, 0, len(s.sessions))
	for id, sess := range s.sessions {
		if sess.leaseGen > 0 { // gen 0 = degraded (no lease acquired at create): nothing to renew
			targets = append(targets, target{id, sess.leaseGen})
		}
	}
	s.mu.Unlock()
	for _, tg := range targets {
		_, ok, err := s.lease.RenewLease(tg.id.String(), s.instance, tg.gen, s.ttl, now)
		if err != nil {
			s.logf("session %s: lease renewal error: %v (retaining session)", tg.id, err)
			continue
		}
		if !ok {
			s.logf("session %s: lease renewal fenced (gen %d, taken over by another gateway); yielding", tg.id, tg.gen)
			s.remove(tg.id)
		}
	}
}

// sweepOnce scans the store for sessions whose owner stopped renewing and
// adopts them. Exactly-one-adopter is the store's generation CAS, not this
// loop's timing.
func (s *Server) sweepOnce(now time.Time) {
	if s.lease == nil || s.store == nil || !s.failover.Enabled {
		return
	}
	list, err := s.store.List()
	if err != nil {
		s.logf("session sweep: list: %v", err)
		return
	}
	for _, ps := range list {
		if s.adoptable(ps, now) {
			s.adopt(ps, now)
		}
	}
}

// adoptable decides whether a persisted session is a sweep candidate.
func (s *Server) adoptable(ps PersistedSession, now time.Time) bool {
	// A record without the creator's persisted identity cannot be respawned
	// under its true policy identity — written pre-upgrade or without a
	// creator key. Never park or spawn it degraded; it keeps the existing
	// client-reattach rehydrate path and self-heals at the owner's next
	// checkpoint.
	if ps.ID == "" || ps.CreatorKey == "" || ps.PeerFQDN == "" {
		return false
	}
	// A record written by a newer build may not parse the way it was written;
	// respawning from a misread checkpoint could re-serve or drop frames.
	// FileStore's List already filters these; this guards every store.
	if ps.SchemaVersion > sessionSchemaVersion {
		return false
	}
	// Generation 0 means the owner never held a lease (degraded acquire at
	// create): its checkpoints bypass SaveIfOwned, so that owner is NOT
	// fenceable and adopting would be real split-brain. Categorically
	// ineligible. Released records always carry generation >= 1.
	if ps.Generation == 0 {
		return false
	}
	if ps.Owner == s.instance {
		return false // ours (live or degraded) — nothing to adopt
	}
	if ps.Owner == "" {
		return true // released by a clean shutdown: claim immediately
	}
	if ps.LeaseExpiry <= 0 {
		return false // owned but never leased-with-expiry: not a liveness signal
	}
	return now.UnixNano() > ps.LeaseExpiry+s.sweepMargin().Nanoseconds()
}

// adopt claims one expired-or-released session via the lease CAS and respawns
// its backend so the client's eventual reattach lands on a warm session. The
// claim uses AcquireLease, never TakeoverLease: Takeover is contractually
// reserved for a transport-verified creator reattach, while Acquire already
// permits expired/released leases and its generation CAS guarantees exactly
// one claimer — and fences the previous owner's SaveIfOwned/Renew the instant
// it commits.
func (s *Server) adopt(ps PersistedSession, now time.Time) {
	id, err := parseSessionID(ps.ID)
	if err != nil {
		return
	}
	prevOwner := ps.Owner
	lease, ok, err := s.lease.AcquireLease(ps.ID, s.instance, ps.Generation, s.ttl, now)
	if err != nil || !ok {
		return // owner renewed, or another gateway claimed first — drop silently
	}
	// Between List and the claim the previous owner may have checkpointed
	// newer cursors. It is fenced now, so this re-Load is stable. The identity
	// fields are re-checked on the fresh copy: a last-moment checkpoint from
	// an older build could have dropped them, and a degraded spawn is never
	// acceptable.
	cur, found, err := s.store.Load(ps.ID)
	if err != nil || !found || cur.CreatorKey == "" || cur.PeerFQDN == "" {
		_, _ = s.lease.ReleaseLease(ps.ID, s.instance, lease.Generation)
		return
	}
	meta := Meta{PeerFQDN: cur.PeerFQDN, PeerAddr: cur.PeerAddr, PeerKey: cur.CreatorKey}

	s.mu.Lock()
	if _, exists := s.sessions[id]; exists {
		// The creator reattached here between our claim and now: rehydrate's
		// TakeoverLease superseded our claim (same-instance takeover checks
		// the generation only). Its session wins; our release is a no-op
		// against the newer generation.
		s.mu.Unlock()
		_, _ = s.lease.ReleaseLease(ps.ID, s.instance, lease.Generation)
		return
	}
	ep, err := restoreEndpoint(cur)
	if err == nil {
		var sess *serverSession
		sess, err = s.resumeFromPersisted(cur, ep, meta, lease.Generation, 0)
		if err == nil {
			// No live Handle: arm the reaper now (attach stops it on reattach,
			// exactly as for a detached session). If the client never returns,
			// remove -> DeleteIfOwner reaps the record — deliberately terminal
			// rather than re-released: by then the client has been absent for
			// owner-death + margin + a full TTL, far past the reattach promise,
			// and delete is what the original owner's reaper would have done.
			sess.reaper = time.AfterFunc(s.ttl, func() {
				s.logf("session %s: adopted session expired after %s unclaimed", id, s.ttl)
				s.remove(id)
			})
		}
	}
	s.mu.Unlock()
	if err != nil {
		s.logf("session %s: adoption failed: %v (lease released)", ps.ID, err)
		_, _ = s.lease.ReleaseLease(ps.ID, s.instance, lease.Generation)
		return
	}
	if prevOwner == "" {
		s.logf("session %s: adopted (released by previous owner, gen %d->%d)", ps.ID, ps.Generation, lease.Generation)
	} else {
		s.logf("session %s: adopted from owner %q (lease expired past margin, gen %d->%d)", ps.ID, prevOwner, ps.Generation, lease.Generation)
	}
}

// Shutdown hands every live session off for immediate takeover: a final
// checkpoint (freshest cursors), then ReleaseLease — owner cleared, expiry
// zeroed, generation AND state preserved — so a peer gateway claims without
// waiting out an expiry, or a reattaching client rehydrates with zero takeover
// friction. This is the handoff op; session termination (client close, TTL
// reap, fence yield) keeps remove's DeleteIfOwner, the terminal op. Close the
// StartLeaseMaintenance stop channel before calling: Shutdown first joins the
// maintenance goroutine, so an in-flight sweep adoption lands BEFORE the drain
// (and is handed off below) instead of after it — which would leak a live
// backend and strand its lease, owned by an exited process, until
// expiry+margin.
func (s *Server) Shutdown() {
	if s.maintDone != nil {
		<-s.maintDone
	}
	s.mu.Lock()
	sessions := make([]*serverSession, 0, len(s.sessions))
	for id, sess := range s.sessions {
		delete(s.sessions, id)
		if sess.reaper != nil {
			sess.reaper.Stop()
		}
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		id := sess.ep.id
		s.checkpoint(sess)
		sess.ep.closeWith(nil) // quiesce pumps before freeing the lease
		if s.lease != nil && sess.leaseGen > 0 {
			if ok, err := s.lease.ReleaseLease(id.String(), s.instance, sess.leaseGen); err != nil {
				s.logf("session %s: lease release on shutdown: %v", id, err)
			} else if ok {
				s.logf("session %s: lease released on shutdown", id)
			}
		}
		if sess.backend != nil {
			_ = sess.backend.Close()
		}
	}
}
