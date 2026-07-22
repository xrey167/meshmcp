package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// newSteerFactory returns a session backend factory for an agent's steer inbox:
// each connection's bytes are decoded as newline-delimited steer envelopes and
// delivered to ch (until ctx ends). It mirrors newDropFactory (drop.go) but
// parses envelope JSON instead of file frames, and reuses dropSink verbatim as
// the send-only backend. Optionally audits each received steer.
func newSteerFactory(ctx context.Context, ch chan<- steerEnvelope, audit *policy.AuditLog) session.BackendFactory {
	return func(meta session.Meta) (session.Backend, error) {
		pr, pw := io.Pipe()
		d := &dropSink{pw: pw, done: make(chan struct{})}
		go func() {
			err := recvEnvelopes(pr, func(env steerEnvelope) {
				log.Printf("steer %q from %s", env.Type, meta.PeerFQDN)
				if audit != nil {
					reason := fmt.Sprintf("steer %s", env.Type)
					if env.Target != "" {
						reason += " -> " + env.Target
					}
					audit.Append(policy.AuditRecord{
						Backend: "agent", Peer: meta.PeerFQDN, PeerKey: meta.PeerKey, PeerAddr: meta.PeerAddr,
						Method: "air/steer", Tool: env.Tool, Decision: "allow",
						Reason: reason, Rule: -1,
					})
				}
				select {
				case ch <- env:
				case <-ctx.Done():
				}
			})
			pr.CloseWithError(err)
			d.finish(err)
		}()
		return d, nil
	}
}

// recvEnvelopes is the pure newline-delimited envelope parser, carved into the
// air package (air.ParseEnvelopes); this alias keeps the receive path reading
// the same name.
var recvEnvelopes = air.ParseEnvelopes
