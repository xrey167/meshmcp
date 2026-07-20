package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"meshmcp/policy"
	"meshmcp/session"
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

// recvEnvelopes decodes newline-delimited JSON steer envelopes from r and calls
// onEnv for each. A malformed line ends the stream with an error.
func recvEnvelopes(r io.Reader, onEnv func(steerEnvelope)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var env steerEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			return fmt.Errorf("bad steer envelope: %w", err)
		}
		onEnv(env)
	}
	return sc.Err()
}
