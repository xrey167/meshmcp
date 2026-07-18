package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"meshmcp/policy"
	"meshmcp/pubsub"
	"meshmcp/session"
)

// meshmcp publish / subscribe / pubsub — the identity-native event fabric.
//
// A `pubsub` broker daemon listens on the mesh, admits only peers on its
// connection ACL, and authorizes every publish and subscribe per topic by the
// caller's WireGuard identity (deny by default). Events are stamped with the
// publisher's key, contained by data-flow labels, hash-chained, and audited —
// the same guarantees the gateway gives tool calls, extended to events:
//
//	meshmcp pubsub    --config broker.yaml           run a broker on the mesh
//	echo '{"level":"warn"}' | meshmcp publish 100.x.y.z:9120 alerts.prod
//	meshmcp subscribe 100.x.y.z:9120 'alerts.*'      stream events to stdout

// PubsubConfig configures a broker daemon.
type PubsubConfig struct {
	Mesh       MeshConfig            `yaml:"mesh"`
	ListenPort int                   `yaml:"listen_port"`
	Allow      []string              `yaml:"allow"`     // connection ACL: who may open a session at all
	AuditLog   string                `yaml:"audit_log"` // hash-chained JSONL decision log
	EventLog   string                `yaml:"event_log"` // durable append-only event stream (resumable + verifiable)
	// Signed Merkle checkpoints over the event stream (non-repudiation). Enable
	// by setting a signing key (from `meshmcp audit keygen`) and a checkpoints
	// file; every N events (default 128) a signed checkpoint is emitted.
	EventSigningKey      string `yaml:"event_signing_key"`
	EventCheckpoints     string `yaml:"event_checkpoints"`
	EventCheckpointEvery int    `yaml:"event_checkpoint_every"`

	// Signed capability grants: a caller presenting a token from one of these
	// pinned authority keys can subscribe/publish a topic beyond the default
	// deny. Name is the audience the grant's `aud` must equal.
	Name        string   `yaml:"name"`
	TrustedKeys []string `yaml:"trusted_public_keys"`

	Policy pubsub.RuleAuthorizer `yaml:"policy"` // per-topic authorization
	Limits pubsub.Limits         `yaml:"limits"` // resource caps
}

func loadPubsubConfig(path string) (*PubsubConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg PubsubConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, errors.New("listen_port must be 1-65535")
	}
	return &cfg, nil
}

// cmdPubsubVerify checks a persisted event log's hash chain, the same
// non-repudiation guarantee `meshmcp audit verify` gives the decision ledger.
func cmdPubsubVerify(args []string) error {
	fs := flag.NewFlagSet("pubsub verify", flag.ExitOnError)
	cps := fs.String("checkpoints", "", "also verify signed checkpoints from this file")
	pubkey := fs.String("pubkey", "", "expected signer public key (hex) to pin checkpoints against")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp pubsub verify [--checkpoints f --pubkey hex] <event-log>")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	events, err := pubsub.LoadEvents(f)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	var lastSeq uint64
	if n := len(events); n > 0 {
		lastSeq = events[n-1].Seq
	}

	if *cps != "" {
		cf, err := os.Open(*cps)
		if err != nil {
			return err
		}
		defer cf.Close()
		n, err := pubsub.VerifyCheckpoints(events, cf, *pubkey)
		if err != nil {
			return fmt.Errorf("checkpoint verification failed: %w", err)
		}
		fmt.Printf("OK: %d event(s), hash chain + %d signed checkpoint(s) verified (through seq %d)\n", len(events), n, lastSeq)
		return nil
	}
	fmt.Printf("OK: %d event(s), hash chain verified (through seq %d)\n", len(events), lastSeq)
	return nil
}

// cmdPubsubStats queries a running broker for a point-in-time snapshot
// (subscribers, sequence, retained events, drops). Gated by the broker's
// connection ACL, like any other session.
func cmdPubsubStats(args []string) error {
	fs := flag.NewFlagSet("pubsub stats", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp pubsub stats [flags] <peer-ip:port>")
	}
	target := fs.Arg(0)

	hello, _ := json.Marshal(helloFrame{Role: "stats"})
	var mu sync.Mutex
	var line string
	var got bool
	stream := &clientStream{out: append(hello, '\n'), done: make(chan struct{})}
	stream.onLine = func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		if got {
			return
		}
		got = true
		line = string(b)
		stream.finish()
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
	sc := session.NewClient(dial, log.Printf)
	runErr := sc.Run(context.Background(), stream)
	mu.Lock()
	g, resp := got, line
	mu.Unlock()
	if !g {
		if runErr != nil {
			return fmt.Errorf("stats from %s: %w", target, runErr)
		}
		return fmt.Errorf("stats from %s: no response", target)
	}
	var st pubsub.Stats
	if json.Unmarshal([]byte(resp), &st) == nil {
		fmt.Printf("subscriptions=%d  sequence=%d  retained=%d  dropped=%d\n",
			st.Subscriptions, st.Sequence, st.Retained, st.Dropped)
	} else {
		fmt.Println(resp)
	}
	return nil
}

// cmdPubsub runs the broker daemon, or verifies a persisted event log.
func cmdPubsub(args []string) error {
	if len(args) > 0 && args[0] == "verify" {
		return cmdPubsubVerify(args[1:])
	}
	if len(args) > 0 && args[0] == "stats" {
		return cmdPubsubStats(args[1:])
	}
	fs := flag.NewFlagSet("pubsub", flag.ExitOnError)
	cfgPath := fs.String("config", "", "broker config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("usage: meshmcp pubsub --config broker.yaml   (or: meshmcp pubsub verify <event-log>)")
	}
	cfg, err := loadPubsubConfig(*cfgPath)
	if err != nil {
		return err
	}

	client, err := startMesh(cfg.Mesh.options(), os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)
	if st, err := client.Status(); err == nil {
		log.Printf("pubsub broker up: %s (%s), port %d",
			strings.SplitN(st.LocalPeerState.IP, "/", 2)[0], st.LocalPeerState.FQDN, cfg.ListenPort)
	}

	var audit *policy.AuditLog
	if cfg.AuditLog != "" {
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open audit log %s: %w", cfg.AuditLog, err)
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}

	// Optional durable event log: resume the chain + replay window from the
	// persisted stream, then keep appending to it.
	var seed []pubsub.Event
	var eventLog *pubsub.EventLog
	if cfg.EventLog != "" {
		if data, err := os.ReadFile(cfg.EventLog); err == nil && len(data) > 0 {
			seed, err = pubsub.LoadEvents(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("event log %s: %w", cfg.EventLog, err)
			}
			var lastSeq uint64
			if n := len(seed); n > 0 {
				lastSeq = seed[n-1].Seq
			}
			log.Printf("resumed %d event(s) from %s (through seq %d)", len(seed), cfg.EventLog, lastSeq)
		} else if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read event log %s: %w", cfg.EventLog, err)
		}
		f, err := os.OpenFile(cfg.EventLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open event log %s: %w", cfg.EventLog, err)
		}
		defer f.Close()
		eventLog = pubsub.NewEventLog(f)

		// Optional signed Merkle checkpoints over the event stream.
		if cfg.EventSigningKey != "" && cfg.EventCheckpoints != "" {
			signer, err := policy.LoadSigner(cfg.EventSigningKey)
			if err != nil {
				return fmt.Errorf("event signing key: %w", err)
			}
			cpf, err := os.OpenFile(cfg.EventCheckpoints, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return fmt.Errorf("open event checkpoints %s: %w", cfg.EventCheckpoints, err)
			}
			defer cpf.Close()
			cp := policy.NewCheckpointer(signer, cpf, cfg.EventCheckpointEvery,
				func() string { return time.Now().UTC().Format(time.RFC3339) }, nil)
			// Continue the checkpoint chain across restarts from the existing file.
			if data, err := os.ReadFile(cfg.EventCheckpoints); err == nil {
				if seq, hash, ok := lastCheckpoint(data); ok {
					cp.SeedFrom(seq, hash)
				}
			}
			eventLog = eventLog.WithCheckpointer(cp)
			log.Printf("signed event checkpoints: %s (signer %s)", cfg.EventCheckpoints, signer.PubKeyHex())
		}
	}

	// Optional signed-capability grants (short-lived topic access minted
	// out-of-band, without editing the broker policy).
	var capVerifier *policy.CapabilityVerifier
	if len(cfg.TrustedKeys) > 0 {
		v, err := policy.NewCapabilityVerifier(cfg.TrustedKeys, func() time.Time { return time.Now() })
		if err != nil {
			return fmt.Errorf("capabilities: %w", err)
		}
		capVerifier = v
		log.Printf("capability grants accepted from %d authority key(s) for audience %q", len(cfg.TrustedKeys), cfg.Name)
	}

	policyCopy := cfg.Policy // take a stable address for the Authorizer
	broker := pubsub.New(pubsub.Options{
		Authorizer:   &policyCopy,
		Audit:        audit,
		Events:       eventLog,
		Seed:         seed,
		Name:         cfg.Name,
		Capabilities: capVerifier,
		Limits:       cfg.Limits,
	})
	defer broker.Close()

	// One admission path, shared with the gateway hook bus (identity proof +
	// ACL + session handoff).
	ln, err := serveBrokerOn(client, broker, cfg.ListenPort, cfg.Allow, log.Printf)
	if err != nil {
		return err
	}
	defer ln.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("pubsub broker shutting down")
	broker.Close() // stop publishes before sealing the final checkpoint
	if eventLog != nil {
		eventLog.Flush()
	}
	return nil
}

// lastCheckpoint parses the last checkpoint line from a checkpoints file, so a
// restart can continue the checkpoint chain from it.
func lastCheckpoint(data []byte) (seq int, hash string, ok bool) {
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if len(bytes.TrimSpace(lines[i])) == 0 {
			continue
		}
		var cp policy.Checkpoint
		if json.Unmarshal(lines[i], &cp) == nil {
			return cp.Seq, cp.Hash(), true
		}
		return 0, "", false
	}
	return 0, "", false
}

// cmdPublish publishes one event to a broker.
func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	o := meshFlags(fs)
	data := fs.String("data", "", "payload (default: read from stdin)")
	rawJSON := fs.Bool("json", false, "treat the payload as raw JSON (default: wrap it as a JSON string)")
	streamMode := fs.Bool("stream", false, "publish one event per stdin line over a single session (a producer feed)")
	retainFlag := fs.Bool("retain", false, "store this event as the topic's retained last-value (new subscribers receive it)")
	fileFlag := fs.String("file", "", "publish a file's bytes as a base64 (binary) payload")
	maxBytes := fs.Int64("max-bytes", 1<<20, "reject a payload larger than this (the broker enforces its own cap too)")
	capFlag := fs.String("capability", "", "present a signed capability grant; @file reads the token from a file")
	var labels stringList
	fs.Var(&labels, "label", "data-flow label to attach to the event (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: meshmcp publish [flags] <peer-ip:port> <topic>")
	}
	target, topic := fs.Arg(0), fs.Arg(1)
	capToken, err := readCapabilityToken(*capFlag)
	if err != nil {
		return err
	}

	if *streamMode {
		return streamPublish(o, target, topic, labels, *rawJSON, *maxBytes, capToken, *retainFlag)
	}

	var payload json.RawMessage
	enc := ""
	if *fileFlag != "" {
		raw, err := os.ReadFile(*fileFlag)
		if err != nil {
			return fmt.Errorf("read --file: %w", err)
		}
		if int64(len(raw)) > *maxBytes {
			return fmt.Errorf("file exceeds %d bytes", *maxBytes)
		}
		b64, _ := json.Marshal(base64.StdEncoding.EncodeToString(raw))
		payload = b64
		enc = "base64"
	} else {
		var body []byte
		if *data != "" {
			body = []byte(*data)
		} else {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, *maxBytes+1))
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
			body = b
		}
		if int64(len(body)) > *maxBytes {
			return fmt.Errorf("payload exceeds %d bytes", *maxBytes)
		}
		if *rawJSON {
			if !json.Valid(body) {
				return errors.New("--json set but payload is not valid JSON")
			}
			payload = json.RawMessage(body)
		} else {
			wrapped, _ := json.Marshal(string(body))
			payload = wrapped
		}
	}

	hello, _ := json.Marshal(helloFrame{Role: "pub", Capability: capToken})
	pub, _ := json.Marshal(pubFrame{Topic: topic, Labels: labels, Retain: *retainFlag, Enc: enc, Payload: payload})
	preamble := append(append(hello, '\n'), append(pub, '\n')...)

	// ack/gotAck are written in the session inbound goroutine (via onLine) and
	// read in this goroutine after Run returns; that goroutine is not joined,
	// so guard the shared state with a mutex to stay race-free.
	var mu sync.Mutex
	var ack ackFrame
	var gotAck bool
	stream := &clientStream{out: preamble, done: make(chan struct{})}
	stream.onLine = func(line []byte) {
		mu.Lock()
		defer mu.Unlock()
		if gotAck {
			return
		}
		gotAck = true
		_ = json.Unmarshal(line, &ack)
		stream.finish()
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
	sc := session.NewClient(dial, log.Printf)
	runErr := sc.Run(context.Background(), stream)
	mu.Lock()
	got, result := gotAck, ack
	mu.Unlock()
	if runErr != nil && !got {
		return fmt.Errorf("publish to %s: %w", target, runErr)
	}
	if !got {
		return fmt.Errorf("publish to %s: no acknowledgment received", target)
	}
	if result.Error != "" {
		return fmt.Errorf("broker rejected publish: %s", result.Error)
	}
	log.Printf("published to %q on %s (seq %d)", topic, target, result.Seq)
	return nil
}

// streamPublish is the producer path: it reads stdin line by line and publishes
// each line as one event over a single session (one mesh join, one broker
// connection), so a continuous feed does not pay the join cost per event.
func streamPublish(o *meshOptions, target, topic string, labels stringList, rawJSON bool, maxBytes int64, capToken string, retain bool) error {
	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	pr, pw := io.Pipe()
	st := &streamPubSink{r: pr}
	go func() {
		defer pw.Close()
		hello, _ := json.Marshal(helloFrame{Role: "pub", Capability: capToken})
		if _, err := pw.Write(append(hello, '\n')); err != nil {
			return
		}
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), int(maxBytes)+1)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var payload json.RawMessage
			if rawJSON {
				if !json.Valid(line) {
					log.Printf("skipping line: not valid JSON")
					continue
				}
				payload = append(json.RawMessage(nil), line...)
			} else {
				enc, _ := json.Marshal(string(line))
				payload = enc
			}
			pf, _ := json.Marshal(pubFrame{Topic: topic, Labels: labels, Retain: retain, Payload: payload})
			if _, err := pw.Write(append(pf, '\n')); err != nil {
				return
			}
		}
	}()

	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
	sc := session.NewClient(dial, log.Printf)
	runErr := sc.Run(context.Background(), st)
	ok, failed, lastErr := st.counts()
	if runErr != nil && ok == 0 && failed == 0 {
		return fmt.Errorf("publish stream to %s: %w", target, runErr)
	}
	log.Printf("published %d event(s) to %q on %s (%d rejected)", ok, topic, target, failed)
	if failed > 0 && lastErr != "" {
		log.Printf("last rejection: %s", lastErr)
	}
	return nil
}

// streamPubSink is the local end of a streaming publish: Read yields the framed
// outbound stream (hello + one pubFrame per stdin line) produced by the pump
// goroutine, and Write tallies the broker's per-event acks.
type streamPubSink struct {
	r     io.Reader
	mu    sync.Mutex
	inbuf []byte
	ok    int
	fail  int
	last  string
}

func (s *streamPubSink) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *streamPubSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.inbuf = append(s.inbuf, p...)
	var lines [][]byte
	for {
		i := bytes.IndexByte(s.inbuf, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, append([]byte(nil), s.inbuf[:i]...))
		s.inbuf = s.inbuf[i+1:]
	}
	for _, ln := range lines {
		if len(ln) == 0 {
			continue
		}
		var ack ackFrame
		if json.Unmarshal(ln, &ack) != nil {
			continue
		}
		if ack.Error != "" {
			s.fail++
			s.last = ack.Error
		} else {
			s.ok++
		}
	}
	s.mu.Unlock()
	return len(p), nil
}

func (s *streamPubSink) Close() error { return nil }

func (s *streamPubSink) counts() (ok, fail int, last string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ok, s.fail, s.last
}

// readCursor reads a persisted subscriber sequence cursor. ok is false if the
// file is absent or unparseable (treated as "start from the beginning").
func readCursor(path string) (seq uint64, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// writeCursor persists the last-seen sequence atomically (temp file + rename),
// so a crash mid-write cannot corrupt the cursor.
func writeCursor(path string, seq uint64) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(seq, 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cmdSubscribe streams events from a broker to stdout until interrupted.
func cmdSubscribe(args []string) error {
	fs := flag.NewFlagSet("subscribe", flag.ExitOnError)
	o := meshFlags(fs)
	since := fs.Uint64("since", 0, "replay retained events with sequence greater than this first")
	bp := fs.String("backpressure", "drop_oldest", "buffer-full policy: drop_oldest or disconnect")
	capFlag := fs.String("capability", "", "present a signed capability grant; @file reads the token from a file")
	durable := fs.String("durable", "", "persist the last-seen sequence to this file and resume from it (at-least-once across restarts)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("usage: meshmcp subscribe [flags] <peer-ip:port> <topic> [topic...]")
	}
	if _, err := pubsub.ParseBackpressure(*bp); err != nil {
		return err
	}
	capToken, err := readCapabilityToken(*capFlag)
	if err != nil {
		return err
	}
	target := fs.Arg(0)
	topics := fs.Args()[1:]

	// Durable subscriber: resume from the persisted cursor so no events are
	// missed across a disconnect or broker restart (with a broker event_log).
	effectiveSince := *since
	if *durable != "" {
		if c, ok := readCursor(*durable); ok && c > effectiveSince {
			effectiveSince = c
		}
	}

	hello, _ := json.Marshal(helloFrame{Role: "sub", Topics: topics, Since: effectiveSince, Backpressure: *bp, Capability: capToken})
	preamble := append(hello, '\n')

	out := os.Stdout
	// subErr is written in the session inbound goroutine (via onLine) and read
	// here after Run returns; guard it since that goroutine is not joined.
	var mu sync.Mutex
	var subErr error
	firstLine := true
	stream := &clientStream{out: preamble, done: make(chan struct{})}
	stream.onLine = func(line []byte) {
		if firstLine {
			firstLine = false
			var ack ackFrame
			_ = json.Unmarshal(line, &ack)
			if ack.Error != "" {
				mu.Lock()
				subErr = fmt.Errorf("broker rejected subscribe: %s", ack.Error)
				mu.Unlock()
				stream.finish()
				return
			}
			if ack.Truncated {
				log.Printf("warning: replay from seq %d was truncated; some events aged out of retention", *since)
			}
			log.Printf("subscribed to %v on %s", topics, target)
			return
		}
		out.Write(append(line, '\n'))
		if *durable != "" {
			var ev struct {
				Seq uint64 `json:"seq"`
			}
			if json.Unmarshal(line, &ev) == nil && ev.Seq > 0 {
				_ = writeCursor(*durable, ev.Seq)
			}
		}
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		log.Println("unsubscribing")
		stream.finish()
		cancel()
	}()

	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", target) }
	scl := session.NewClient(dial, log.Printf)
	err = scl.Run(ctx, stream)
	mu.Lock()
	se := subErr
	mu.Unlock()
	if se != nil {
		return se
	}
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("subscribe to %s: %w", target, err)
	}
	return nil
}
