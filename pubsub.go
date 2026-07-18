package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
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
	Policy     pubsub.RuleAuthorizer `yaml:"policy"`    // per-topic authorization
	Limits     pubsub.Limits         `yaml:"limits"`    // resource caps
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

// cmdPubsub runs the broker daemon.
func cmdPubsub(args []string) error {
	fs := flag.NewFlagSet("pubsub", flag.ExitOnError)
	cfgPath := fs.String("config", "", "broker config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("usage: meshmcp pubsub --config broker.yaml")
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

	policyCopy := cfg.Policy // take a stable address for the Authorizer
	broker := pubsub.New(pubsub.Options{
		Authorizer: &policyCopy,
		Audit:      audit,
		Limits:     cfg.Limits,
	})
	defer broker.Close()

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", cfg.ListenPort, err)
	}
	checker := newACL(cfg.Allow)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; ln.Close() }()

	srv := session.NewServer(func(meta session.Meta) (session.Backend, error) {
		return newBrokerBackend(broker, meta, log.Printf), nil
	}, 2*time.Minute, log.Printf)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("pubsub broker shutting down")
			return nil
		}
		pubKey, fqdn := peerIdentity(client, conn.RemoteAddr())
		if pubKey == "" {
			log.Printf("pubsub session DENIED from %s: identity could not be proven", conn.RemoteAddr())
			conn.Close()
			continue
		}
		if !checker.allows(pubKey, fqdn) {
			log.Printf("pubsub session DENIED from %s (%s): not in allow list", fqdn, shortKey(pubKey))
			conn.Close()
			continue
		}
		go srv.Handle(conn, session.Meta{PeerFQDN: fqdn, PeerAddr: conn.RemoteAddr().String(), PeerKey: pubKey})
	}
}

// cmdPublish publishes one event to a broker.
func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	o := meshFlags(fs)
	data := fs.String("data", "", "payload (default: read from stdin)")
	rawJSON := fs.Bool("json", false, "treat the payload as raw JSON (default: wrap it as a JSON string)")
	maxBytes := fs.Int64("max-bytes", 1<<20, "reject a payload larger than this (the broker enforces its own cap too)")
	var labels stringList
	fs.Var(&labels, "label", "data-flow label to attach to the event (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: meshmcp publish [flags] <peer-ip:port> <topic>")
	}
	target, topic := fs.Arg(0), fs.Arg(1)

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

	var payload json.RawMessage
	if *rawJSON {
		if !json.Valid(body) {
			return errors.New("--json set but payload is not valid JSON")
		}
		payload = json.RawMessage(body)
	} else {
		enc, _ := json.Marshal(string(body))
		payload = enc
	}

	hello, _ := json.Marshal(helloFrame{Role: "pub"})
	pub, _ := json.Marshal(pubFrame{Topic: topic, Labels: labels, Payload: payload})
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

// cmdSubscribe streams events from a broker to stdout until interrupted.
func cmdSubscribe(args []string) error {
	fs := flag.NewFlagSet("subscribe", flag.ExitOnError)
	o := meshFlags(fs)
	since := fs.Uint64("since", 0, "replay retained events with sequence greater than this first")
	bp := fs.String("backpressure", "drop_oldest", "buffer-full policy: drop_oldest or disconnect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("usage: meshmcp subscribe [flags] <peer-ip:port> <topic> [topic...]")
	}
	if _, err := pubsub.ParseBackpressure(*bp); err != nil {
		return err
	}
	target := fs.Arg(0)
	topics := fs.Args()[1:]

	hello, _ := json.Marshal(helloFrame{Role: "sub", Topics: topics, Since: *since, Backpressure: *bp})
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
