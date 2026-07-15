package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"meshmcp/control"
	"meshmcp/policy"
	"meshmcp/registry"
)

// cmdControl runs the managed control plane: enrollment, the service registry,
// and policy distribution, served as a single mesh peer (no public port). A
// team points new nodes at it and they bootstrap themselves — the mesh without
// the operator toil.
func cmdControl(args []string) error {
	fs := flag.NewFlagSet("control", flag.ExitOnError)
	o := meshFlags(fs)
	port := fs.Int("port", 9600, "mesh port to serve the control API on")
	addr := fs.String("addr", "", "bind a plain local address instead of the mesh (dev/testing)")
	regDir := fs.String("registry", "", "service registry directory (enables /v1/registry)")
	polDir := fs.String("policies", "", "policy directory (enables /v1/policy)")
	enrollKey := fs.String("enroll-key", "", "static setup key handed to enrolling nodes ($NB_ENROLL_KEY)")
	enrollMgmt := fs.String("enroll-management-url", "", "management URL handed to enrolling nodes")
	nbToken := fs.String("netbird-token", "", "NetBird PAT to mint per-node one-off keys ($NB_API_TOKEN)")
	nbAPI := fs.String("netbird-api", "https://api.netbird.io", "NetBird management API base URL")
	nbGroups := fs.String("enroll-groups", "", "comma-separated NetBird groups to place enrolled nodes in")
	nbTTL := fs.Duration("enroll-ttl", 24*time.Hour, "issued key expiry")
	enrollAudit := fs.String("enroll-audit", "", "tamper-evident enrollment audit log (JSONL)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	srv := &control.Server{}
	if *regDir != "" {
		reg, err := registry.NewFileRegistry(*regDir)
		if err != nil {
			return fmt.Errorf("registry %s: %w", *regDir, err)
		}
		srv.Reg = reg
	}
	if *polDir != "" {
		ps, err := control.NewFilePolicyStore(*polDir)
		if err != nil {
			return fmt.Errorf("policies %s: %w", *polDir, err)
		}
		srv.Policies = ps
	}
	// Enrollment: prefer real NetBird key issuance (per-node one-off keys) when
	// a PAT is available; fall back to a static key otherwise.
	token := *nbToken
	if token == "" {
		token = os.Getenv("NB_API_TOKEN")
	}
	if token != "" {
		var enrollLog *policy.AuditLog
		if *enrollAudit != "" {
			f, err := os.OpenFile(*enrollAudit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				return fmt.Errorf("open enroll audit %s: %w", *enrollAudit, err)
			}
			defer f.Close()
			enrollLog = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
		}
		var groups []string
		if *nbGroups != "" {
			groups = strings.Split(*nbGroups, ",")
		}
		mgmt := *enrollMgmt
		if mgmt == "" {
			mgmt = o.ManagementURL
		}
		srv.Enroll = (&control.NetBirdIssuer{
			APIURL:        *nbAPI,
			ManagementURL: mgmt,
			Token:         token,
			Groups:        groups,
			TTL:           *nbTTL,
			RegistryDir:   *regDir,
			ControlNode:   o.DeviceName,
			Audit:         enrollLog,
		}).Enroll
		log.Printf("enrollment: NetBird key issuance via %s (per-node one-off keys)", *nbAPI)
	} else {
		key := *enrollKey
		if key == "" {
			key = os.Getenv("NB_ENROLL_KEY")
		}
		if key != "" {
			mgmt := *enrollMgmt
			if mgmt == "" {
				mgmt = o.ManagementURL
			}
			srv.Enroll = control.StaticEnroll(mgmt, key, *regDir, o.DeviceName)
			log.Printf("enrollment: static key (set --netbird-token for per-node key issuance)")
		}
	}

	handler := srv.Handler()

	// Dev/testing path: bind a plain local port, no mesh.
	if *addr != "" {
		log.Printf("control plane on http://%s (LOCAL, not on the mesh)", *addr)
		return http.ListenAndServe(*addr, handler)
	}

	o.BlockInbound = false
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)
	if st, err := client.Status(); err == nil {
		ip := strings.SplitN(st.LocalPeerState.IP, "/", 2)[0]
		log.Printf("control plane up: %s (%s) on mesh port %d", ip, st.LocalPeerState.FQDN, *port)
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", *port))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", *port, err)
	}
	defer ln.Close()
	return http.Serve(ln, handler)
}
