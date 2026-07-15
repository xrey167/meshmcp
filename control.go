package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"meshmcp/control"
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
	enrollKey := fs.String("enroll-key", "", "setup key handed to enrolling nodes ($NB_ENROLL_KEY)")
	enrollMgmt := fs.String("enroll-management-url", "", "management URL handed to enrolling nodes")
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
