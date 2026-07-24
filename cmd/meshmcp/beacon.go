package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/xrey167/meshmcp/beacon"
)

// cmdBeacon runs the public passthrough relay: `meshmcp beacon --zone ...`.
//
// The beacon is the "zero inbound ports" ingress companion to `meshmcp edge`
// (docs/design/HOSTED-CLIENT-INGRESS.md). Gateways dial OUT to the control
// listener and register, receiving a stable public subdomain derived from their
// key; hosted clients (e.g. claude.ai custom connectors) reach the public
// listener and are routed to the right gateway by their cleartext SNI, spliced as
// raw bytes. The beacon terminates NO TLS and holds NO gateway key — TLS
// terminates on each gateway with the gateway's OWN certificate, so the beacon
// sees only ciphertext and the SNI routing label.
func cmdBeacon(args []string) error {
	fs := flag.NewFlagSet("beacon", flag.ExitOnError)
	zone := fs.String("zone", "", "public DNS zone the beacon serves, e.g. beacon.example.com (required)")
	publicAddr := fs.String("public", ":443", "public TLS listen address — hosted clients connect here")
	controlAddr := fs.String("control", ":7443", "gateway tunnel listen address — gateways dial out to here")
	dnsAddr := fs.String("dns", "", "authoritative DNS listen address, e.g. :53 (optional; enables ACME DNS-01 so gateways auto-provision certs)")
	publicIP := fs.String("public-ip", "", "the beacon's public IPv4 that <label>.<zone> A records resolve to (required with --dns)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *zone == "" {
		return fmt.Errorf("beacon: --zone is required (the public DNS zone, e.g. beacon.example.com)")
	}
	var ip net.IP
	if *dnsAddr != "" {
		if *publicIP == "" {
			return fmt.Errorf("beacon: --public-ip is required with --dns (the address <label>.%s resolves to)", *zone)
		}
		if ip = net.ParseIP(*publicIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("beacon: --public-ip %q is not a valid IPv4 address", *publicIP)
		}
	}

	publicLn, err := net.Listen("tcp", *publicAddr)
	if err != nil {
		return fmt.Errorf("beacon: listen public %s: %w", *publicAddr, err)
	}
	controlLn, err := net.Listen("tcp", *controlAddr)
	if err != nil {
		publicLn.Close()
		return fmt.Errorf("beacon: listen control %s: %w", *controlAddr, err)
	}

	srv := beacon.NewServer(*zone)
	srv.SetLogf(log.Printf)

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	defer stop()

	fmt.Fprintf(os.Stderr, "meshmcp beacon: zone *.%s — public %s, control %s (TLS terminates on each gateway; the beacon splices ciphertext only)\n",
		*zone, *publicAddr, *controlAddr)

	if *dnsAddr != "" {
		srv.SetPublicIP(ip)
		go func() {
			if err := srv.ServeDNS(ctx, *dnsAddr); err != nil && ctx.Err() == nil {
				log.Printf("beacon: dns server on %s stopped: %v", *dnsAddr, err)
			}
		}()
		fmt.Fprintf(os.Stderr, "meshmcp beacon: authoritative DNS on %s (A *.%s -> %s; TXT _acme-challenge.* for gateway DNS-01)\n",
			*dnsAddr, *zone, *publicIP)
	}

	return srv.Run(ctx, publicLn, controlLn)
}
