package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/xrey167/meshmcp/air"
)

// cmdAirDNS prints the DNS records an operator publishes so a gateway's Air
// catalog is discoverable from a domain name (ARD legs 2–3). The record
// generation and resolution logic lives in the air package; this is the CLI
// wiring. meshmcp does not run DNS — it only emits records to publish.
func cmdAirDNS(args []string) error {
	fs := flag.NewFlagSet("air dns", flag.ExitOnError)
	control := fs.String("control", "", "the gateway's control endpoint on the mesh (mesh-ip:port)")
	srvHost := fs.String("srv-host", "", "the gateway's mesh FQDN for the SRV target (default: the control ip)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air dns <domain> --control <mesh-ip:port> [--srv-host fqdn]")
	}
	domain := fs.Arg(0)
	if *control == "" {
		return errors.New("air dns: --control <mesh-ip:port> is required")
	}
	host, portStr, err := net.SplitHostPort(*control)
	if err != nil {
		return fmt.Errorf("air dns: bad --control %q: %w", *control, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return fmt.Errorf("air dns: bad port in --control %q: %w", *control, err)
	}
	recs, err := air.DNSRecords(domain, host, port, *srvHost)
	if err != nil {
		return fmt.Errorf("air dns: %w", err)
	}
	fmt.Fprintln(os.Stderr, dim("# publish these records so `air catalog --resolve "+domain+"` finds this gateway:"))
	for _, rec := range recs {
		fmt.Println(rec)
	}
	return nil
}
