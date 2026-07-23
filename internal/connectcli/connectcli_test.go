package connectcli

import (
	"flag"
	"io"
	"strings"
	"testing"
	"time"
)

func TestMeshFlagsDefaults(t *testing.T) {
	t.Setenv("NB_MANAGEMENT_URL", "")
	t.Setenv("NB_SETUP_KEY", "")
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o := MeshFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if o.ManagementURL != "" || o.SetupKey != "" {
		t.Fatalf("env-less defaults must be empty: %+v", o)
	}
	if o.StartTimeout != 2*time.Minute {
		t.Fatalf("start timeout default: %v", o.StartTimeout)
	}
	if o.WireguardPort != 0 {
		t.Fatalf("wg port default must be 0 (random): %d", o.WireguardPort)
	}
}

func TestStartMeshRequiresSetupKey(t *testing.T) {
	_, err := StartMesh(&MeshOptions{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "setup key required") {
		t.Fatalf("want setup-key error, got %v", err)
	}
}

func TestConnectUsage(t *testing.T) {
	if err := Connect([]string{}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("want usage error with no target, got %v", err)
	}
}
