package main

import (
	"strings"
	"testing"
)

// Shared by the tests of this package.
const (
	testApex      = "example.com"
	testWildcard  = "example.org"
	testNet       = "example.net"
	testHost      = "a.example.org"
	testWWW       = "www.example.org"
	testIP        = "1.2.3.4"
	testOtherHost = "other.io"
	testHTTP11    = "http/1.1"
)

// The flags are package-level variables; nothing in the tests calls
// flag.Parse, so they hold their defaults.
func TestFlagDefaults(t *testing.T) {
	t.Parallel()

	defaults := map[string]struct{ got, want string }{
		"https-addr": {*httpsAddr, ":443"},
		"http-addr":  {*httpAddr, ":80"},
		"stun-addr":  {*stunAddr, ":3478"},
		"domains":    {*domainsFlag, ""},
		"apex":       {*apexFlag, ""},
		"acme-email": {*acmeEmail, ""},
		"socket":     {*socket, ""},
		"datadir":    {*dataDir, defaultDataDir()},
	}
	for name, value := range defaults {
		if value.got != value.want {
			t.Errorf("--%s defaults to %q, want %q", name, value.got, value.want)
		}
	}

	if *versionFlag {
		t.Error("--version defaults to true")
	}
}

func TestBootstrapNamesDefault(t *testing.T) {
	t.Parallel()

	want := []string{
		"controlplane.tailscale.com",
		"login.tailscale.com",
		"login.us.tailscale.com",
		"log.tailscale.com",
		"log.tailscale.io",
	}

	got := strings.Split(*bootstrapNames, ",")
	if len(got) != len(want) {
		t.Fatalf("--bootstrap-dns-names defaults to %q", *bootstrapNames)
	}

	for idx := range want {
		if got[idx] != want[idx] {
			t.Errorf("name %d = %q, want %q", idx, got[idx], want[idx])
		}
	}
}
