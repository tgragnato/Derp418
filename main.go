package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"tailscale.com/version"
)

var (
	versionFlag = flag.Bool("version", false, "print version and exit")
	dataDir     = flag.String("datadir", defaultDataDir(),
		"directory for the node key and the TLS certificates (must persist across restarts)")
	domainsFlag = flag.String("domains", "",
		"comma-separated wildcard domains (required): every subdomain is served over TLS, DERP included, "+
			"and so are www and the bare name of each one except --apex; any other request is redirected to --apex")
	apexFlag = flag.String("apex", "",
		"domain every request that isn't DERP is redirected to (required); it is not served by this server")
	httpsAddr = flag.String("https-addr", ":443", "HTTPS listen address")
	httpAddr  = flag.String("http-addr", ":80", "HTTP listen address: ACME challenges and redirect to HTTPS")
	stunAddr  = flag.String("stun-addr", ":3478", "STUN UDP listen address")
	acmeEmail = flag.String("acme-email", "", "optional ACME account contact email address")
	socket    = flag.String("socket", "",
		"optional alternate path to the local tailscaled socket, used to verify clients (default: the OS default socket)")
	bootstrapNames = flag.String("bootstrap-dns-names", defaultBootstrapNames,
		"comma-separated hostnames to resolve and serve at /bootstrap-dns")
)

// defaultBootstrapNames is the set the official DERP servers publish: clients
// use these to reach the control plane when their own DNS resolution is broken.
const defaultBootstrapNames = "controlplane.tailscale.com,login.tailscale.com,login.us.tailscale.com," +
	"log.tailscale.com,log.tailscale.io"

func main() {
	code := mainCode()
	if code != 0 {
		os.Exit(code)
	}
}

// mainCode runs the server and returns the process exit code.
func mainCode() int {
	flag.Parse()

	if *versionFlag {
		fmt.Println(version.Long())

		return 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	err := run(ctx)
	if err != nil {
		slog.Error("derper stopped", "error", err)

		return 1
	}

	return 0
}
