package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/atomicfile"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stunserver"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	// httpsTimeout is the read/write timeout of the HTTPS server. For derper
	// this basically only affects TLS setup, as read/write deadlines are
	// cleared on Hijack, which the DERP server does. But without it, we slowly
	// accumulate stuck TLS handshake goroutines forever.
	httpsTimeout = 30 * time.Second
	// httpTimeout is the read/write timeout of the plain HTTP server.
	httpTimeout = 60 * time.Second

	hstsValue = "max-age=63072000; includeSubDomains"

	// serverCount is the number of servers serve runs: HTTP and HTTPS.
	serverCount = 2

	privateDirPerm  = 0o700
	privateFilePerm = 0o600
)

var errNoDataDir = errors.New("--datadir not specified")

// defaultDataDir returns the default value of --datadir, or "" if the user
// config directory can't be determined.
func defaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}

	return filepath.Join(dir, "derp418")
}

// loadNodeKey returns the DERP node's private key stored in path, generating
// and saving one on first run.
func loadNodeKey(path string) (key.NodePrivate, error) {
	var nodeKey key.NodePrivate

	text, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		text, err = createNodeKey(path)
	}

	if err != nil {
		return nodeKey, fmt.Errorf("node key %s: %w", path, err)
	}

	err = nodeKey.UnmarshalText(text)
	if err != nil {
		return nodeKey, fmt.Errorf("parsing node key %s: %w", path, err)
	}

	return nodeKey, nil
}

// createNodeKey generates a node key and saves it, with private permissions,
// in path. It returns the saved text.
func createNodeKey(path string) ([]byte, error) {
	text, err := key.NewNode().MarshalText()
	if err != nil {
		return nil, fmt.Errorf("generating: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(path), privateDirPerm)
	if err != nil {
		return nil, fmt.Errorf("creating directory: %w", err)
	}

	err = atomicfile.WriteFile(path, text, privateFilePerm)
	if err != nil {
		return nil, fmt.Errorf("saving: %w", err)
	}

	return text, nil
}

func run(ctx context.Context) error {
	if *dataDir == "" {
		return errNoDataDir
	}

	domains, err := parseDomains(*domainsFlag, *apexFlag)
	if err != nil {
		return err
	}

	nodeKey, err := loadNodeKey(filepath.Join(*dataDir, "derper.key"))
	if err != nil {
		return err
	}

	go serveSTUN(ctx)

	derp := derpserver.New(nodeKey, log.Printf)
	// Only clients that are peers of the local tailscaled (i.e. members of
	// this tailnet) are admitted; if tailscaled can't be queried they are
	// refused.
	derp.SetVerifyClient(true)
	derp.SetTailscaledSocketPath(*socket)

	errorLog := log.New(logger.HTTPServerLogFilter{Inner: dropNotServed(log.Printf)}, "", 0)
	certManager := newCertManager(filepath.Join(*dataDir, "certs"), domains, *acmeEmail)
	httpsServer := newHTTPSServer(derp, domains, certManager, errorLog)
	httpServer := newHTTPServer(certManager, errorLog)

	return serve(ctx, httpsServer, httpServer, domains.preloadHosts())
}

func serveSTUN(ctx context.Context) {
	err := stunserver.New(ctx).ListenAndServe(*stunAddr)
	if err != nil {
		log.Printf("derper: STUN: %v", err)
	}
}

// newMux returns the HTTPS routes: DERP and its probes, the bootstrap DNS
// answer, and a redirect to the apex for everything else.
func newMux(derp *derpserver.Server, domains *domainSet) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.AddWebSocketSupport(derp, derpserver.Handler(derp)))

	// These two endpoints are the same. Different versions of the clients
	// have assumed different paths over time so we support both.
	mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
	mux.HandleFunc("/derp/latency-check", derpserver.ProbeHandler)

	bootstrap := bootstrapDNSHandler(splitNames(*bootstrapNames), net.DefaultResolver, bootstrapLookupTimeout)
	mux.HandleFunc("/bootstrap-dns", tsweb.BrowserHeaderHandlerFunc(bootstrap))
	mux.Handle("/generate_204", http.HandlerFunc(derpserver.ServeNoContent))
	mux.HandleFunc("/", domains.redirect)

	return mux
}

// newHTTPSServer returns the HTTPS server: ECDSA certificates for the served
// hosts, HSTS, and a teapot for anyone trying to use it as a CONNECT proxy.
func newHTTPSServer(
	derp *derpserver.Server, domains *domainSet, certManager *autocert.Manager, errorLog *log.Logger,
) *http.Server {
	mux := newMux(derp, domains)
	tlsCfg := tlsConfig(certManager, domains)
	derp.ModifyTLSConfigToAddMetaCert(tlsCfg)

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Strict-Transport-Security", hstsValue)

		if request.Method == http.MethodConnect {
			http.Error(writer, http.StatusText(http.StatusTeapot), http.StatusTeapot)

			return
		}

		mux.ServeHTTP(writer, request)
	})

	return newServer(redstar(handler), tlsCfg, errorLog, httpsTimeout)
}

// newHTTPServer returns the plain HTTP server: it answers the ACME challenges
// and /generate_204, and sends everything else to HTTPS.
func newHTTPServer(certManager *autocert.Manager, errorLog *log.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/generate_204", derpserver.ServeNoContent)
	mux.Handle("/", certManager.HTTPHandler(http.HandlerFunc(redirectToHTTPS)))

	return newServer(redstar(mux), nil, errorLog, httpTimeout)
}

// newServer returns an HTTP server with the given read/write timeout; TLSConfig
// may be nil for a plain one.
func newServer(handler http.Handler, tlsCfg *tls.Config, errorLog *log.Logger, timeout time.Duration) *http.Server {
	return &http.Server{
		Addr:                         "",
		Handler:                      handler,
		DisableGeneralOptionsHandler: false,
		TLSConfig:                    tlsCfg,
		ReadTimeout:                  timeout,
		ReadHeaderTimeout:            0,
		WriteTimeout:                 timeout,
		IdleTimeout:                  0,
		MaxHeaderBytes:               0,
		MaxHeaderValueCount:          0,
		TLSNextProto:                 nil,
		ConnState:                    nil,
		ErrorLog:                     errorLog,
		BaseContext:                  nil,
		ConnContext:                  nil,
		HTTP2:                        nil,
		Protocols:                    nil,
		DisableClientPriority:        false,
	}
}

// serve listens on both ports before anything needs them (the certificate
// challenges are answered on the plain HTTP one), preloads the certificates of
// preload, and serves until ctx ends or a server fails.
func serve(ctx context.Context, httpsServer, httpServer *http.Server, preload []string) error {
	var listenConfig net.ListenConfig

	httpListener, err := listenConfig.Listen(ctx, "tcp", *httpAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *httpAddr, err)
	}
	defer closeLogged(httpListener)

	httpsListener, err := listenConfig.Listen(ctx, "tcp", *httpsAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *httpsAddr, err)
	}
	defer closeLogged(httpsListener)

	log.Printf("derper: serving on %s and %s", *httpsAddr, *httpAddr)

	failed := make(chan error, serverCount)

	go func() { failed <- httpServer.Serve(httpListener) }()
	go func() { failed <- httpsServer.ServeTLS(httpsListener, "", "") }()

	go preloadCertificates(httpsServer.TLSConfig, preload, log.Printf)

	select {
	case err = <-failed:
	case <-ctx.Done():
		err = nil
	}

	closeLogged(httpServer)
	closeLogged(httpsServer)

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving: %w", err)
	}

	return nil
}

// closeLogged closes closer, logging an error other than "already closed".
func closeLogged(closer io.Closer) {
	err := closer.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("derper: closing: %v", err)
	}
}

// redirectToHTTPS sends plain HTTP requests to the same host and URI over
// HTTPS, as in the TLSRef reference configuration. ACME challenges and
// /generate_204 (captive portal detection, which must not be redirected) are
// answered before it is reached.
//
// It only sends the client back to the host it asked for, so the target is the
// client's own and not an open redirect.
func redirectToHTTPS(writer http.ResponseWriter, request *http.Request) {
	target := url.URL{
		Scheme:      "https",
		Opaque:      "",
		User:        nil,
		Host:        request.Host,
		Path:        request.URL.Path,
		RawPath:     request.URL.RawPath,
		OmitHost:    false,
		ForceQuery:  false,
		RawQuery:    request.URL.RawQuery,
		Fragment:    "",
		RawFragment: "",
	}
	http.Redirect(writer, request, target.String(), http.StatusMovedPermanently)
}
