package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/types/logger"
)

var (
	errNotTLS                   = errors.New("not a TLS connection")
	errTestCertificateFailure = errors.New("test certificate failure")
)

const (
	certValidity  = 60 * 24 * time.Hour
	handshakeWait = 10 * time.Second
	rsaBits       = 2048
)

// signer returns a new key of the given kind with its PEM encoding.
func signer(t *testing.T, useRSA bool) (crypto.Signer, []byte) {
	t.Helper()

	if useRSA {
		priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			t.Fatal(err)
		}

		return priv, pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Headers: nil, Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	return priv, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: nil, Bytes: der})
}

// cacheCert stores a self-signed certificate for host in the autocert cache
// under name, in the layout autocert reads: the private key, then the chain.
func cacheCert(t *testing.T, cache autocert.Cache, name, host string, useRSA bool) {
	t.Helper()

	priv, keyPEM := signer(t, useRSA)
	// A literal would have to spell out every one of x509.Certificate's fields.
	template := new(x509.Certificate)
	template.SerialNumber = big.NewInt(1)
	template.Subject = pkix.Name{
		Country:            nil,
		Organization:       nil,
		OrganizationalUnit: nil,
		Locality:           nil,
		Province:           nil,
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         host,
		Names:              nil,
		ExtraNames:         nil,
	}
	template.DNSNames = []string{host}
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(certValidity)

	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	blob := slices.Concat(keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: nil, Bytes: der}))

	err = cache.Put(t.Context(), name, blob)
	if err != nil {
		t.Fatal(err)
	}
}

// testDomains returns the domains the TLS tests serve.
func testDomains(t *testing.T) *domainSet {
	t.Helper()

	domains, err := parseDomains(testWildcard, testApex)
	if err != nil {
		t.Fatal(err)
	}

	return domains
}

// newTestManager returns a manager serving dir's cache whose ACME client can't
// reach any CA, so a test that tries to order a certificate fails fast.
func newTestManager(t *testing.T, dir string) (*autocert.Manager, *domainSet) {
	t.Helper()

	domains := testDomains(t)
	mgr := newCertManager(dir, domains, "")
	mgr.Client = &acme.Client{
		Key:          nil,
		HTTPClient:   nil,
		DirectoryURL: "http://127.0.0.1:1/directory",
		RetryBackoff: nil,
		UserAgent:    "",
		KID:          "",
	}

	return mgr, domains
}

// newTestTLSConfig returns the server TLS config over a cache in dir.
func newTestTLSConfig(t *testing.T, dir string) *tls.Config {
	t.Helper()

	mgr, domains := newTestManager(t, dir)

	return tlsConfig(mgr, domains)
}

// serveTLS serves cfg on a local port, completing handshakes only.
func serveTLS(t *testing.T, cfg *tls.Config) string {
	t.Helper()

	var listenConfig net.ListenConfig

	plain, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	listener := tls.NewListener(plain, cfg)
	ctx := t.Context()

	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()

				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.HandshakeContext(ctx)
				}
			}()
		}
	}()

	return listener.Addr().String()
}

func dialTLS(ctx context.Context, addr string, cfg *tls.Config) (*tls.ConnectionState, error) {
	// A literal would have to spell out net.Dialer's deprecated fields.
	netDialer := new(net.Dialer)
	netDialer.Timeout = handshakeWait

	dialer := &tls.Dialer{NetDialer: netDialer, Config: cfg}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", addr, err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("dialing %s: %w", addr, errNotTLS)
	}

	state := tlsConn.ConnectionState()

	return &state, nil
}

// clientConfig returns a TLS client config for sni that skips verification: the
// test certificates are self-signed.
func clientConfig(sni string) *tls.Config {
	// A literal would have to spell out tls.Config's deprecated fields.
	cfg := new(tls.Config)
	cfg.ServerName = sni
	cfg.InsecureSkipVerify = true
	cfg.MinVersion = tls.VersionTLS13

	return cfg
}

func TestNewCertManager(t *testing.T) {
	t.Parallel()

	mgr, _ := newTestManager(t, t.TempDir())
	if mgr.Prompt == nil || mgr.Cache == nil || mgr.HostPolicy == nil {
		t.Fatalf("manager not fully set up: %+v", mgr)
	}

	//nolint:staticcheck // deprecated, but it is exactly the flag that must stay off: no RSA, ever
	if mgr.ForceRSA {
		t.Error("ForceRSA is set")
	}

	err := mgr.HostPolicy(t.Context(), testHost)
	if err != nil {
		t.Errorf("served host refused: %v", err)
	}

	err = mgr.HostPolicy(t.Context(), testApex)
	if err == nil {
		t.Error("apex accepted")
	}
}

func TestTLSConfig(t *testing.T) {
	t.Parallel()

	cfg := newTestTLSConfig(t, t.TempDir())
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
	}

	wantCurves := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP384}
	if !reflect.DeepEqual(cfg.CurvePreferences, wantCurves) {
		t.Errorf("CurvePreferences = %v, want %v", cfg.CurvePreferences, wantCurves)
	}

	wantProtos := []string{testHTTP11, acme.ALPNProto}
	if !reflect.DeepEqual(cfg.NextProtos, wantProtos) {
		t.Errorf("NextProtos = %v, want %v", cfg.NextProtos, wantProtos)
	}

	if cfg.GetCertificate == nil {
		t.Error("GetCertificate is nil")
	}
}

func TestServesECDSAOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache := autocert.DirCache(dir)
	cacheCert(t, cache, testHost, testHost, false)
	cacheCert(t, cache, testHost+"+rsa", testHost, true) // must never be served

	addr := serveTLS(t, newTestTLSConfig(t, dir))

	// A TLS 1.3-only hello doesn't list ECDSA-specific TLS 1.2 suites, which
	// makes plain autocert pick RSA.
	state, err := dialTLS(t.Context(), addr, clientConfig(testHost))
	if err != nil {
		t.Fatal(err)
	}

	if got := state.PeerCertificates[0].PublicKeyAlgorithm; got != x509.ECDSA {
		t.Errorf("served a %v certificate, want ECDSA", got)
	}

	if state.Version != tls.VersionTLS13 {
		t.Errorf("negotiated %#x, want TLS 1.3", state.Version)
	}
}

func TestPlainAutocertWouldServeRSA(t *testing.T) {
	t.Parallel()

	// Guards the reason for the GetCertificate wrapper: if autocert stops
	// preferring RSA for these clients, the wrapper can go.
	dir := t.TempDir()
	cache := autocert.DirCache(dir)
	cacheCert(t, cache, testHost, testHost, false)
	cacheCert(t, cache, testHost+"+rsa", testHost, true)

	mgr, _ := newTestManager(t, dir)
	cfg := mgr.TLSConfig()
	cfg.MinVersion = tls.VersionTLS13

	state, err := dialTLS(t.Context(), serveTLS(t, cfg), clientConfig(testHost))
	if err != nil {
		t.Fatal(err)
	}

	if got := state.PeerCertificates[0].PublicKeyAlgorithm; got != x509.RSA {
		t.Skipf("autocert now serves %v to a TLS 1.3-only client", got)
	}
}

func TestRefusesHostsNotServed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cacheCert(t, autocert.DirCache(dir), testOtherHost, testOtherHost, false)

	addr := serveTLS(t, newTestTLSConfig(t, dir))

	for _, sni := range []string{testOtherHost, testApex, "", testIP} {
		t.Run("sni="+sni, func(t *testing.T) {
			t.Parallel()

			_, err := dialTLS(t.Context(), addr, clientConfig(sni))
			if err == nil {
				t.Error("handshake succeeded")
			}
		})
	}
}

func TestGetCertificateNotServed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cache := autocert.DirCache(dir)
	cacheCert(t, cache, testHost, testHost, false)
	cacheCert(t, cache, testOtherHost, testOtherHost, false)

	cfg := newTestTLSConfig(t, dir)

	for _, sni := range []string{"", testOtherHost, testApex, testIP, "evilexample.org"} {
		t.Run("sni="+sni, func(t *testing.T) {
			t.Parallel()

			_, err := cfg.GetCertificate(helloFor(sni))
			if !errors.Is(err, errHostNotServed) {
				t.Errorf("error = %v, want errHostNotServed", err)
			}
		})
	}

	t.Run("served host", func(t *testing.T) {
		t.Parallel()

		cert, err := cfg.GetCertificate(helloFor(testHost))
		if err != nil || cert == nil {
			t.Errorf("GetCertificate = %v, %v", cert, err)
		}
	})
}

func TestFilterLogf(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, line string
		wantKept   bool
	}{
		{"no SNI", "http: TLS handshake error from 192.0.2.1:5000: host not served\n", false},
		{"no trailing newline", "http: TLS handshake error from [2001:db8::1]:5000: host not served", false},
		{
			"unsupported TLS versions",
			"http: TLS handshake error from 192.0.2.1:5000: tls: client offered only unsupported versions: [303 302 301]\n",
			false,
		},
		{
			"no common cipher suite",
			"http: TLS handshake error from 192.0.2.1:5000: tls: no cipher suite supported by both client and server; " +
				"client offered: [16 33 c09e]\n",
			false,
		},
		{
			"plain HTTP on HTTPS",
			"http: TLS handshake error from 192.0.2.1:5000: client sent an HTTP request to an HTTPS server\n",
			false,
		},
		{
			"ACME failure",
			"http: TLS handshake error from 192.0.2.1:5000: acme/autocert: unable to authorize\n",
			true,
		},
		{
			"ACME rate limit",
			"http: TLS handshake error from 192.0.2.1:5000: 429 "+
				"urn:ietf:params:acme:error:rateLimited: too many certificates\n",
			true,
		},
		{"mentions it elsewhere", "host not served is what we return\n", true},
		{"unrelated line", "http: Accept error: too many open files\n", true},
	}
	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			t.Parallel()

			var got []string

			filterLogf(func(format string, args ...any) {
				got = append(got, fmt.Sprintf(format, args...))
			}, httpServerLogFilters()...)("%s", tcase.line)

			if kept := len(got) == 1; kept != tcase.wantKept {
				t.Fatalf("kept = %v (%q), want %v", kept, got, tcase.wantKept)
			}

			if tcase.wantKept && got[0] != tcase.line {
				t.Errorf("line changed: %q", got[0])
			}
		})
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	written, err := b.buf.Write(data)
	if err != nil {
		return written, fmt.Errorf("buffering: %w", err)
	}

	return written, nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// waitFor polls until cond holds, failing the test after handshakeWait.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(handshakeWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func TestNotServedHandshakesAreNotLogged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cacheCert(t, autocert.DirCache(dir), testHost, testHost, false)

	var out syncBuffer

	logf := filterLogf(
		func(format string, args ...any) { _, _ = fmt.Fprintf(&out, format, args...) },
		httpServerLogFilters()...,
	)
	errorLog := log.New(logger.HTTPServerLogFilter{Inner: logf}, "", 0)
	tlsCfg := newTestTLSConfig(t, dir)
	getCertificate := tlsCfg.GetCertificate
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == testHost {
			return nil, errTestCertificateFailure
		}

		return getCertificate(hello)
	}
	server := newServer(http.NotFoundHandler(), tlsCfg, errorLog, httpsTimeout)

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() { _ = server.ServeTLS(listener, "", "") }()

	t.Cleanup(func() { _ = server.Close() })

	// Handshakes that fail for being unserved: nothing may be logged for them.
	for _, sni := range []string{"", testOtherHost, testApex, testIP} {
		_, err := dialTLS(t.Context(), listener.Addr().String(), clientConfig(sni))
		if err == nil {
			t.Fatalf("sni %q: handshake succeeded", sni)
		}
	}

	// A different handshake failure must still be logged. It also marks the
	// point by which the server has logged everything it was going to.
	_, err = dialTLS(t.Context(), listener.Addr().String(), clientConfig(testHost))
	if err == nil {
		t.Fatal("handshake with failing certificate succeeded")
	}

	waitFor(t, "the certificate failure to be logged", func() bool {
		return strings.Contains(out.String(), "TLS handshake error")
	})
	time.Sleep(100 * time.Millisecond)

	if got := out.String(); strings.Contains(got, "host not served") || strings.Count(got, "TLS handshake error") != 1 {
		t.Errorf("log:\n%s", got)
	}
}

func TestRefusesOlderTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cacheCert(t, autocert.DirCache(dir), testHost, testHost, false)

	addr := serveTLS(t, newTestTLSConfig(t, dir))

	old := clientConfig(testHost)
	old.MinVersion = 0
	old.MaxVersion = tls.VersionTLS12

	_, err := dialTLS(t.Context(), addr, old)
	if err == nil {
		t.Error("TLS 1.2 handshake succeeded")
	}
}

func TestNoHTTP2(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cacheCert(t, autocert.DirCache(dir), testHost, testHost, false)

	addr := serveTLS(t, newTestTLSConfig(t, dir))

	cfg := clientConfig(testHost)
	cfg.NextProtos = []string{"h2", testHTTP11}

	state, err := dialTLS(t.Context(), addr, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if state.NegotiatedProtocol != testHTTP11 {
		t.Errorf("negotiated %q, want http/1.1: DERP can't run over HTTP/2", state.NegotiatedProtocol)
	}
}

func TestPreloadCertificates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cacheCert(t, autocert.DirCache(dir), testWWW, testWWW, false)
	cfg := newTestTLSConfig(t, dir)

	var out syncBuffer

	preloadCertificates(cfg, []string{testWWW, testWildcard}, func(format string, args ...any) {
		_, _ = fmt.Fprintf(&out, format+"\n", args...)
	})

	waitFor(t, "both preloads to be reported", func() bool {
		return strings.Contains(out.String(), "certificate for www.example.org ready") &&
			strings.Contains(out.String(), "preloading certificate for example.org")
	})
}
