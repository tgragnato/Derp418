package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/types/logger"
)

// errHostNotServed is what a handshake for a host this server doesn't answer
// for (no SNI, an IP, another domain) fails with. dropNotServed keeps it out of
// the log.
var errHostNotServed = errors.New("host not served")

// newCertManager returns an autocert.Manager that keeps its ACME account key
// and certificates in dir. It obtains one certificate per subdomain, on the
// first connection to it, for hosts served by domains only.
func newCertManager(dir string, domains *domainSet, email string) *autocert.Manager {
	mgr := new(autocert.Manager)
	mgr.Prompt = autocert.AcceptTOS
	mgr.HostPolicy = domains.hostPolicy
	mgr.Cache = autocert.DirCache(dir)
	mgr.Email = email

	return mgr
}

// dropNotServed returns a logger that discards the TLS handshake errors caused
// by errHostNotServed, which port scanners and clients connecting by IP produce
// all day, and passes everything else to inner.
func dropNotServed(inner logger.Logf) logger.Logf {
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if strings.HasSuffix(strings.TrimSpace(msg), ": "+errHostNotServed.Error()) {
			return
		}

		inner("%s", msg)
	}
}

// tlsConfig returns mgr's TLS config, serving ECDSA certificates only, for the
// hosts of domains, and following the TLSRef "modern" guideline (v6.0): TLS 1.3
// only, post-quantum hybrid key exchange preferred. HTTP/1.1 only (plus the
// ACME TLS-ALPN challenge), as DERP upgrades the connection.
func tlsConfig(mgr *autocert.Manager, domains *domainSet) *tls.Config {
	cfg := mgr.TLSConfig()

	// Certificates are ECDSA only. autocert falls back to RSA for any client
	// whose hello doesn't list an ECDSA-specific TLS 1.2 cipher suite, which
	// includes TLS 1.3-only clients. Present it with a hello that always
	// qualifies for ECDSA; a client that can't verify ECDSA certificates then
	// fails the handshake instead of being served RSA.
	getCertificate := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !domains.served(hello.ServerName) {
			return nil, errHostNotServed
		}

		ecdsaHello := *hello
		ecdsaHello.SignatureSchemes = []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
		ecdsaHello.SupportedCurves = []tls.CurveID{tls.CurveP256}
		ecdsaHello.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

		return getCertificate(&ecdsaHello)
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.CurvePreferences = []tls.CurveID{
		tls.X25519MLKEM768,
		tls.X25519,
		tls.CurveP384,
	}
	cfg.NextProtos = []string{"http/1.1", acme.ALPNProto}

	return cfg
}

// helloFor returns the hello of a client asking for host, as far as the
// certificate lookup is concerned.
func helloFor(host string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		CipherSuites:      nil,
		ServerName:        host,
		SupportedCurves:   nil,
		SupportedPoints:   nil,
		SignatureSchemes:  nil,
		SupportedProtos:   nil,
		SupportedVersions: nil,
		Extensions:        nil,
		Conn:              nil,
		HelloRetryRequest: false,
	}
}

// preloadCertificates obtains, or loads from the cache, the certificate of each
// host, so the first client doesn't wait for an ACME order and a failing setup
// (DNS, ports 80 and 443) shows up in the log at startup. It must run once the
// listeners are up, as the challenges are answered through them.
func preloadCertificates(cfg *tls.Config, hosts []string, logf logger.Logf) {
	for _, host := range hosts {
		go func() {
			_, err := cfg.GetCertificate(helloFor(host))
			if err != nil {
				logf("derper: preloading certificate for %s: %v", host, err)

				return
			}

			logf("derper: certificate for %s ready", host)
		}()
	}
}
