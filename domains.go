package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	errNoDomains = errors.New("--domains must list at least one domain")
	errNotDomain = errors.New("not a DNS domain")
)

// domainSet describes what this server answers for.
//
// Every subdomain of a wildcard domain is served over TLS (DERP included), and
// so is each wildcard domain itself, except apex: that is where everything that
// isn't DERP is redirected, and it is hosted elsewhere.
type domainSet struct {
	apex    string
	domains []string // wildcard domains; may include apex
}

func parseDomains(list, apex string) (*domainSet, error) {
	apex, err := cleanDomain("--apex", apex)
	if err != nil {
		return nil, err
	}

	set := &domainSet{apex: apex, domains: nil}

	for entry := range strings.SplitSeq(list, ",") {
		if strings.TrimSpace(entry) == "" {
			continue
		}

		domain, err := cleanDomain("--domains", entry)
		if err != nil {
			return nil, err
		}

		set.domains = append(set.domains, domain)
	}

	if len(set.domains) == 0 {
		return nil, errNoDomains
	}

	return set, nil
}

func cleanDomain(flagName, name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return "", fmt.Errorf("%s: %q: %w", flagName, name, errNotDomain)
	}

	return name, nil
}

// served reports whether host is one this server answers for.
func (set *domainSet) served(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == set.apex {
		return false // redirecting it to itself would loop
	}

	for _, domain := range set.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

// hostPolicy is the autocert.HostPolicy: certificates are only issued for
// hosts that are served.
func (set *domainSet) hostPolicy(_ context.Context, host string) error {
	if !set.served(host) {
		return fmt.Errorf("%q: %w", host, errHostNotServed)
	}

	return nil
}

// preloadHosts returns the hosts whose certificates are obtained at startup:
// www and the bare name of every wildcard domain other than apex.
func (set *domainSet) preloadHosts() []string {
	var hosts []string

	for _, domain := range set.domains {
		if domain != set.apex {
			hosts = append(hosts, "www."+domain, domain)
		}
	}

	return hosts
}

// hostOnly returns hostport without its port, if it has one.
func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}

	return host
}

// redirect sends the request to the same path and query on the apex. Hosts
// that aren't served, apex included, get a 404.
func (set *domainSet) redirect(writer http.ResponseWriter, request *http.Request) {
	if !set.served(hostOnly(request.Host)) {
		http.NotFound(writer, request)

		return
	}

	http.Redirect(writer, request, httpsURL(set.apex, request), http.StatusMovedPermanently)
}

// httpsURL returns the URL of request's path and query on host, over HTTPS.
func httpsURL(host string, request *http.Request) string {
	target := url.URL{
		Scheme:      "https",
		Opaque:      "",
		User:        nil,
		Host:        host,
		Path:        request.URL.Path,
		RawPath:     request.URL.RawPath,
		OmitHost:    false,
		ForceQuery:  false,
		RawQuery:    request.URL.RawQuery,
		Fragment:    "",
		RawFragment: "",
	}

	return target.String()
}
