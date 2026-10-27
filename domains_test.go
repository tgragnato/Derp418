package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParseDomains(t *testing.T) {
	t.Parallel()

	good := []struct {
		name, list, apex string
		wantApex         string
		wantDomains      []string
	}{
		{"single", testWildcard, testApex, testApex, []string{testWildcard}},
		{
			"normalized", " Example.ORG. , example.net ,", "EXAMPLE.com.",
			testApex, []string{testWildcard, testNet},
		},
		{
			"apex in the list", testApex + "," + testWildcard, testApex,
			testApex, []string{testApex, testWildcard},
		},
	}
	for _, tcase := range good {
		t.Run("ok/"+tcase.name, func(t *testing.T) {
			t.Parallel()

			domains, err := parseDomains(tcase.list, tcase.apex)
			if err != nil {
				t.Fatal(err)
			}

			if domains.apex != tcase.wantApex || !reflect.DeepEqual(domains.domains, tcase.wantDomains) {
				t.Errorf("got apex %q domains %q", domains.apex, domains.domains)
			}
		})
	}

	bad := []struct {
		name, list, apex string
		want             error
	}{
		{"no domains", "", testApex, errNoDomains},
		{"only separators", " , ,", testApex, errNoDomains},
		{"no apex", testWildcard, "", errNotDomain},
		{"apex is an IP", testWildcard, testIP, errNotDomain},
		{"apex is not a domain", testWildcard, "localhost", errNotDomain},
		{"domain is an IP", testIP, testApex, errNotDomain},
		{"domain is not a domain", testWildcard + ",localhost", testApex, errNotDomain},
	}
	for _, tcase := range bad {
		t.Run("err/"+tcase.name, func(t *testing.T) {
			t.Parallel()

			domains, err := parseDomains(tcase.list, tcase.apex)
			if !errors.Is(err, tcase.want) {
				t.Errorf("error = %v (domains %+v), want %v", err, domains, tcase.want)
			}
		})
	}
}

func TestServed(t *testing.T) {
	t.Parallel()

	domains, err := parseDomains(testApex+","+testWildcard+","+testNet, testApex)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		host string
		want bool
	}{
		{"derp.example.com", true},
		{"a.example.com", true},
		{"a.b.example.com", false},
		{"www.example.com", true},
		{testApex, false}, // the apex is the redirect target
		{testWildcard, true},
		{testWWW, true},
		{"x.example.org", true},
		{testNet, true},
		{"a.b.example.net", false},
		{"Derp.Example.COM.", true},
		{"EXAMPLE.com", false},
		{"evilexample.org", false},
		{"example.org.evil.net", false},
		{testOtherHost, false},
		{testIP, false},
		{"", false},
	}
	for _, tcase := range cases {
		t.Run(tcase.host, func(t *testing.T) {
			t.Parallel()

			if got := domains.served(tcase.host); got != tcase.want {
				t.Errorf("served(%q) = %v", tcase.host, got)
			}

			err := domains.hostPolicy(t.Context(), tcase.host)
			if (err == nil) != tcase.want {
				t.Errorf("hostPolicy(%q) = %v", tcase.host, err)
			}

			if err != nil && !errors.Is(err, errHostNotServed) {
				t.Errorf("hostPolicy(%q) = %v, want errHostNotServed", tcase.host, err)
			}
		})
	}
}

func TestServedApexInsideWildcard(t *testing.T) {
	t.Parallel()

	// The apex is a subdomain of a wildcard domain: it must still not be served.
	domains, err := parseDomains(testWildcard, "site.example.org")
	if err != nil {
		t.Fatal(err)
	}

	if domains.served("site.example.org") {
		t.Error("apex is served")
	}

	if !domains.served("other.example.org") {
		t.Error("sibling of the apex is not served")
	}
}

func TestPreloadHosts(t *testing.T) {
	t.Parallel()

	domains, err := parseDomains(testApex+","+testWildcard+","+testNet, testApex)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{testWWW, testWildcard, "www.example.net", testNet}
	if got := domains.preloadHosts(); !reflect.DeepEqual(got, want) {
		t.Errorf("preloadHosts = %q, want %q", got, want)
	}
}

func TestRedirect(t *testing.T) {
	t.Parallel()

	domains, err := parseDomains(testApex+","+testWildcard, testApex)
	if err != nil {
		t.Fatal(err)
	}

	moved := http.StatusMovedPermanently

	cases := []struct {
		name, host, uri string
		wantCode        int
		wantLocation    string
	}{
		{"subdomain", testHost, "/x?y=1", moved, "https://example.com/x?y=1"},
		{"wildcard of the apex", "derp.example.com", "/", moved, "https://example.com/"},
		{"bare wildcard domain", testWildcard, "/a/b", moved, "https://example.com/a/b"},
		{"host with port", testHost + ":443", "/", moved, "https://example.com/"},
		{
			"query is escaped as sent", testHost, "/p?q=%20&r=a%2Fb",
			moved, "https://example.com/p?q=%20&r=a%2Fb",
		},
		{"encoded slash is kept", testHost, "/a%2Fb/c", moved, "https://example.com/a%2Fb/c"},
		{"apex itself", testApex, "/", http.StatusNotFound, ""},
		{"apex with port", testApex + ":443", "/", http.StatusNotFound, ""},
		{"unknown host", testOtherHost, "/", http.StatusNotFound, ""},
		{"IP", testIP, "/", http.StatusNotFound, ""},
	}
	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tcase.uri, nil)
			request.Host = tcase.host
			recorder := httptest.NewRecorder()
			domains.redirect(recorder, request)

			if recorder.Code != tcase.wantCode {
				t.Fatalf("status = %d, want %d", recorder.Code, tcase.wantCode)
			}

			if got := recorder.Header().Get("Location"); got != tcase.wantLocation {
				t.Errorf("Location = %q, want %q", got, tcase.wantLocation)
			}
		})
	}
}
