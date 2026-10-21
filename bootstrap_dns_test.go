package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

const (
	loginName = "login.example.com"
	logName   = "log.example.com"
	nameA     = "a.example.com"
	nameB     = "b.example.com"
	nameC     = "c.example.com"
	slowName  = "slow.example.com"
	shortA    = "a.com"
)

var errNoSuchHost = errors.New("no such host")

// fakeResolver answers LookupIP from a table; names missing from it fail.
type fakeResolver struct {
	answers map[string][]net.IP
	// If set, every lookup waits until the whole group is in flight at once.
	barrier *sync.WaitGroup

	mu    sync.Mutex
	calls []string
}

func newFakeResolver(answers map[string][]net.IP) *fakeResolver {
	return &fakeResolver{answers: answers, barrier: nil, mu: sync.Mutex{}, calls: nil}
}

func (res *fakeResolver) LookupIP(ctx context.Context, _, host string) ([]net.IP, error) {
	res.mu.Lock()
	res.calls = append(res.calls, host)
	res.mu.Unlock()

	if res.barrier != nil {
		res.barrier.Done()

		everyoneIn := make(chan struct{})

		go func() { res.barrier.Wait(); close(everyoneIn) }()

		select {
		case <-everyoneIn:
		case <-ctx.Done():
			return nil, fmt.Errorf("looking up %s: %w", host, ctx.Err())
		}
	}

	addrs, ok := res.answers[host]
	if !ok {
		return nil, errNoSuchHost
	}

	return slices.Clone(addrs), nil
}

func (res *fakeResolver) lookups() int {
	res.mu.Lock()
	defer res.mu.Unlock()

	return len(res.calls)
}

// blockingResolver never answers until the context ends.
type blockingResolver struct{}

func (blockingResolver) LookupIP(ctx context.Context, _, host string) ([]net.IP, error) {
	<-ctx.Done()

	return nil, fmt.Errorf("looking up %s: %w", host, ctx.Err())
}

// mixedResolver blocks on one name and delegates the rest.
type mixedResolver struct {
	fast *fakeResolver
	slow string
}

func (res mixedResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if host == res.slow {
		return blockingResolver{}.LookupIP(ctx, network, host)
	}

	return res.fast.LookupIP(ctx, network, host)
}

func ips(addrs ...string) []net.IP {
	out := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, net.ParseIP(addr))
	}

	return out
}

func serveBootstrap(t *testing.T, handler http.HandlerFunc, target string) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))

	return recorder
}

func decodeAnswer(t *testing.T, body []byte) map[string][]string {
	t.Helper()

	var got map[string][]string

	err := json.Unmarshal(body, &got)
	if err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, body)
	}

	return got
}

func TestSplitNames(t *testing.T) {
	t.Parallel()

	cases := []struct {
		list string
		want []string
	}{
		{shortA + ",b.com", []string{shortA, "b.com"}},
		{" a.com , b.com ,", []string{shortA, "b.com"}},
		{shortA, []string{shortA}},
		{"", nil},
		{" , ,", nil},
	}
	for _, tcase := range cases {
		if got := splitNames(tcase.list); !reflect.DeepEqual(got, tcase.want) {
			t.Errorf("splitNames(%q) = %q, want %q", tcase.list, got, tcase.want)
		}
	}
}

func addrStrings(addrs []net.IP) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}

	slices.Sort(out)

	return out
}

func TestShuffleKeepsTheAddresses(t *testing.T) {
	t.Parallel()

	addrs := ips("192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2")
	shuffled := slices.Clone(addrs)
	shuffle(shuffled)

	if got, want := addrStrings(shuffled), addrStrings(addrs); !reflect.DeepEqual(got, want) {
		t.Errorf("shuffle changed the set of addresses: %v, want %v", got, want)
	}

	shuffle(nil)
	shuffle(ips("192.0.2.1"))
}

func TestShuffleReorders(t *testing.T) {
	t.Parallel()

	addrs := ips(
		"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
		"192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8",
	)

	// 8! orders: the chance of 50 shuffles all leaving the order alone is nil.
	for range 50 {
		shuffled := slices.Clone(addrs)

		shuffle(shuffled)

		if !reflect.DeepEqual(shuffled, addrs) {
			return
		}
	}

	t.Error("50 shuffles never changed the order")
}

func TestBootstrapDNSAnswer(t *testing.T) {
	t.Parallel()

	res := newFakeResolver(map[string][]net.IP{
		loginName: ips("192.0.2.1", "2001:db8::1"),
		logName:   ips("192.0.2.2"),
	})
	handler := bootstrapDNSHandler([]string{loginName, logName}, res, time.Second)

	recorder := serveBootstrap(t, handler, "/bootstrap-dns")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}

	if got := recorder.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection = %q, want close", got)
	}

	got := decodeAnswer(t, recorder.Body.Bytes())

	want := map[string][]string{loginName: {"192.0.2.1", "2001:db8::1"}, logName: {"192.0.2.2"}}
	for name, addrs := range want {
		slices.Sort(got[name])
		slices.Sort(addrs)

		if !reflect.DeepEqual(got[name], addrs) {
			t.Errorf("%s = %v, want %v", name, got[name], addrs)
		}
	}

	if len(got) != len(want) {
		t.Errorf("answer = %v", got)
	}
}

func TestBootstrapDNSResolvesEveryRequest(t *testing.T) {
	t.Parallel()

	res := newFakeResolver(map[string][]net.IP{nameA: ips("192.0.2.1")})
	handler := bootstrapDNSHandler([]string{nameA}, res, time.Second)

	for range 3 {
		serveBootstrap(t, handler, "/bootstrap-dns")
	}

	if got := res.lookups(); got != 3 {
		t.Errorf("%d lookups for 3 requests, want 3: nothing is cached here", got)
	}
}

func TestBootstrapDNSIgnoresQuery(t *testing.T) {
	t.Parallel()

	res := newFakeResolver(map[string][]net.IP{nameA: ips("192.0.2.1")})
	handler := bootstrapDNSHandler([]string{nameA}, res, time.Second)

	for _, target := range []string{"/bootstrap-dns", "/bootstrap-dns?q=" + nameA, "/bootstrap-dns?q=whatever"} {
		recorder := serveBootstrap(t, handler, target)

		if got := decodeAnswer(t, recorder.Body.Bytes()); len(got) != 1 || len(got[nameA]) != 1 {
			t.Errorf("%s: answer = %v", target, got)
		}
	}
}

func TestBootstrapDNSLeavesOutFailures(t *testing.T) {
	t.Parallel()

	res := newFakeResolver(map[string][]net.IP{"up.example.com": ips("192.0.2.1")})
	handler := bootstrapDNSHandler([]string{"up.example.com", "down.example.com"}, res, time.Second)

	recorder := serveBootstrap(t, handler, "/bootstrap-dns")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}

	got := decodeAnswer(t, recorder.Body.Bytes())
	if _, ok := got["down.example.com"]; ok || len(got["up.example.com"]) != 1 {
		t.Errorf("answer = %v", got)
	}
}

func TestBootstrapDNSUnavailable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		names []string
		res   ipResolver
	}{
		{"every lookup fails", []string{nameA, nameB}, newFakeResolver(nil)},
		{"no names", nil, newFakeResolver(nil)},
		{"a name with no addresses", []string{nameA}, newFakeResolver(map[string][]net.IP{nameA: nil})},
	}
	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			t.Parallel()

			handler := bootstrapDNSHandler(tcase.names, tcase.res, time.Second)
			if recorder := serveBootstrap(t, handler, "/bootstrap-dns"); recorder.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", recorder.Code)
			}
		})
	}
}

func TestBootstrapDNSLooksUpInParallel(t *testing.T) {
	t.Parallel()

	// Each lookup waits for the other two to be in flight: sequential lookups
	// would deadlock until the timeout and fail the request.
	names := []string{nameA, nameB, nameC}

	res := newFakeResolver(map[string][]net.IP{
		nameA: ips("192.0.2.1"), nameB: ips("192.0.2.2"), nameC: ips("192.0.2.3"),
	})
	res.barrier = &sync.WaitGroup{}
	res.barrier.Add(len(names))

	recorder := serveBootstrap(t, bootstrapDNSHandler(names, res, 5*time.Second), "/bootstrap-dns")
	if recorder.Code != http.StatusOK || len(decodeAnswer(t, recorder.Body.Bytes())) != len(names) {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

func TestBootstrapDNSTimeout(t *testing.T) {
	t.Parallel()

	start := time.Now()

	handler := bootstrapDNSHandler([]string{slowName}, blockingResolver{}, 100*time.Millisecond)

	recorder := serveBootstrap(t, handler, "/bootstrap-dns")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", recorder.Code)
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v, the timeout is 100ms", elapsed)
	}
}

func TestBootstrapDNSSlowNameDoesNotHoldBackTheOthers(t *testing.T) {
	t.Parallel()

	res := mixedResolver{
		fast: newFakeResolver(map[string][]net.IP{"fast.example.com": ips("192.0.2.1")}),
		slow: slowName,
	}
	handler := bootstrapDNSHandler([]string{"fast.example.com", slowName}, res, 200*time.Millisecond)

	recorder := serveBootstrap(t, handler, "/bootstrap-dns")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}

	got := decodeAnswer(t, recorder.Body.Bytes())
	if len(got["fast.example.com"]) != 1 || len(got) != 1 {
		t.Errorf("answer = %v", got)
	}
}

func TestBootstrapDNSDefaultResolver(t *testing.T) {
	t.Parallel()

	// "localhost" resolves without a network.
	handler := bootstrapDNSHandler([]string{"localhost"}, net.DefaultResolver, bootstrapLookupTimeout)

	recorder := serveBootstrap(t, handler, "/bootstrap-dns")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}

	if got := decodeAnswer(t, recorder.Body.Bytes()); !slices.Contains(got["localhost"], "127.0.0.1") {
		t.Errorf("localhost = %v", got["localhost"])
	}
}
