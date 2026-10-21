package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bootstrapLookupTimeout bounds the time a /bootstrap-dns request waits for the
// resolver.
const bootstrapLookupTimeout = 5 * time.Second

// ipResolver is the part of *net.Resolver the bootstrap DNS handler uses.
type ipResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// splitNames parses a comma-separated list of host names.
func splitNames(list string) []string {
	var names []string

	for name := range strings.SplitSeq(list, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}

	return names
}

// shuffle puts ips in a random order, so clients don't always prefer the same
// address family. If the system has no randomness the order is left alone.
func shuffle(ips []net.IP) {
	for last := len(ips) - 1; last > 0; last-- {
		pick, err := rand.Int(rand.Reader, big.NewInt(int64(last)+1))
		if err != nil {
			return
		}

		other := int(pick.Int64())
		ips[last], ips[other] = ips[other], ips[last]
	}
}

// bootstrapDNSHandler answers with the addresses of names, as {"name": [ip, ...]},
// resolving them through res on every request and in parallel; the system's
// resolver is expected to do the caching. Names that don't resolve are left out,
// and if none does the answer is a 503.
//
// Clients whose own DNS is broken use this to reach the control plane.
func bootstrapDNSHandler(names []string, res ipResolver, timeout time.Duration) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), timeout)
		defer cancel()

		results := make([][]net.IP, len(names))

		var group sync.WaitGroup
		for idx, name := range names {
			group.Go(func() {
				addrs, err := res.LookupIP(ctx, "ip", name)
				if err != nil {
					log.Printf("bootstrap DNS lookup %q: %v", name, err)

					return
				}

				shuffle(addrs)
				results[idx] = addrs
			})
		}

		group.Wait()

		answer := make(map[string][]net.IP)

		for idx, addrs := range results {
			if len(addrs) > 0 {
				answer[names[idx]] = addrs
			}
		}

		if len(answer) == 0 {
			http.Error(writer, "bootstrap DNS unavailable", http.StatusServiceUnavailable)

			return
		}

		payload, err := json.MarshalIndent(answer, "", "\t")
		if err != nil {
			http.Error(writer, fmt.Sprint(err), http.StatusInternalServerError)

			return
		}

		writer.Header().Set("Content-Type", "application/json")
		// Bootstrap DNS requests occur cross-regions, so keeping a connection
		// open is pointlessly expensive.
		writer.Header().Set("Connection", "close")

		_, _ = writer.Write(payload)
	}
}
