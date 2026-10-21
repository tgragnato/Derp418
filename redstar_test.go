package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

const (
	derpTimeout = 20 * time.Second
	payload     = "through the teapot"
)

var (
	phpSessionCookie = regexp.MustCompile(`^PHPSESSID=[0-9a-v]{26}; path=/$`)
	phpSessionValue  = regexp.MustCompile(`^[0-9a-v]{26}$`)
)

func TestPHPSessionID(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}

	for range 100 {
		session := phpSessionID()
		if !phpSessionValue.MatchString(session) {
			t.Fatalf("bad session id %q", session)
		}

		if seen[session] {
			t.Fatalf("repeated session id %q", session)
		}

		seen[session] = true
	}
}

type headerCase struct {
	name            string
	handler         http.HandlerFunc
	wantCode        int
	wantContentType string // "" means no Content-Type
}

func headerCases() []headerCase {
	return []headerCase{
		{
			"implicit 200",
			func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hi") },
			http.StatusOK, htmlType,
		},
		{
			"go error page",
			func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", http.StatusServiceUnavailable) },
			http.StatusServiceUnavailable, htmlType,
		},
		{"not found", http.NotFound, http.StatusNotFound, htmlType},
		{
			"redirect",
			func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/x", http.StatusMovedPermanently) },
			http.StatusMovedPermanently, htmlType,
		},
		{
			"html lowercase charset",
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
			},
			http.StatusOK, htmlType,
		},
		{
			"json is kept",
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, "{}")
			},
			http.StatusOK, "application/json",
		},
		{
			"no content",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
			http.StatusNoContent, "",
		},
		{
			"not modified",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotModified) },
			http.StatusNotModified, "",
		},
		{
			"empty 200 gets a type",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
			http.StatusOK, htmlType,
		},
	}
}

func TestRedstarHeaders(t *testing.T) {
	t.Parallel()

	wantHeaders := map[string]string{
		"Server":        redstarServer,
		"Expires":       "Thu, 19 Nov 1981 08:52:00 GMT",
		"Cache-Control": "no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
		"Pragma":        "no-cache",
		"Vary":          "Accept-Encoding",
	}

	for _, tcase := range headerCases() {
		t.Run(tcase.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			redstar(tcase.handler).ServeHTTP(recorder, request)

			result := recorder.Result()
			defer result.Body.Close()

			if result.StatusCode != tcase.wantCode {
				t.Errorf("status = %d, want %d", result.StatusCode, tcase.wantCode)
			}

			for name, want := range wantHeaders {
				if got := result.Header.Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}

			cookies := result.Header.Values("Set-Cookie")
			if len(cookies) != 1 || !phpSessionCookie.MatchString(cookies[0]) {
				t.Errorf("Set-Cookie = %q", cookies)
			}

			if got := result.Header.Get("Content-Type"); got != tcase.wantContentType {
				t.Errorf("Content-Type = %q, want %q", got, tcase.wantContentType)
			}

			if got := result.Header.Get("X-Content-Type-Options"); got != "" {
				t.Errorf("X-Content-Type-Options = %q, want it dropped", got)
			}
		})
	}
}

func TestRedstarDistinctCookies(t *testing.T) {
	t.Parallel()

	handler := redstar(http.NotFoundHandler())
	cookie := func() string {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

		return recorder.Header().Get("Set-Cookie")
	}

	if first, second := cookie(), cookie(); first == second {
		t.Errorf("same cookie twice: %q", first)
	}
}

func TestRedstarSwitchingProtocolsUntouched(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	handler := redstar(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusSwitchingProtocols)
	}))
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	if got := recorder.Header().Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type of a 1xx = %q, want it left alone", got)
	}
}

// fetch returns the status, headers and body of a GET to target.
func fetch(t *testing.T, target string) (int, http.Header, string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	return response.StatusCode, response.Header, string(body)
}

func TestRedstarHijackAndFlush(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(redstar(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if _, ok := writer.(http.Flusher); !ok {
			t.Error("not a Flusher")
		}

		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Error("not a Hijacker")

			return
		}

		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)

			return
		}
		defer conn.Close()

		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})))
	defer server.Close()

	if _, _, body := fetch(t, server.URL); body != "ok" {
		t.Errorf("body = %q", body)
	}
}

// newRedstarDERP starts a DERP server behind redstar, the way run wires it.
func newRedstarDERP(t *testing.T) *httptest.Server {
	t.Helper()

	derpServer := derpserver.New(key.NewNode(), func(string, ...any) {})

	t.Cleanup(func() { _ = derpServer.Close() })

	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.AddWebSocketSupport(derpServer, derpserver.Handler(derpServer)))

	server := httptest.NewServer(redstar(mux))
	t.Cleanup(server.Close)

	return server
}

// connectDERP connects a new DERP client to the server and returns it with
// its public key.
func connectDERP(ctx context.Context, t *testing.T, server *httptest.Server) (*derphttp.Client, key.NodePublic) {
	t.Helper()

	private := key.NewNode()

	client, err := derphttp.NewClient(private, server.URL+"/derp", func(string, ...any) {}, netmon.NewStatic())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = client.Close() })

	err = client.Connect(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	return client, private.Public()
}

// firstPacket returns the data of the first packet client receives.
func firstPacket(client *derphttp.Client) <-chan string {
	got := make(chan string, 1)

	go func() {
		for {
			msg, err := client.Recv()
			if err != nil {
				return // client closed at the end of the test
			}

			if packet, ok := msg.(derp.ReceivedPacket); ok {
				got <- string(packet.Data)

				return
			}
		}
	}()

	return got
}

func TestDERPThroughRedstar(t *testing.T) {
	t.Parallel()

	server := newRedstarDERP(t)

	ctx, cancel := context.WithTimeout(t.Context(), derpTimeout)
	defer cancel()

	sender, _ := connectDERP(ctx, t, server)
	receiver, receiverKey := connectDERP(ctx, t, server)
	got := firstPacket(receiver)

	// The receiver may not be registered with the server yet when the sender
	// first sends, in which case that packet is dropped: keep sending until
	// one gets through.
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case data := <-got:
			if data != payload {
				t.Fatalf("got %q, want %q", data, payload)
			}

			return
		case <-tick.C:
			err := sender.Send(receiverKey, []byte(payload))
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("no packet reached the peer")
		}
	}
}

func TestDERPWebSocketThroughRedstar(t *testing.T) {
	t.Parallel()

	server := newRedstarDERP(t)

	ctx, cancel := context.WithTimeout(t.Context(), derpTimeout)
	defer cancel()

	options := &websocket.DialOptions{
		HTTPClient:           nil,
		HTTPHeader:           nil,
		Host:                 "",
		Subprotocols:         []string{"derp"},
		CompressionMode:      websocket.CompressionDisabled,
		CompressionThreshold: 0,
		OnPingReceived:       nil,
		OnPongReceived:       nil,
	}

	conn, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/derp", options)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// A successful upgrade leaves no body to close.
	if response.Body != nil {
		defer response.Body.Close()
	}

	defer conn.Close(websocket.StatusNormalClosure, "")

	if got := conn.Subprotocol(); got != "derp" {
		t.Errorf("subprotocol = %q", got)
	}
}

func TestPlainRequestToDERPEndpoint(t *testing.T) {
	t.Parallel()

	server := newRedstarDERP(t)

	status, header, _ := fetch(t, server.URL+"/derp")
	if status != http.StatusUpgradeRequired {
		t.Errorf("status = %d, want 426", status)
	}

	if got := header.Get("Server"); got != redstarServer {
		t.Errorf("Server = %q, want the Red Star banner on a plain request to /derp", got)
	}
}
