package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Easter egg: every plain HTTP response claims to come from a Red Star OS 4.0
// box (Apache 2.4.25 with PHP 5.6.2), with the PHP 5 session cookie and the
// "nocache" headers such a server sends. DERP connections are unaffected: their
// upgrade response is written straight to the connection.

const (
	redstarServer = "Apache/2.4.25 (RedStar4.0) OpenSSL/1.0.1e-fips PHP/5.6.2"
	htmlType      = "text/html; charset=UTF-8"

	// sessionIDLength and sessionIDMask describe a PHP 5 session id: 26
	// characters of 5 bits each.
	sessionIDLength = 26
	sessionIDMask   = 31
)

func redstar(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := writer.Header()
		header.Set("Server", redstarServer)
		header.Add("Set-Cookie", "PHPSESSID="+phpSessionID()+"; path=/")
		header.Set("Expires", "Thu, 19 Nov 1981 08:52:00 GMT")
		header.Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
		header.Set("Pragma", "no-cache")
		header.Set("Vary", "Accept-Encoding")
		next.ServeHTTP(&redstarWriter{ResponseWriter: writer, wroteHeader: false}, request)
	})
}

// phpSessionID returns 26 characters of [0-9a-v], the format of a PHP 5
// session id (5 bits per character).
func phpSessionID() string {
	const alphabet = "0123456789abcdefghijklmnopqrstuv"

	var session [sessionIDLength]byte

	_, _ = rand.Read(session[:]) // never fails

	for idx := range session {
		session[idx] = alphabet[session[idx]&sessionIDMask]
	}

	return string(session[:])
}

// redstarWriter makes the headers Go adds on its own look like PHP's: HTML is
// always "text/html; charset=UTF-8", the plain-text error pages become HTML,
// and "X-Content-Type-Options", which Apache doesn't send, is dropped.
type redstarWriter struct {
	http.ResponseWriter

	wroteHeader bool
}

func (writer *redstarWriter) WriteHeader(code int) {
	if code >= http.StatusOK && !writer.wroteHeader {
		writer.wroteHeader = true
		header := writer.Header()

		contentType := header.Get("Content-Type")
		switch {
		case strings.HasPrefix(contentType, "text/html"), strings.HasPrefix(contentType, "text/plain"):
			header.Set("Content-Type", htmlType)
		case contentType == "" && code != http.StatusNoContent && code != http.StatusNotModified:
			header.Set("Content-Type", htmlType)
		}

		header.Del("X-Content-Type-Options")
	}

	writer.ResponseWriter.WriteHeader(code)
}

func (writer *redstarWriter) Write(data []byte) (int, error) {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}

	written, err := writer.ResponseWriter.Write(data)
	if err != nil {
		return written, fmt.Errorf("writing response: %w", err)
	}

	return written, nil
}

// Hijack, Flush and Unwrap keep DERP (which hijacks the connection) working.
func (writer *redstarWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(writer.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("hijacking connection: %w", err)
	}

	return conn, rw, nil
}

func (writer *redstarWriter) Flush() {
	// http.Flusher has no way to report an error.
	_ = http.NewResponseController(writer.ResponseWriter).Flush()
}

func (writer *redstarWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }
