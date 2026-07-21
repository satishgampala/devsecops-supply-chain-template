package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParsePortAcceptsValidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "default", raw: "", want: "8080"},
		{name: "minimum", raw: "1", want: "1"},
		{name: "typical", raw: "8080", want: "8080"},
		{name: "maximum", raw: "65535", want: "65535"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := parsePort(test.raw)
			if err != nil {
				t.Fatalf("parsePort() error = %v", err)
			}
			if got != test.want {
				t.Errorf("parsePort() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestParsePortRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"text", "0", "-1", "65536"} {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			if _, err := parsePort(raw); err == nil {
				t.Fatal("parsePort() error = nil, want an error")
			}
		})
	}
}

func TestNewServerSetsResourceLimits(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newServer("127.0.0.1:8080", handler)

	if server.Addr != "127.0.0.1:8080" {
		t.Errorf("Addr = %q, want %q", server.Addr, "127.0.0.1:8080")
	}
	if server.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %s, want %s", server.ReadHeaderTimeout, 5*time.Second)
	}
	if server.ReadTimeout != 10*time.Second {
		t.Errorf("ReadTimeout = %s, want %s", server.ReadTimeout, 10*time.Second)
	}
	if server.WriteTimeout != 10*time.Second {
		t.Errorf("WriteTimeout = %s, want %s", server.WriteTimeout, 10*time.Second)
	}
	if server.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %s, want %s", server.IdleTimeout, 60*time.Second)
	}
	if server.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, 1<<20)
	}
}

func TestRunHealthcheckSucceedsOnHealthyEndpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	if err := runHealthcheck(context.Background(), serverPort(t, server)); err != nil {
		t.Fatalf("runHealthcheck() error = %v", err)
	}
}

func TestRunHealthcheckRejectsNonOKResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	if err := runHealthcheck(context.Background(), serverPort(t, server)); err == nil {
		t.Fatal("runHealthcheck() error = nil, want an error")
	}
}

func TestRunHealthcheckRejectsConnectionError(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runHealthcheck(ctx, port); err == nil {
		t.Fatal("runHealthcheck() error = nil, want an error")
	}
}

func TestRunHealthcheckHonorsExpiredContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runHealthcheck(ctx, "8080")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runHealthcheck() error = %v, want context.Canceled", err)
	}
}

func TestRunHealthcheckRejectsInvalidPort(t *testing.T) {
	t.Parallel()

	if err := runHealthcheck(context.Background(), "invalid"); err == nil {
		t.Fatal("runHealthcheck() error = nil, want an error")
	}
}

func serverPort(t *testing.T, server *httptest.Server) string {
	t.Helper()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}

	return port
}
