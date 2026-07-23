package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/satishgampala/devsecops-supply-chain-template/internal/httpapi"
)

const (
	defaultPort       = "8080"
	healthcheckPeriod = 2 * time.Second
	shutdownPeriod    = 10 * time.Second
)

var errInvalidPort = errors.New("port must be an integer from 1 through 65535")

func main() {
	if err := run(os.Args[1:], os.Getenv("PORT")); err != nil {
		slog.Error("service failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, rawPort string) error {
	port, err := parsePort(rawPort)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch {
	case len(args) == 0:
		return runServer(ctx, port)
	case len(args) == 1 && args[0] == "healthcheck":
		return runHealthcheck(ctx, port)
	default:
		return errors.New("unsupported command")
	}
}

func parsePort(raw string) (string, error) {
	if raw == "" {
		return defaultPort, nil
	}

	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return "", errInvalidPort
	}

	return strconv.Itoa(port), nil
}

func newServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func runServer(ctx context.Context, port string) error {
	server := newServer(net.JoinHostPort("", port), httpapi.New())
	serveErrors := make(chan error, 1)

	go func() {
		serveErrors <- server.ListenAndServe()
	}()

	slog.Info("http server starting", "address", server.Addr)
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("http server failed: %w", err)
	case <-ctx.Done():
		slog.Info("http server shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownPeriod)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("http server shutdown failed: %w", err)
	}

	if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server failed during shutdown: %w", err)
	}

	return nil
}

func runHealthcheck(ctx context.Context, port string) error {
	validatedPort, err := parsePort(port)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://"+net.JoinHostPort("127.0.0.1", validatedPort)+"/healthz",
		nil,
	)
	if err != nil {
		return errors.New("healthcheck request could not be created")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   healthcheckPeriod,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("healthcheck request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return errors.New("healthcheck endpoint is unhealthy")
	}

	return nil
}
