// Command server is the entry point for the Hatef Identity Platform IdP
// backend (identity-api). It loads configuration from the environment, starts
// the HTTP server, and shuts down gracefully on SIGINT/SIGTERM.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("server terminated with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// run wires up configuration and the server, then blocks until a termination
// signal is received and a graceful shutdown completes. It is separated from
// main so it can return errors instead of calling os.Exit directly.
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	srv := server.New(cfg, logger)

	// Listen for OS termination signals to trigger graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the server in a goroutine so we can wait on the signal context.
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()

	select {
	case err := <-serverErr:
		// Server stopped on its own (e.g. failed to bind the port).
		return err
	case <-ctx.Done():
		// Signal received; begin graceful shutdown.
		stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
