package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestRunRequiresDatabaseForPublisherAndCleanup(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	for _, cleanup := range []bool{false, true} {
		if err := run(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), cleanup); err == nil {
			t.Fatalf("cleanup=%v accepted missing database", cleanup)
		}
	}
}
