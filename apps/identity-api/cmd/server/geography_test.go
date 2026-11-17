package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/server"
)

func TestGeographyBuilderPreservesMissingDependenciesWithoutMemoryFallback(t *testing.T) {
	reader, limiter, err := buildGeographyService(nil, nil)
	if err != nil || reader != nil || limiter != nil {
		t.Fatalf("missing dependencies acquired substitute authority: %v", err)
	}
	s := server.New(config.Config{Environment: "development"}, slog.New(slog.DiscardHandler), server.Deps{Geography: reader, GeographyLimiter: limiter})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/geography/provinces?country=IR", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("development read failed open: %d", rec.Code)
	}
}

func TestGeographyBuilderUsesRuntimePoolAndExistingRedisLimiter(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	// Pool construction performs no dial or DDL. The builder may not initialize
	// an empty catalog, load importer credentials, or provision schema authority.
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/geography_builder?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	t.Setenv("GEOGRAPHY_IMPORT_DATABASE_URL", "invalid-cli-only-secret")
	reader, limiter, err := buildGeographyService(pool, client)
	if err != nil || reader == nil || limiter == nil {
		t.Fatalf("runtime reader wiring: %v", err)
	}
	if allowed, err := limiter.Allow(context.Background(), "rate:geography:builder-test", 1, time.Minute); err != nil || !allowed {
		t.Fatalf("Redis budget did not admit initial request: %v", err)
	}
	if allowed, err := limiter.Allow(context.Background(), "rate:geography:builder-test", 1, time.Minute); err != nil || allowed {
		t.Fatalf("Redis budget did not persist: %v", err)
	}
	reader, limiter, err = buildGeographyService(nil, client)
	if err != nil || reader != nil || limiter == nil {
		t.Fatalf("typed nil pool escaped into reader interface: %v", err)
	}
}

func TestGeographyConfigurationRejectsBeforeStartupDial(t *testing.T) {
	productionStartupEnvironment(t)
	t.Setenv(config.EnvGeographyQueryTimeout, "2s")
	if err := run(slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "geography") || strings.Contains(err.Error(), "ping redis") || strings.Contains(err.Error(), "ping database") {
		t.Fatalf("unbounded geography configuration did not reject before dialing: %v", err)
	}
}
