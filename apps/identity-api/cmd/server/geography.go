package main

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/server"
)

// Geography never loads importer credentials, migrates, or installs a memory
// catalog/limiter. Missing runtime dependencies leave reads fail-closed at 503.
func buildGeographyService(pool *pgxpool.Pool, redisClient *redis.Client) (server.GeographyReader, ratelimit.Limiter, error) {
	var reader server.GeographyReader
	if pool != nil {
		reader = geography.New(pool)
	}
	var limiter ratelimit.Limiter
	if redisClient != nil {
		shared, err := ratelimit.NewRedisLimiter(redisClient)
		if err != nil {
			return nil, nil, err
		}
		limiter = shared
	}
	return reader, limiter, nil
}
