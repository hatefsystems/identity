// Command admin-legal performs bounded legal metadata maintenance or an explicit
// synthetic signer/lookup probe. Run with intake disabled and operator credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
)

func main() {
	op := flag.String("operation", "", "backfill, cleanup, or lookup-probe")
	limit := flag.Int("limit", 500, "maximum records (1..1000)")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := run(ctx, *op, *limit); err != nil {
		slog.Error("legal maintenance failed; verify operator configuration, keys and dependencies")
		os.Exit(1)
	}
}

func run(ctx context.Context, operation string, limit int) error {
	if limit < 1 || limit > 1000 {
		return errors.New("invalid batch size")
	}
	if operation != "backfill" && operation != "cleanup" && operation != "lookup-probe" {
		return errors.New("invalid operation")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL required")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	if operation == "lookup-probe" {
		return lookupProbe(ctx, pool)
	}
	cfg, err := config.LoadAdmin()
	if err != nil {
		return err
	}
	crypto, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return err
	}
	provider, err := kms.NewMockProvider(crypto.MasterKEK, crypto.MasterKEKVersion)
	if err != nil {
		return err
	}
	enc, err := envelope.New(provider)
	if err != nil {
		return err
	}
	holds, err := legalhold.New(db.New(pool), enc, legalhold.WithReleasedMetadataRetention(cfg.LegalReleasedRetention))
	if err != nil {
		return err
	}
	if operation == "backfill" {
		n, err := holds.Backfill(ctx, pool, limit)
		if err == nil {
			slog.Info("legal backfill batch committed", "records", n)
		}
		return err
	}
	n, err := holds.CleanupReleased(ctx, pool, limit)
	if err == nil {
		slog.Info("legal cleanup batch committed", "records", n)
	}
	return err
}

func lookupProbe(ctx context.Context, pool *pgxpool.Pool) error {
	pepper, err := config.LoadBlindIndexPepper()
	if err != nil {
		return err
	}
	indexer, err := blindindex.New(pepper)
	if err != nil {
		return err
	}
	environment := os.Getenv("APP_ENV")
	if environment == "" {
		environment = "development"
	}
	cfg, err := config.LoadAudit(environment)
	if err != nil {
		return err
	}
	if !cfg.HasNATS() {
		return errors.New("NATS_URL required")
	}
	nc, js, err := natsjs.Connect(ctx, cfg.NATSURL, "admin-lookup-probe", slog.Default())
	if err != nil {
		return err
	}
	defer nc.Close()
	id := uuid.New()
	u, err := db.New(pool).CreateUser(ctx, db.CreateUserParams{Email: legalhold.LookupFixtureEmail(id), Status: "active"})
	if err != nil {
		return err
	}
	// The synthetic account has no credentials or roles. On failure it is left
	// intact so a delayed signer can still index it; never remove user evidence.
	slog.Info("synthetic lookup probe started", "fixture_id", id, "synthetic_account", u.ID)
	env, err := audit.NewEnvelope(audit.Event{EventType: audit.EventLoginSucceeded, ActionStatus: audit.StatusSuccess,
		ActorID: u.ID, ActorSPIFFEID: "spiffe://identity.invalid/operator/lookup-probe", ClientIP: "127.0.0.1",
		Security: &audit.SecurityContext{AccountRef: u.ID, ClientID: legalhold.LookupFixtureClient}}, id, time.Now())
	if err != nil {
		return err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	// Omit captured identity material so this exercises the deployed signer's
	// own configured pepper, rather than simply echoing the producer's digest.
	if _, err := js.Publish(ctx, cfg.Subject, data, jetstream.WithMsgID(id.String())); err != nil {
		return err
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := legalhold.VerifyLookupFixture(ctx, pool, indexer, id); err == nil {
			if _, err := pool.Exec(ctx, "DELETE FROM users WHERE id=$1 AND email=$2", u.ID, legalhold.LookupFixtureEmail(id)); err != nil {
				return err
			}
			if err := legalhold.VerifyLookupFixture(ctx, pool, indexer, id); err != nil {
				return err
			}
			fmt.Printf("ADMIN_LOOKUP_FIXTURE_ID=%s\n", id)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
