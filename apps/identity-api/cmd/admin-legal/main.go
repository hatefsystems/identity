// Command admin-legal performs bounded legal metadata maintenance or an explicit
// synthetic signer/lookup probe. Run with intake disabled and operator credentials.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/receiptreconcile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalworkflow"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		slog.Error("legal maintenance options invalid")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := run(ctx, opts); err != nil {
		slog.Error("legal maintenance failed; verify operator configuration, keys and dependencies")
		os.Exit(1)
	}
}

type options struct {
	operation, policyFile string
	limit, proofLimit     int
	dryRun                bool
	supplied              map[string]bool
}

func parseOptions(args []string) (options, error) {
	opts := options{supplied: make(map[string]bool)}
	flags := flag.NewFlagSet("admin-legal", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.operation, "operation", "", "backfill, cleanup, lookup-probe, policy-install, workflow-cleanup, workflow-status, or ledger-receipts")
	flags.IntVar(&opts.limit, "limit", 500, "maximum records: workflow-cleanup 1..500; maintenance/status/receipts 1..1000")
	flags.StringVar(&opts.policyFile, "policy-file", "", "approved JSON artifact for policy-install only")
	flags.BoolVar(&opts.dryRun, "dry-run", false, "workflow-cleanup only: roll back eligible cleanup")
	flags.IntVar(&opts.proofLimit, "receipt-proof-limit", 1000, "ledger-receipts only: Class C proof nodes (1..10000)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return opts, errors.New("invalid options")
	}
	flags.Visit(func(f *flag.Flag) { opts.supplied[f.Name] = true })
	if opts.operation == "ledger-receipts" && !opts.supplied["limit"] {
		opts.limit = 100
	}
	return opts, validateOptions(opts)
}

func validateOptions(opts options) error {
	maximum := 1000
	if opts.operation == "workflow-cleanup" {
		maximum = 500
	}
	if opts.limit < 1 || opts.limit > maximum {
		return errors.New("invalid batch size")
	}
	switch opts.operation {
	case "backfill", "cleanup", "lookup-probe", "policy-install", "workflow-cleanup", "workflow-status", "ledger-receipts":
	default:
		return errors.New("invalid operation")
	}
	if ((opts.dryRun || opts.supplied["dry-run"]) && opts.operation != "workflow-cleanup") ||
		((opts.policyFile != "" || opts.supplied["policy-file"]) && opts.operation != "policy-install") ||
		(opts.supplied["receipt-proof-limit"] && opts.operation != "ledger-receipts") ||
		(opts.supplied["limit"] && (opts.operation == "lookup-probe" || opts.operation == "policy-install")) {
		return errors.New("operation does not support supplied options")
	}
	if opts.operation == "policy-install" && opts.policyFile == "" {
		return errors.New("policy-file required")
	}
	if opts.operation == "ledger-receipts" && (opts.proofLimit < 1 || opts.proofLimit > 10000) {
		return errors.New("invalid proof size")
	}
	return nil
}

func run(ctx context.Context, opts options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	dsn := os.Getenv("DATABASE_URL")
	if opts.operation == "ledger-receipts" {
		dsn = os.Getenv("LEDGER_RECEIPTS_DATABASE_URL")
		if dsn == "" {
			return errors.New("LEDGER_RECEIPTS_DATABASE_URL required")
		}
	}
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
	if opts.operation == "lookup-probe" {
		return lookupProbe(ctx, pool)
	}
	if opts.operation == "ledger-receipts" {
		if err := receiptreconcile.ProbePrivileges(ctx, pool); err != nil {
			return err
		}
		result, err := receiptreconcile.ReconcileSnapshot(ctx, pool, receiptreconcile.Options{Limit: opts.limit, ProofLimit: opts.proofLimit})
		if err == nil {
			slog.Info("ledger receipt reconciliation complete", "summary", result)
		}
		return err
	}
	environment := os.Getenv("APP_ENV")
	if environment == "" {
		environment = "development"
	}
	if opts.operation == "workflow-status" {
		result, err := legalworkflow.StatusSnapshot(ctx, pool, environment, opts.limit, time.Now())
		if err == nil {
			slog.Info("legal workflow status", "summary", result)
		}
		return err
	}
	if opts.operation == "policy-install" {
		if err := legalpolicy.ProbeInstaller(ctx, pool); err != nil {
			return err
		}
	}
	if opts.operation == "cleanup" {
		if err := legalpolicy.ProbeMetadataMaintenance(ctx, pool); err != nil {
			return err
		}
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
	if opts.operation == "policy-install" || opts.operation == "workflow-cleanup" {
		return runWorkflowOperation(ctx, pool, enc, environment, opts.operation, opts.policyFile, opts.limit, opts.dryRun)
	}
	var releasedRetention time.Duration
	if opts.operation == "cleanup" {
		policy, err := legalpolicy.LoadBaseline(ctx, pool, uuid.Nil, environment)
		if err != nil {
			return err
		}
		releasedRetention = policy.ReleasedHoldRetention()
	}
	holds, err := legalhold.New(db.New(pool), enc, legalhold.WithReleasedMetadataRetention(releasedRetention))
	if err != nil {
		return err
	}
	if opts.operation == "backfill" {
		n, err := holds.Backfill(ctx, pool, opts.limit)
		if err == nil {
			slog.Info("legal backfill batch committed", slog.Int("records", n)) //nolint:gosec // G706: a typed integer count cannot inject log text.
		}
		return err
	}
	n, err := holds.CleanupReleased(ctx, pool, opts.limit)
	if err == nil {
		slog.Info("legal cleanup batch committed", slog.Int64("records", n)) //nolint:gosec // G706: a typed integer count cannot inject log text.
	}
	return err
}

func runWorkflowOperation(ctx context.Context, pool *pgxpool.Pool, enc *envelope.Encryptor, environment, operation, policyFile string, limit int, dryRun bool) error {
	actor, err := uuid.Parse(os.Getenv("ADMIN_OPERATOR_ID"))
	if err != nil || actor == uuid.Nil {
		return errors.New("trusted operator attribution required")
	}
	identity := os.Getenv("ADMIN_OPERATOR_SPIFFE_ID")
	var artifact []byte
	var policy legalpolicy.Policy
	if operation == "policy-install" {
		if policyFile == "" {
			return errors.New("policy-file required")
		}
		// #nosec G304 -- The trusted operator selects this local CLI input; it is never an HTTP path.
		file, err := os.Open(policyFile)
		if err != nil {
			return errors.New("approval artifact unavailable")
		}
		defer func() { _ = file.Close() }()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > legalpolicy.MaxArtifactBytes {
			return errors.New("approval artifact must be a bounded regular file")
		}
		artifact, err = io.ReadAll(io.LimitReader(file, legalpolicy.MaxArtifactBytes+1))
		if err != nil {
			return errors.New("approval artifact unreadable")
		}
		policy, err = legalpolicy.Decode(bytes.NewReader(artifact))
		if err != nil {
			return err
		}
		if err = policy.Validate(environment); err != nil {
			return err
		}
	} else {
		policy, err = legalpolicy.LoadBaseline(ctx, pool, uuid.Nil, environment)
		if err != nil {
			return err
		}
	}
	auditCfg, err := config.LoadAudit(environment)
	if err != nil {
		return err
	}
	actions, err := adminaction.New(pool, enc, auditCfg.Subject, policy.ContextRetention())
	if err != nil {
		return err
	}
	if operation == "policy-install" {
		if err := policyInstall(ctx, actions, bytes.NewReader(artifact), environment, actor, identity); err != nil {
			return err
		}
		slog.Info("approved legal policy installed")
		return nil
	}
	workflow, err := legalworkflow.New(enc, legalworkflow.Config{Environment: environment})
	if err != nil {
		return err
	}
	result, err := workflow.Cleanup(ctx, pool, actions, legalworkflow.Actor{ID: actor}, identity, limit, dryRun)
	if err == nil {
		slog.Info("legal workflow cleanup complete", "considered", result.Considered, "deleted", result.Deleted, "held", result.Held, "would_delete", result.WouldDelete, "dry_run", result.DryRun)
	}
	return err
}

func lookupProbe(ctx context.Context, pool *pgxpool.Pool) error {
	pepper, err := config.LoadBlindIndexPepper()
	if err != nil {
		return err
	}
	pepperVersion, err := config.LoadBlindIndexPepperVersion()
	if err != nil {
		return err
	}
	indexer, err := blindindex.New(pepper, pepperVersion)
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
