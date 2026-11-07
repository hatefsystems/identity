// Command admin-roles provisions or revokes one role using separately controlled
// operator DB credentials. No HTTP endpoint invokes this command.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

func main() {
	user := flag.String("user-id", "", "target account UUID")
	role := flag.String("role", "", "super_admin, moderator, support, or dpo")
	revoke := flag.Bool("revoke", false, "revoke the role instead of granting it")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := run(ctx, *user, *role, *revoke); err != nil {
		slog.Error("role operation failed; verify operator credentials, account/MFA eligibility, configuration and audit storage")
		os.Exit(1)
	}
	slog.Info("role operation and audit intent committed")
}

func run(ctx context.Context, user, role string, revoke bool) error {
	environment, err := config.LoadEnvironment()
	if err != nil {
		return err
	}
	target, err := uuid.Parse(user)
	if err != nil {
		return err
	}
	operator, err := uuid.Parse(os.Getenv("ADMIN_OPERATOR_ID"))
	if err != nil {
		return err
	}
	identity := os.Getenv("ADMIN_OPERATOR_SPIFFE_ID")
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" || identity == "" {
		return errors.New("operator database and identity required")
	}
	cfg, err := config.LoadAdmin()
	if err != nil {
		return err
	}
	subject, err := config.LoadAuditSubject()
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
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	baseline, err := loadOperatorBaseline(ctx, pool, cfg, environment)
	if err != nil {
		return err
	}
	actions, err := adminaction.New(pool, enc, subject, baseline.ContextRetention())
	if err != nil {
		return err
	}
	return rbac.ProvisionRole(ctx, actions, operator, identity, target, role, revoke, environment)
}

func loadOperatorBaseline(ctx context.Context, q db.DBTX, cfg config.AdminConfig, environment string) (legalpolicy.Policy, error) {
	var configuredID uuid.UUID
	var err error
	if cfg.GovernancePolicyID != "" {
		configuredID, err = uuid.Parse(cfg.GovernancePolicyID)
		if err != nil || configuredID == uuid.Nil {
			return legalpolicy.Policy{}, legalpolicy.ErrInvalidPolicy
		}
	}
	baseline, err := legalpolicy.LoadBaseline(ctx, q, configuredID, environment)
	if err != nil {
		return legalpolicy.Policy{}, err
	}
	if (os.Getenv(config.EnvAdminContextRetention) != "" && cfg.ContextRetention != baseline.ContextRetention()) ||
		(os.Getenv(config.EnvAdminLegalReleasedRetention) != "" && cfg.LegalReleasedRetention != baseline.ReleasedHoldRetention()) {
		return legalpolicy.Policy{}, legalpolicy.ErrMismatch
	}
	return baseline, nil
}
