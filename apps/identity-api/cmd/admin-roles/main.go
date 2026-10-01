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
	environment := os.Getenv("APP_ENV")
	if environment == "" {
		environment = "development"
	}
	auditCfg, err := config.LoadAudit(environment)
	if err != nil {
		return err
	}
	actions, err := adminaction.New(pool, enc, auditCfg.Subject, cfg.ContextRetention)
	if err != nil {
		return err
	}
	return rbac.ProvisionRole(ctx, actions, operator, identity, target, role, revoke)
}
