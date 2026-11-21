//go:build integration

package passwordmanager

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

const fixturePHC = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type passwordDatabaseFixture struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	policy accountpolicy.Policy
}

func newPasswordDatabaseFixture(t *testing.T) passwordDatabaseFixture {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" {
			t.Fatal("mandatory password integration requires PostgreSQL")
		}
		t.Skip("isolated PostgreSQL not configured")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid provisioning configuration")
	}
	t.Cleanup(admin.Close)
	name := "password_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted+" TEMPLATE template0"); err != nil {
		t.Fatal("cannot create run-owned password database")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("run-owned password database teardown failed")
		}
		var exists bool
		if err := admin.QueryRow(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil || exists {
			t.Error("run-owned password database teardown unconfirmed")
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	var actual string
	if err := sqlDB.QueryRowContext(ctx, `SELECT current_database()`).Scan(&actual); err != nil || actual != name {
		_ = sqlDB.Close()
		t.Fatal("migration database is not run-owned")
	}
	err = migrate.Up(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		t.Fatal("run-owned password migration failed", err)
	}
	n, err := username.New(username.Policy{
		ID: uuid.New(), Normalization: username.NormalizationV1, ReservedNames: []string{},
		Folds: []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}},
	}, `\x{0633}+`, bytes.Repeat([]byte{0x49}, 32), "password-policy-fixture")
	if err != nil {
		t.Fatal(err)
	}
	a := n.Authority()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, []any{a.PolicyID, a.Fingerprint[:], n.CanonicalArtifact()}},
		{`INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)`, []any{a.KeyID, a.KeyVerifier[:]}},
		{`UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton`, []any{a.PolicyID, a.Fingerprint[:], a.KeyID, a.KeyVerifier[:]}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal("seed run-owned username authority failed", err)
		}
	}
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x61}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	names, err := username.NewStore(pool, cipher, n)
	if err != nil {
		t.Fatal(err)
	}
	return passwordDatabaseFixture{ctx, pool, accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: names}}
}

func (f passwordDatabaseFixture) account(t *testing.T, name int) (db.User, session.Session, *Service) {
	t.Helper()
	q := db.New(f.pool)
	user, err := q.CreateUser(f.ctx, db.CreateUserParams{Email: new(uuid.NewString() + "@password.invalid"), PasswordHash: new(fixturePHC), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateWebauthnCredential(f.ctx, db.CreateWebauthnCredentialParams{ID: []byte(uuid.NewString()), UserID: user.ID, PublicKey: []byte("fixture-presence-only"), AttestationType: "none", UserPresent: true, UserVerified: true}); err != nil {
		t.Fatal(err)
	}
	if name > 0 {
		value, err := f.policy.Usernames.Normalizer().Normalize(strings.Repeat("\u0633", name))
		if err != nil {
			t.Fatal(err)
		}
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollback(f.ctx, tx)
		if err := f.policy.Usernames.Assign(f.ctx, tx, user.ID, user.AuthVersion, value); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	sess := passwordSession()
	sess.UserID, sess.AuthVersion = user.ID.String(), user.AuthVersion
	svc, err := New(Deps{DB: f.pool, Queries: q, Sessions: &passwordSessions{current: sess}, Limiter: &passwordLimiter{allowed: true}, Policy: f.policy})
	if err != nil {
		t.Fatal(err)
	}
	return user, sess, svc
}

func TestPasswordDerivationOutsideLocksAndEarnedAuthorityIntegration(t *testing.T) {
	f := newPasswordDatabaseFixture(t)
	for index, mode := range []string{"auth version", "verifier", "policy epoch", "session", "grant expiry"} {
		t.Run(mode, func(t *testing.T) {
			user, sess, svc := f.account(t, index+1)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			svc.verify = func(context.Context, string, string) (bool, error) { return false, nil }
			svc.hash = func(ctx context.Context, _ string) (string, error) {
				close(entered)
				select {
				case <-release:
					return fixturePHC, nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			}
			grant := passwordGrant(sess)
			done := make(chan error, 1)
			go func() {
				_, err := svc.Mutate(f.ctx, sess, "change", "private replacement secret", Authorization{Grant: grant}, "203.0.113.8")
				done <- err
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("did not reach derivation: %v", err)
			case <-f.ctx.Done():
				t.Fatal("derivation barrier timed out")
			}
			bounded, stop := context.WithTimeout(f.ctx, 2*time.Second)
			defer stop()
			tx, err := f.pool.Begin(bounded)
			if err != nil {
				t.Fatal(err)
			}
			defer rollback(f.ctx, tx)
			// Both locks must be independently available while Argon2 is paused.
			if _, err := tx.Exec(bounded, `SELECT singleton FROM username_active_policy WHERE singleton FOR UPDATE`); err != nil {
				t.Fatal("hashing retained username-policy lock", err)
			}
			if err := pglock.LockAccount(bounded, tx, user.ID); err != nil {
				t.Fatal("hashing retained account lock", err)
			}
			query := ""
			switch mode {
			case "auth version":
				query = `UPDATE users SET auth_version=auth_version+1 WHERE id=$1`
			case "verifier":
				query = `UPDATE users SET password_hash='changed fixture verifier' WHERE id=$1`
			case "policy epoch":
				query = `UPDATE username_active_policy SET epoch=epoch+1 WHERE singleton`
			case "session":
				svc.deps.Sessions.(*passwordSessions).err = session.ErrSessionNotFound
			case "grant expiry":
				grant.ExpiresAt = time.Now().Add(-time.Second)
			}
			if query != "" {
				args := []any{user.ID}
				if mode == "policy epoch" {
					args = nil
				}
				if _, err := tx.Exec(bounded, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(bounded); err != nil {
				t.Fatal(err)
			}
			unblock()
			select {
			case err := <-done:
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatalf("earned authority drift accepted: %v", err)
				}
			case <-f.ctx.Done():
				t.Fatal("mutation did not finish")
			}
			after, err := db.New(f.pool).GetUserByID(f.ctx, user.ID)
			wantVersion, wantHash := user.AuthVersion, fixturePHC
			if mode == "auth version" {
				wantVersion++
			}
			if mode == "verifier" {
				wantHash = "changed fixture verifier"
			}
			if err != nil || after.AuthVersion != wantVersion || after.PasswordHash == nil || *after.PasswordHash != wantHash {
				t.Fatal("rejected mutation changed verifier or version", err)
			}
		})
	}
}

func TestPasswordConcurrentChangesHaveOneEarnedVersionWinnerIntegration(t *testing.T) {
	f := newPasswordDatabaseFixture(t)
	user, sess, svc := f.account(t, 1)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	svc.verify = func(context.Context, string, string) (bool, error) { return false, nil }
	svc.hash = func(ctx context.Context, _ string) (string, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return fixturePHC, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	// Each caller has a separate limiter/session reader, so race evidence concerns
	// shared PostgreSQL authority rather than mutable test bookkeeping.
	replica, err := New(Deps{DB: f.pool, Queries: db.New(f.pool), Sessions: &passwordSessions{current: sess}, Limiter: &passwordLimiter{allowed: true}, Policy: f.policy})
	if err != nil {
		t.Fatal(err)
	}
	replica.hash, replica.verify = svc.hash, svc.verify
	type outcome struct {
		changed bool
		err     error
	}
	done := make(chan outcome, 2)
	for _, service := range []*Service{svc, replica} {
		go func() {
			changed, err := service.Mutate(f.ctx, sess, "change", "private replacement secret", Authorization{Grant: passwordGrant(sess)}, "203.0.113.8")
			done <- outcome{changed, err}
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case result := <-done:
			t.Fatalf("race failed before both derivations: %v", result.err)
		case <-f.ctx.Done():
			t.Fatal("race admission timed out")
		}
	}
	unblock()
	winners, rejected := 0, 0
	for range 2 {
		select {
		case result := <-done:
			if result.changed && result.err == nil {
				winners++
			} else if !result.changed && errors.Is(result.err, ErrUnauthorized) {
				rejected++
			} else {
				t.Fatalf("unexpected race outcome: %+v", result)
			}
		case <-f.ctx.Done():
			t.Fatal("race completion timed out")
		}
	}
	after, err := db.New(f.pool).GetUserByID(f.ctx, user.ID)
	if err != nil || winners != 1 || rejected != 1 || after.AuthVersion != user.AuthVersion+1 {
		t.Fatalf("changes did not fence earned version: wins=%d rejected=%d version=%d error=%v", winners, rejected, after.AuthVersion, err)
	}
}

func TestPasswordRemovalRacesFinalPasskeyRemovalIntegration(t *testing.T) {
	f := newPasswordDatabaseFixture(t)
	user, sess, svc := f.account(t, 1)
	q := db.New(f.pool)
	credentials, err := q.ListWebauthnCredentialsByUser(f.ctx, user.ID)
	if err != nil || len(credentials) != 1 {
		t.Fatal("final passkey fixture unavailable", err)
	}
	wa, err := webauthn.New(webauthn.Config{RPID: "identity.example", RPOrigins: []string{"https://identity.example"}, RPDisplayName: "Identity", ChallengeTTL: time.Minute, MockChallengeKey: bytes.Repeat([]byte{0x39}, 32)}, q, q, webauthn.NewMemoryChallengeStore(), webauthn.WithTransacter(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	wa.SetAccountPolicy(f.policy)
	start, done := make(chan struct{}), make(chan error, 2)
	go func() {
		<-start
		_, err := svc.Mutate(f.ctx, sess, "remove", "", Authorization{Grant: passwordGrant(sess)}, "203.0.113.8")
		done <- err
	}()
	go func() {
		<-start
		done <- wa.DeleteCredential(session.WithSession(f.ctx, sess), user.ID, credentials[0].ID)
	}()
	close(start)
	winners := 0
	for range 2 {
		select {
		case err := <-done:
			if err == nil {
				winners++
			}
		case <-f.ctx.Done():
			t.Fatal("final-factor race timed out")
		}
	}
	after, err := q.GetUserByID(f.ctx, user.ID)
	count, countErr := q.CountWebauthnCredentialsByUser(f.ctx, user.ID)
	if err != nil || countErr != nil || winners != 1 || after.AuthVersion != user.AuthVersion+1 || count == 0 && after.PasswordHash == nil {
		t.Fatalf("race lost final primary credential: wins=%d version=%d keys=%d error=%v/%v", winners, after.AuthVersion, count, err, countErr)
	}
}

func TestPasswordResultingPolicyAndNoopPreservationIntegration(t *testing.T) {
	f := newPasswordDatabaseFixture(t)
	for index, mode := range []string{"identical", "absent removal", "missing username", "unusable proposed verifier", "last credential", "privileged last factor", "disabled add", "disabled removal"} {
		t.Run(mode, func(t *testing.T) {
			name := index + 1
			if mode == "missing username" {
				name = 0
			}
			user, sess, svc := f.account(t, name)
			operation, secret := "change", "private replacement secret"
			want := error(nil)
			svc.verify = func(context.Context, string, string) (bool, error) { return true, nil }
			svc.hash = func(context.Context, string) (string, error) {
				t.Fatal("authorized no-op unexpectedly rehashed")
				return "", nil
			}
			switch mode {
			case "absent removal":
				operation, secret = "remove", ""
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET password_hash=NULL WHERE id=$1`, user.ID); err != nil {
					t.Fatal(err)
				}
			case "missing username":
				want = ErrConflict
			case "unusable proposed verifier":
				svc.verify = func(context.Context, string, string) (bool, error) { return false, nil }
				svc.hash = func(context.Context, string) (string, error) { return "not-a-supported-verifier", nil }
				want = ErrConflict
			case "last credential":
				operation, secret, want = "remove", "", accountpolicy.ErrLastCredential
				if _, err := f.pool.Exec(f.ctx, `DELETE FROM webauthn_credentials WHERE user_id=$1`, user.ID); err != nil {
					t.Fatal(err)
				}
			case "privileged last factor":
				want = accountpolicy.ErrLastFactor
				if _, err := f.pool.Exec(f.ctx, `DELETE FROM webauthn_credentials WHERE user_id=$1`, user.ID); err != nil {
					t.Fatal(err)
				}
				role := "password-policy-fixture"
				if _, err := db.New(f.pool).CreateRole(f.ctx, db.CreateRoleParams{ID: role, Description: "Fixture role"}); err != nil {
					t.Fatal(err)
				}
				if err := db.New(f.pool).AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: user.ID, RoleID: role}); err != nil {
					t.Fatal(err)
				}
			case "disabled add":
				operation, want = "add", ErrConflict
				svc.deps.Policy.PasswordLoginEnabled = false
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET password_hash=NULL WHERE id=$1`, user.ID); err != nil {
					t.Fatal(err)
				}
			case "disabled removal":
				operation, secret = "remove", ""
				svc.deps.Policy.PasswordLoginEnabled = false
			}
			before, err := db.New(f.pool).GetUserByID(f.ctx, user.ID)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := svc.Mutate(f.ctx, sess, operation, secret, Authorization{Grant: passwordGrant(sess)}, "203.0.113.8")
			if !errors.Is(err, want) || changed != (mode == "disabled removal") {
				t.Fatalf("resulting policy changed=%v error=%v expected=%v", changed, err, want)
			}
			after, err := db.New(f.pool).GetUserByID(f.ctx, user.ID)
			if err != nil {
				t.Fatal(err)
			}
			if changed {
				if after.AuthVersion != before.AuthVersion+1 || after.PasswordHash != nil {
					t.Fatal("disabled removal did not commit exactly once")
				}
			} else if after.AuthVersion != before.AuthVersion || !sameVerifier(after.PasswordHash, before.PasswordHash) || after.UpdatedAt != before.UpdatedAt {
				t.Fatal("rejected operation/no-op rewrote verifier, version or timestamp")
			}
		})
	}
}
