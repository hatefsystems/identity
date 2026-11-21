//go:build integration

package smsotp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type smsIntegrationFixture struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	redis  *redis.Client
	store  *RedisOTPStore
	users  *PostgresUserStore
	phone  string
	cipher contactproof.Cipher
}

func smsIntegration(t *testing.T) smsIntegrationFixture {
	t.Helper()
	dsn, redisURL := os.Getenv("DATABASE_URL"), os.Getenv("REDIS_URL")
	if dsn == "" || redisURL == "" {
		if os.Getenv("REQUIRE_SMS_INTEGRATION") == "1" || os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" || os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL and REDIS_URL are required for mandatory SMS integration")
		}
		t.Skip("isolated PostgreSQL and Redis fixtures are not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid fixture database configuration")
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatal("configured fixture database unavailable")
	}
	name := "sms_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0"); err != nil {
		t.Fatal("cannot create run-owned SMS fixture database")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("cannot remove run-owned SMS fixture database")
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
	err = migrate.Up(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		t.Fatal("run-owned SMS fixture migration failed")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal("invalid fixture Redis configuration")
	}
	opts.MaxRetries = -1
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("configured fixture Redis unavailable")
	}
	store, err := NewRedisOTPStore(client)
	if err != nil {
		t.Fatal(err)
	}
	cipher := smsTestCipher(t)
	users, err := NewUserStore(pool, cipher)
	if err != nil {
		t.Fatal(err)
	}
	random := uuid.New()
	phone := fmt.Sprintf("+989%09d", binary.BigEndian.Uint32(random[:4])%1000000000)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = client.Del(cleanup, lockoutKey(phone)).Err()
	})
	return smsIntegrationFixture{ctx, pool, client, store, users, phone, cipher}
}
func (f smsIntegrationFixture) user(t *testing.T) db.User {
	t.Helper()
	u, err := db.New(f.pool).CreateUser(f.ctx, db.CreateUserParams{Email: new(uuid.NewString() + "@sms.invalid"), Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func (f smsIntegrationFixture) service(t *testing.T, users UserStore, enc Encryptor) (*Service, *fakeSender) {
	t.Helper()
	sender := &fakeSender{}
	s, err := New(Config{HashPepper: []byte(strings.Repeat("p", 32))}, users, enc, &fakeIndexer{}, &fakeLimiter{calls: map[string]int{}}, f.store, sender)
	if err != nil {
		t.Fatal(err)
	}
	return s, sender
}
func (f smsIntegrationFixture) challenge(t *testing.T, s *Service, u db.User) string {
	t.Helper()
	id, err := s.SendCode(f.ctx, u.ID, u.AuthVersion, "session-a", f.phone, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = f.store.Delete(cleanup, id)
	})
	return id
}

func TestSMSRedisPostgresVerificationAndRemovalOneWinnerIntegration(t *testing.T) {
	f := smsIntegration(t)
	u := f.user(t)
	s, sender := f.service(t, f.users, f.cipher)
	id := f.challenge(t, s, u)
	otherUsers, err := NewUserStore(f.pool, f.cipher)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := f.service(t, otherUsers, f.cipher)
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, svc := range []*Service{s, other} {
		go func(svc *Service) {
			<-start
			results <- svc.Verify(f.ctx, u.ID, u.AuthVersion, "session-a", id, sender.code)
		}(svc)
	}
	close(start)
	winners := 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrNoActiveCode) && !errors.Is(err, ErrStaleSession) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("verification did not have one Redis/SQL winner")
	}
	after, err := db.New(f.pool).GetUserByID(f.ctx, u.ID)
	if err != nil || after.AuthVersion != u.AuthVersion+1 {
		t.Fatal("verification not persisted")
	}
	phone, err := f.cipher.Decrypt(f.ctx, after.PhoneEncrypted)
	if err != nil || string(phone) != f.phone {
		t.Fatal("verification did not persist authenticated phone")
	}
	clear(phone)
	if proof, err := contactproof.Read(f.ctx, db.New(f.pool), f.cipher, u.ID, contactproof.Phone); err != nil || proof == nil {
		t.Fatal("verification did not persist exact evidence")
	}
	if err := db.New(f.pool).PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Email, EvidenceEncrypted: smsTestProof(t, f.cipher, u.ID, contactproof.Email, *u.Email)}); err != nil {
		t.Fatal(err)
	}
	disabled, err := NewDisabled(f.users)
	if err != nil {
		t.Fatal(err)
	}
	changes := make(chan bool, 2)
	errs := make(chan error, 2)
	start = make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			changed, err := disabled.RemovePhone(f.ctx, u.ID, after.AuthVersion)
			changes <- changed
			errs <- err
		}()
	}
	close(start)
	winners = 0
	for i := 0; i < 2; i++ {
		if <-changes {
			winners++
		}
		if err := <-errs; err != nil && !errors.Is(err, ErrStaleSession) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("removal did not report one conditional change/event")
	}
	removed, err := db.New(f.pool).GetUserByID(f.ctx, u.ID)
	if err != nil || removed.AuthVersion != u.AuthVersion+2 || removed.PhoneEncrypted != nil || removed.PhoneBlindIndex != nil {
		t.Fatal("removal did not revoke exactly once and clear phone")
	}
	if changed, err := disabled.RemovePhone(f.ctx, u.ID, removed.AuthVersion); changed || err != nil {
		t.Fatal("absent phone removal not a no-op")
	}
	final, err := db.New(f.pool).GetUserByID(f.ctx, u.ID)
	if err != nil || final.AuthVersion != removed.AuthVersion {
		t.Fatal("absent phone removal revoked authority")
	}
}

type smsBarrierEncryptor struct {
	admitted chan struct{}
	release  chan struct{}
	once     sync.Once
	cipher   contactproof.Cipher
}

func (e *smsBarrierEncryptor) Encrypt(ctx context.Context, p []byte) ([]byte, error) {
	// The phone and its proof have separate envelopes but one admission barrier.
	e.once.Do(func() { close(e.admitted) })
	select {
	case <-e.release:
		return e.cipher.Encrypt(ctx, p)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestSMSRevocationAfterProofAdmissionRejectsFinalMutationIntegration(t *testing.T) {
	f := smsIntegration(t)
	u := f.user(t)
	gate := &smsBarrierEncryptor{admitted: make(chan struct{}), release: make(chan struct{}), cipher: f.cipher}
	s, sender := f.service(t, f.users, gate)
	id := f.challenge(t, s, u)
	result := make(chan error, 1)
	go func() { result <- s.Verify(f.ctx, u.ID, u.AuthVersion, "session-a", id, sender.code) }()
	select {
	case <-gate.admitted:
	case <-f.ctx.Done():
		t.Fatal("verification admission barrier timed out")
	}
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("SMS fixture transaction rollback failed")
		}
	}()
	if err := pglock.LockAccount(f.ctx, tx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	if err := <-result; !errors.Is(err, ErrStaleSession) {
		t.Fatal("revoked admitted session mutated phone")
	}
	after, err := db.New(f.pool).GetUserByID(f.ctx, u.ID)
	if err != nil || after.PhoneEncrypted != nil {
		t.Fatal("stale phone write exists")
	}
	if _, err := f.store.Get(f.ctx, id); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("failed SQL mutation resurrected OTP")
	}
}

type smsUnknownCommitDatabase struct{ *pgxpool.Pool }

func (d smsUnknownCommitDatabase) BeginTx(ctx context.Context, opt pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.Pool.BeginTx(ctx, opt)
	return smsUnknownCommitTx{tx}, err
}

type smsUnknownCommitTx struct{ pgx.Tx }

func (tx smsUnknownCommitTx) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	return errPrivate
}
func TestSMSConsumedProofUnknownSQLCommitRequiresReadCurrentStateIntegration(t *testing.T) {
	f := smsIntegration(t)
	u := f.user(t)
	users, err := NewUserStore(smsUnknownCommitDatabase{f.pool}, f.cipher)
	if err != nil {
		t.Fatal(err)
	}
	s, sender := f.service(t, users, f.cipher)
	id := f.challenge(t, s, u)
	if err := s.Verify(f.ctx, u.ID, u.AuthVersion, "session-a", id, sender.code); err != ErrRestartRequired {
		t.Fatal("unknown commit presented as success/reusable proof")
	}
	after, err := db.New(f.pool).GetUserByID(f.ctx, u.ID)
	if err != nil || len(after.PhoneEncrypted) == 0 || after.AuthVersion != u.AuthVersion+1 {
		t.Fatal("unknown committed result cannot be read")
	}
	if _, err := f.store.Get(f.ctx, id); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("OTP restored after unknown commit")
	}
}

func TestSMSPhoneRemovalVersusVerifiedReplacementIntegration(t *testing.T) {
	for _, verifiedEmail := range []bool{false, true} {
		t.Run(fmt.Sprintf("verified_email_%t", verifiedEmail), func(t *testing.T) {
			f := smsIntegration(t)
			u := f.user(t)
			oldPhone := "+15550102020"
			q := db.New(f.pool)
			if _, err := q.SetUserPhone(f.ctx, db.SetUserPhoneParams{ID: u.ID, PhoneEncrypted: smsTestEncrypted(t, f.cipher, oldPhone), PhoneBlindIndex: new("idx_" + oldPhone)}); err != nil {
				t.Fatal(err)
			}
			if err := q.PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Phone, EvidenceEncrypted: smsTestProof(t, f.cipher, u.ID, contactproof.Phone, oldPhone)}); err != nil {
				t.Fatal(err)
			}
			if verifiedEmail {
				if err := q.PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Email, EvidenceEncrypted: smsTestProof(t, f.cipher, u.ID, contactproof.Email, *u.Email)}); err != nil {
					t.Fatal(err)
				}
			} else {
				if changed, err := f.users.RemovePhoneIfCurrent(f.ctx, u.ID, u.AuthVersion); changed || !errors.Is(err, accountpolicy.ErrLastVerifiedContact) {
					t.Fatal("populated email authorized last verified phone removal")
				}
			}
			replacement := smsTestEncrypted(t, f.cipher, f.phone)
			proof := smsTestProof(t, f.cipher, u.ID, contactproof.Phone, f.phone)
			other, err := NewUserStore(f.pool, f.cipher)
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			removed := make(chan bool, 1)
			removeErr := make(chan error, 1)
			replaceErr := make(chan error, 1)
			go func() {
				<-start
				changed, err := f.users.RemovePhoneIfCurrent(f.ctx, u.ID, u.AuthVersion)
				removed <- changed
				removeErr <- err
			}()
			go func() {
				<-start
				replaceErr <- other.SetPhoneIfCurrent(f.ctx, u.ID, u.AuthVersion, replacement, "idx_"+f.phone, proof)
			}()
			close(start)
			changed, removal, replacementErr := <-removed, <-removeErr, <-replaceErr
			if verifiedEmail {
				if changed {
					if removal != nil || !errors.Is(replacementErr, ErrStaleSession) {
						t.Fatal("removal winner did not fence admitted replacement")
					}
				} else if replacementErr != nil || !errors.Is(removal, ErrStaleSession) {
					t.Fatal("replacement winner did not fence admitted removal")
				}
			} else if changed || replacementErr != nil || !errors.Is(removal, accountpolicy.ErrLastVerifiedContact) && !errors.Is(removal, ErrStaleSession) {
				t.Fatal("last contact removal won against atomic verified replacement")
			}
			after, err := q.GetUserByID(f.ctx, u.ID)
			if err != nil || after.AuthVersion != u.AuthVersion+1 {
				t.Fatal("concurrent mutation did not revoke exactly once")
			}
			evidence, err := contactproof.Read(f.ctx, q, f.cipher, u.ID, contactproof.Phone)
			if err != nil {
				t.Fatal("concurrent mutation left unreadable evidence")
			}
			if changed {
				if after.PhoneEncrypted != nil || after.PhoneBlindIndex != nil || evidence != nil {
					t.Fatal("phone removal left contact or evidence")
				}
			} else if !bytes.Equal(after.PhoneEncrypted, replacement) || evidence == nil || evidence.Destination != f.phone {
				t.Fatal("replacement did not atomically preserve exact verified phone")
			}
		})
	}
}

func TestSMSUnknownPhoneProvenanceRepairRequiresNewBoundEvidenceIntegration(t *testing.T) {
	f := smsIntegration(t)
	u := f.user(t)
	q := db.New(f.pool)
	oldPhone := "+15550102020"
	if _, err := q.SetUserPhone(f.ctx, db.SetUserPhoneParams{ID: u.ID, PhoneEncrypted: smsTestEncrypted(t, f.cipher, oldPhone), PhoneBlindIndex: new("idx_" + oldPhone)}); err != nil {
		t.Fatal(err)
	}
	if err := q.PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Phone, EvidenceEncrypted: smsTestProof(t, f.cipher, uuid.New(), contactproof.Phone, oldPhone)}); err != nil {
		t.Fatal(err)
	}
	if changed, err := f.users.RemovePhoneIfCurrent(f.ctx, u.ID, u.AuthVersion); changed || !errors.Is(err, ErrUnavailable) {
		t.Fatal("unreadable provenance silently permitted removal")
	}
	s, sender := f.service(t, f.users, f.cipher)
	id := f.challenge(t, s, u)
	if err := s.Verify(f.ctx, u.ID, u.AuthVersion, "session-a", id, sender.code); err != nil {
		t.Fatal("fresh bound OTP could not atomically repair unknown provenance")
	}
	after, err := q.GetUserByID(f.ctx, u.ID)
	if err != nil || after.AuthVersion != u.AuthVersion+1 {
		t.Fatal("repair did not revoke exactly once")
	}
	proof, err := contactproof.Read(f.ctx, q, f.cipher, u.ID, contactproof.Phone)
	if err != nil || proof == nil || proof.Destination != f.phone || proof.AccountID != u.ID {
		t.Fatal("repair left unknown or mismatched provenance")
	}
	if changed, err := f.users.RemovePhoneIfCurrent(f.ctx, u.ID, after.AuthVersion); changed || !errors.Is(err, accountpolicy.ErrLastVerifiedContact) {
		t.Fatal("repaired verified phone was removed without verified current email")
	}
}

type smsRollbackDatabase struct {
	*pgxpool.Pool
	fail string
}

func (d smsRollbackDatabase) BeginTx(ctx context.Context, opt pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.Pool.BeginTx(ctx, opt)
	return smsRollbackTx{tx, d.fail}, err
}

type smsRollbackTx struct {
	pgx.Tx
	fail string
}

func (tx smsRollbackTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if tx.fail == "evidence" && strings.Contains(sql, "PutContactVerificationEvidence") || tx.fail == "revoke" && strings.Contains(sql, "RevokeUserCredentials") {
		return pgconn.CommandTag{}, errPrivate
	}
	return tx.Tx.Exec(ctx, sql, args...)
}
func (tx smsRollbackTx) Commit(ctx context.Context) error {
	if tx.fail == "commit" {
		return errPrivate
	}
	return tx.Tx.Commit(ctx)
}

func TestSMSPhoneMutationRollbackPreservesAuthorityAndEvidenceIntegration(t *testing.T) {
	for _, operation := range []string{"replace", "remove"} {
		for _, failure := range []string{"evidence", "revoke", "commit"} {
			if operation == "remove" && failure == "evidence" {
				continue
			}
			t.Run(operation+"_"+failure, func(t *testing.T) {
				f := smsIntegration(t)
				u := f.user(t)
				q := db.New(f.pool)
				oldPhone := "+15550102020"
				encrypted := smsTestEncrypted(t, f.cipher, oldPhone)
				if _, err := q.SetUserPhone(f.ctx, db.SetUserPhoneParams{ID: u.ID, PhoneEncrypted: encrypted, PhoneBlindIndex: new("idx_" + oldPhone)}); err != nil {
					t.Fatal(err)
				}
				// Unknown provenance must be repairable; failure must preserve it exactly.
				oldEvidence := smsTestProof(t, f.cipher, uuid.New(), contactproof.Phone, oldPhone)
				if operation == "remove" {
					oldEvidence = smsTestProof(t, f.cipher, u.ID, contactproof.Phone, oldPhone)
					if err := q.PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Email, EvidenceEncrypted: smsTestProof(t, f.cipher, u.ID, contactproof.Email, *u.Email)}); err != nil {
						t.Fatal(err)
					}
				}
				if err := q.PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Phone, EvidenceEncrypted: oldEvidence}); err != nil {
					t.Fatal(err)
				}
				users, err := NewUserStore(smsRollbackDatabase{f.pool, failure}, f.cipher)
				if err != nil {
					t.Fatal(err)
				}
				if operation == "replace" {
					s, sender := f.service(t, users, f.cipher)
					id := f.challenge(t, s, u)
					if err := s.Verify(f.ctx, u.ID, u.AuthVersion, "session-a", id, sender.code); !errors.Is(err, ErrRestartRequired) {
						t.Fatal("rolled-back replacement returned success")
					}
					if _, err := f.store.Get(f.ctx, id); !errors.Is(err, ErrNoActiveCode) {
						t.Fatal("rolled-back replacement restored consumed OTP")
					}
				} else if changed, err := users.RemovePhoneIfCurrent(f.ctx, u.ID, u.AuthVersion); changed || !errors.Is(err, ErrUnavailable) {
					t.Fatal("rolled-back removal returned committed change")
				}
				after, err := q.GetUserByID(f.ctx, u.ID)
				if err != nil || after.AuthVersion != u.AuthVersion || !bytes.Equal(after.PhoneEncrypted, encrypted) || after.PhoneBlindIndex == nil || *after.PhoneBlindIndex != "idx_"+oldPhone {
					t.Fatal("rollback changed authority or phone")
				}
				row, err := q.GetCurrentContactEvidence(f.ctx, db.GetCurrentContactEvidenceParams{UserID: u.ID, Channel: contactproof.Phone})
				if err != nil || !bytes.Equal(row.EvidenceEncrypted, oldEvidence) {
					t.Fatal("rollback changed original verification evidence")
				}
			})
		}
	}
}

func TestSMSRealRedisMalformedExpiryAndConsumeFailureIntegration(t *testing.T) {
	f := smsIntegration(t)
	rec := boundOTPRecord()
	rec.Phone = f.phone
	for _, value := range []string{"-1", "1junk", "999999999999999999999999"} {
		id, err := generateVerificationID()
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.Store(f.ctx, id, rec, time.Minute, 0); err != nil {
			t.Fatal(err)
		}
		if err := f.redis.HSet(f.ctx, otpKey(id), "attempts", value).Err(); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Consume(f.ctx, id, rec, rec.CodeHash, 3, 15*time.Minute); err != ErrNoActiveCode {
			t.Fatal("malformed counter not closed")
		}
		if err := f.store.Delete(f.ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	id, err := generateVerificationID()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Store(f.ctx, id, rec, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := f.store.Delete(cleanup, id); err != nil {
			t.Error("SMS fixture OTP cleanup failed")
		}
	})
	if err := f.redis.PExpire(f.ctx, otpKey(id), time.Millisecond).Err(); err != nil {
		t.Fatal(err)
	}
	// Redis expiry can be awaited by a blocking command, not an application retry.
	time.Sleep(5 * time.Millisecond)
	if err := f.store.Consume(f.ctx, id, rec, rec.CodeHash, 3, 15*time.Minute); err != ErrNoActiveCode {
		t.Fatal("expired challenge accepted")
	}
	if err := f.store.Store(f.ctx, id, rec, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.redis.HSet(f.ctx, lockoutKey(f.phone), "bad", "type").Err(); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Consume(f.ctx, id, rec, rec.CodeHash, 3, 15*time.Minute); err != ErrUnavailable {
		t.Fatal("failed lockout transition accepted proof")
	}
	if _, err := f.store.Get(f.ctx, id); err != nil {
		t.Fatal("lockout storage failure consumed proof")
	}
}
