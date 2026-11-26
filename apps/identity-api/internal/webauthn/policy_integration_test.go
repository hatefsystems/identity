//go:build integration

package webauthn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// Synthetic namespace admission exists only inside a unique child database.
func factorAccountPolicy(ctx context.Context, t *testing.T, pool *pgxpool.Pool) accountpolicy.Policy {
	t.Helper()
	n, err := username.New(username.Policy{
		ID: uuid.New(), Normalization: username.NormalizationV1, MinLetters: 1, MaxCodePoints: 40, ReservedNames: []string{},
		Folds: []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}},
	}, `\x{0633}+`, bytes.Repeat([]byte{0x43}, 32), "passkey-policy-fixture")
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
			t.Fatal("seed run-owned policy authority failed")
		}
	}
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x59}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	store, err := username.NewStore(pool, cipher, n)
	if err != nil {
		t.Fatal(err)
	}
	return accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: store}
}

func assignFactorUsername(ctx context.Context, t *testing.T, pool *pgxpool.Pool, policy accountpolicy.Policy, user db.User, index int) {
	t.Helper()
	value, err := policy.Usernames.Normalizer().Normalize(strings.Repeat("\u0633", index+1))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := policy.Usernames.Assign(ctx, tx, user.ID, user.AuthVersion, value); err != nil {
		t.Fatal("assign fixture username failed", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationPasskeyRemovalResultingPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), factorIntegrationTimeout)
	defer cancel()
	pool := openFactorIntegrationPool(ctx, t)
	policy := factorAccountPolicy(ctx, t, pool)
	q := db.New(pool)
	// Parseable verifier fixture, never a production credential or secret.
	const supportedHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for index, tc := range []struct {
		name                                                 string
		hash                                                 *string
		username, disabled, privileged, totpFlag, totpSecret bool
		want                                                 error
	}{
		{name: "passkey-only", want: ErrLastCredential},
		{name: "totp-not-primary", totpFlag: true, totpSecret: true, want: ErrLastCredential},
		{name: "empty-password", hash: new(""), username: true, want: ErrLastCredential},
		{name: "malformed-password", hash: new("not-a-verifier"), username: true, want: ErrLastCredential},
		{name: "password-without-username", hash: new(supportedHash), want: ErrLastCredential},
		{name: "disabled-password-route", hash: new(supportedHash), username: true, disabled: true, want: ErrLastCredential},
		{name: "usable-password", hash: new(supportedHash), username: true},
		{name: "privileged-without-factor", hash: new(supportedHash), username: true, privileged: true, want: ErrLastFactor},
		{name: "privileged-totp-flag-only", hash: new(supportedHash), username: true, privileged: true, totpFlag: true, want: ErrLastFactor},
		{name: "privileged-totp-secret-only", hash: new(supportedHash), username: true, privileged: true, totpSecret: true, want: ErrLastFactor},
		{name: "privileged-usable-totp", hash: new(supportedHash), username: true, privileged: true, totpFlag: true, totpSecret: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := createFactorIntegrationUser(ctx, t, pool, tc.name)
			key := createFactorIntegrationCredential(ctx, t, q, id)
			secret := []byte(nil)
			if tc.totpSecret {
				secret = []byte("fixture-encrypted-totp")
			}
			if _, err := pool.Exec(ctx, `UPDATE users SET password_hash=$2,is_mfa_enabled=$3,mfa_totp_secret_encrypted=$4 WHERE id=$1`, id, tc.hash, tc.totpFlag, secret); err != nil {
				t.Fatal(err)
			}
			user, err := q.GetUserByID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if tc.username {
				assignFactorUsername(ctx, t, pool, policy, user, index)
			}
			if tc.privileged {
				if _, err := q.CreateRole(ctx, db.CreateRoleParams{ID: "custom-passkey-policy", Description: "Fixture role"}); err != nil {
					t.Fatal(err)
				}
				if err := q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: id, RoleID: "custom-passkey-policy"}); err != nil {
					t.Fatal(err)
				}
			}
			svc := newFactorIntegrationWebAuthn(t, q, pool)
			configured := policy
			configured.PasswordLoginEnabled = !tc.disabled
			svc.SetAccountPolicy(configured)
			admitted := factorSessionContext(ctx, user)
			rows, err := svc.ListCredentialsWithPolicy(admitted, id)
			if err != nil || len(rows) != 1 || rows[0].CanRemove != (tc.want == nil) {
				t.Fatalf("advisory policy differs: %v, %v", rows, err)
			}
			err = svc.DeleteCredential(admitted, id, key)
			if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("deletion=%v want=%v", err, tc.want)
			}
			after, err := q.GetUserByID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			wantVersion := user.AuthVersion
			wantKeys := int64(1)
			if tc.want == nil {
				wantVersion++
				wantKeys = 0
			}
			count, err := q.CountWebauthnCredentialsByUser(ctx, id)
			if err != nil || after.AuthVersion != wantVersion || count != wantKeys {
				t.Fatalf("mutation/version not atomic: version=%d keys=%d err=%v", after.AuthVersion, count, err)
			}
		})
	}
}

func TestIntegrationPasskeyPolicyGuardPrecedesAccountLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), factorIntegrationTimeout)
	defer cancel()
	pool := openFactorIntegrationPool(ctx, t)
	policy := factorAccountPolicy(ctx, t, pool)
	q := db.New(pool)
	id := createFactorIntegrationUser(ctx, t, pool, "guard-order")
	key := createFactorIntegrationCredential(ctx, t, q, id)
	user, err := q.GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE username_active_policy SET admission_state='closed' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if err := pglock.LockAccount(ctx, holder, id); err != nil {
		t.Fatal(err)
	}
	svc := newFactorIntegrationWebAuthn(t, q, pool)
	svc.SetAccountPolicy(policy)
	bounded, stop := context.WithTimeout(factorSessionContext(ctx, user), time.Second)
	defer stop()
	for _, list := range []bool{false, true} {
		if list {
			_, err = svc.ListCredentialsWithPolicy(bounded, id)
		} else {
			err = svc.DeleteCredential(bounded, id, key)
		}
		if !errors.Is(err, username.ErrUnavailable) {
			t.Fatalf("list=%v blocked on account before authority refusal: %v", list, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE username_active_policy SET admission_state='open' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	wrong, err := username.New(policy.Usernames.Normalizer().Policy(), `\x{0633}+`, bytes.Repeat([]byte{0x44}, 32), "passkey-policy-fixture")
	if err != nil {
		t.Fatal(err)
	}
	wrongStore, err := username.NewStore(pool, factorTestEncryptor{}, wrong)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: wrongStore})
	for _, list := range []bool{false, true} {
		if list {
			_, err = svc.ListCredentialsWithPolicy(bounded, id)
		} else {
			err = svc.DeleteCredential(bounded, id, key)
		}
		if !errors.Is(err, username.ErrPolicyMismatch) {
			t.Fatalf("list=%v accepted substituted lookup key material or took account lock first: %v", list, err)
		}
	}
	after, err := q.GetUserByID(ctx, id)
	if err != nil || after.AuthVersion != user.AuthVersion {
		t.Fatal("authority refusal changed account version")
	}
}

func TestIntegrationPasskeyUnusableRetainedUsernameFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), factorIntegrationTimeout)
	defer cancel()
	pool := openFactorIntegrationPool(ctx, t)
	policy := factorAccountPolicy(ctx, t, pool)
	q := db.New(pool)
	id := createFactorIntegrationUser(ctx, t, pool, "invalid-retained-username")
	key := createFactorIntegrationCredential(ctx, t, q, id)
	const supportedHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := pool.Exec(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, id, supportedHash); err != nil {
		t.Fatal(err)
	}
	user, err := q.GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	a, err := policy.Guard(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.New(tx).GetUserByIDForUpdate(ctx, id); err != nil {
		t.Fatal(err)
	}
	// Seed corrupt ciphertext on a genuinely unclaimed fixture account, without
	// rewriting existing immutable ownership or bypassing the database guard.
	count, err := db.New(tx).AssignUsername(ctx, db.AssignUsernameParams{
		ID: id, AuthVersion: user.AuthVersion, UsernameKey: bytes.Repeat([]byte{0x41}, 32),
		UsernameDetailsEncrypted: bytes.Repeat([]byte{0x42}, 128),
		UsernamePolicyID:         uuid.NullUUID{UUID: a.PolicyID, Valid: true}, UsernamePolicyFingerprint: a.Fingerprint[:],
		UsernamePolicyEpoch: &a.Epoch, UsernameLookupKeyID: &a.KeyID,
	})
	if err != nil || count != 1 {
		t.Fatal("seed corrupt protected fixture failed", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	svc := newFactorIntegrationWebAuthn(t, q, pool)
	svc.SetAccountPolicy(policy)
	ctx = factorSessionContext(ctx, user)
	if _, err := svc.ListCredentialsWithPolicy(ctx, id); !errors.Is(err, username.ErrUnavailable) {
		t.Fatalf("unusable retained username fabricated advisory fallback: %v", err)
	}
	if err := svc.DeleteCredential(ctx, id, key); !errors.Is(err, username.ErrUnavailable) {
		t.Fatalf("unusable retained username accepted mutation or fabricated last-credential refusal: %v", err)
	}
	after, err := q.GetUserByID(ctx, id)
	remaining, countErr := q.CountWebauthnCredentialsByUser(ctx, id)
	if err != nil || countErr != nil || after.AuthVersion != user.AuthVersion || remaining != 1 {
		t.Fatal("unavailable protected username mutated account")
	}
}

func TestIntegrationPasskeyEnrollmentRevokesOnceAndCosmeticsDoNot(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "recovery"}[recovery], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), factorIntegrationTimeout)
			defer cancel()
			pool := openFactorIntegrationPool(ctx, t)
			q := db.New(pool)
			id := createFactorIntegrationUser(ctx, t, pool, "enrollment")
			if !recovery {
				createFactorIntegrationCredential(ctx, t, q, id)
			}
			user, err := q.GetUserByID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			ctx = factorSessionContext(ctx, user)
			if recovery {
				current, _ := session.FromContext(ctx)
				current.Kind = session.KindRecoveryEnrollment
				ctx = session.WithSession(ctx, current)
			}
			svc := newFactorIntegrationWebAuthn(t, q, pool)
			auth := newSoftAuthenticator(t)
			auth.rpID, auth.origin = "identity.test", "https://identity.test"
			flow := FlowRegistration
			name := "Original"
			if recovery {
				flow = FlowRecoveryRegistration
				name = ""
			}
			first, err := svc.beginRegistration(ctx, id, "factor-session", flow, recovery, name)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := svc.beginRegistration(ctx, id, "factor-session", flow, recovery, name)
			if err != nil {
				t.Fatal(err)
			}
			before, err := q.GetUserByID(ctx, id)
			if err != nil || before.AuthVersion != user.AuthVersion || len(before.WebauthnUserHandle) != 0 {
				t.Fatal("pending enrollment changed authority")
			}
			row, err := svc.finishRegistration(ctx, id, "factor-session", flow, recovery, auth.attestation(challengeOf(first.Response.Challenge)))
			if err != nil {
				t.Fatal(err)
			}
			after, err := q.GetUserByID(ctx, id)
			if err != nil || after.AuthVersion != user.AuthVersion+1 {
				t.Fatal("enrollment did not revoke exactly once")
			}
			if _, err := svc.finishRegistration(ctx, id, "factor-session", flow, recovery, newSoftAuthenticator(t).attestation(challengeOf(pending.Response.Challenge))); !errors.Is(err, ErrAccountNotActive) {
				t.Fatalf("old enrollment retained authority: %v", err)
			}
			fresh := factorSessionContext(ctx, after)
			current, _ := session.FromContext(fresh)
			if err := session.ValidateAuthority(fresh, session.NewDBAccountState(pool), current.UserID, current.AuthVersion, current.Kind, current.Evidence); err != nil {
				t.Fatal("fresh session was not valid before cosmetic rename", err)
			}
			if _, err := svc.RenameCredential(fresh, id, row.ID, "Renamed"); err != nil {
				t.Fatal(err)
			}
			if err := session.ValidateAuthority(fresh, session.NewDBAccountState(pool), current.UserID, current.AuthVersion, current.Kind, current.Evidence); err != nil {
				t.Fatal("cosmetic rename invalidated a previously valid session", err)
			}
			if _, err := svc.ListCredentialsWithPolicy(fresh, id); err != nil {
				t.Fatal(err)
			}
			if err := svc.commitSignCountChecked(fresh, &gowebauthn.Credential{ID: row.ID, Authenticator: gowebauthn.Authenticator{SignCount: 1}}, &after); err != nil {
				t.Fatal(err)
			}
			final, err := q.GetUserByID(ctx, id)
			count, countErr := q.CountWebauthnCredentialsByUser(ctx, id)
			wantCount := int64(1)
			if !recovery {
				wantCount = 2
			}
			if err != nil || countErr != nil || final.AuthVersion != after.AuthVersion || count != wantCount {
				t.Fatal("rename/use/list/stale enrollment changed authority")
			}
		})
	}
}

func TestIntegrationPasskeyEnrollmentDeletionRaceRevokesOneWinner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), factorIntegrationTimeout)
	defer cancel()
	pool := openFactorIntegrationPool(ctx, t)
	q := db.New(pool)
	id := createFactorIntegrationUser(ctx, t, pool, "enroll-delete")
	key := createFactorIntegrationCredential(ctx, t, q, id)
	createFactorIntegrationCredential(ctx, t, q, id)
	user, err := q.GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	ctx = factorSessionContext(ctx, user)
	svc := newFactorIntegrationWebAuthn(t, q, newFactorBeginBarrier(pool, 2))
	auth := newSoftAuthenticator(t)
	auth.rpID, auth.origin = "identity.test", "https://identity.test"
	options, err := svc.BeginRegistration(ctx, id, "factor-session", "Race")
	if err != nil {
		t.Fatal(err)
	}
	body := auth.attestation(challengeOf(options.Response.Challenge))
	results := make(chan error, 2)
	go func() { _, err := svc.FinishRegistration(ctx, id, "factor-session", body); results <- err }()
	go func() { results <- svc.DeleteCredential(ctx, id, key) }()
	winners, stale := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			winners++
		} else if errors.Is(err, ErrAccountNotActive) {
			stale++
		} else {
			t.Fatalf("unexpected race outcome: %v", err)
		}
	}
	after, err := q.GetUserByID(ctx, id)
	count, countErr := q.CountWebauthnCredentialsByUser(ctx, id)
	if err != nil || countErr != nil || winners != 1 || stale != 1 || after.AuthVersion != user.AuthVersion+1 || (count != 1 && count != 3) {
		t.Fatalf("race was not one atomic winner: winner=%d stale=%d version=%d keys=%d", winners, stale, after.AuthVersion, count)
	}
}
