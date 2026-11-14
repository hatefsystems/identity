//go:build integration

package legalhold

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
	"github.com/hatefsystems/identity/apps/identity-api/internal/registration"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type registrationRestoreFixture struct {
	pending             registration.Attempt
	pendingCapability   []byte
	emailToken          []byte
	pendingCipherDigest [32]byte
	completed           db.RegistrationAttempt
	completedCapability []byte
	fingerprint         []byte
	user                db.User
	phone               string
	usernameDisplay     string
}

func (f *registrationRestoreFixture) clear() {
	clear(f.pendingCapability)
	clear(f.emailToken)
	clear(f.completedCapability)
	clear(f.fingerprint)
	clear(f.pending.Record.CapabilityHash)
	clear(f.pending.Record.EmailTokenHash)
	clear(f.pending.Record.DetailsEncrypted)
	clear(f.pending.Details.UserHandle)
	clear(f.completed.CapabilityHash)
	clear(f.completed.CompletionFingerprint)
	clear(f.user.PhoneEncrypted)
	clear(f.user.WebauthnUserHandle)
	clear(f.user.UsernameKey)
	clear(f.user.UsernameDetailsEncrypted)
	clear(f.user.UsernamePolicyFingerprint)
	*f = registrationRestoreFixture{}
}

// The terminal row is explicitly synthetic constrained restore evidence, not a
// claim of received email/SMS, real passkey enrollment or production account birth.
func seedRegistrationRestoreFixture(ctx context.Context, t *testing.T, pool *pgxpool.Pool, cipher Encryptor, indexer BlindIndexer) *registrationRestoreFixture {
	t.Helper()
	f := &registrationRestoreFixture{phone: "+989123456782"}
	t.Cleanup(f.clear)
	usernames := registrationRestoreUsernames(t, pool, cipher)
	seedRegistrationRestoreUsernamePolicy(ctx, t, pool, usernames.Normalizer())
	store, err := registration.NewStore(pool, cipher, 10, usernames)
	if err != nil {
		t.Fatal("construct registration restore store failed")
	}
	pendingEmail, err := emailaddress.Canonicalize("\u0628\u0627\u0632\u0633\u0627\u0632\u06cc+" + uuid.NewString()[:8] + "@Example.invalid")
	if err != nil {
		t.Fatal("canonicalize Unicode restore contact failed")
	}
	pendingUsername, err := usernames.Normalizer().Normalize("\u0628\u0627\u0632\u0633\u0627\u0632\u06cc.\u0643\u06cc\u0648\u0627\u0646")
	if err != nil {
		t.Fatal("normalize chosen pending restore username failed")
	}
	f.pending, f.pendingCapability, err = store.Create(ctx, pendingEmail, "+989123456781", registrationRestoreJKT(t), pendingUsername)
	if err != nil {
		t.Fatal("seed envelope-bound pending signup fixture failed")
	}
	f.emailToken, err = registration.NewCapability()
	if err != nil || bytes.Equal(f.emailToken, f.pendingCapability) {
		t.Fatal("create independent email proof token failed")
	}
	tokenHash, err := registration.HashCapability(f.emailToken)
	if err != nil {
		t.Fatal("hash restore email token failed")
	}
	tx := registrationRestoreTransaction(ctx, t, pool)
	func() {
		defer registrationRestoreRollback(t, tx)
		pending, err := store.Lock(ctx, tx, f.pending.Record.ID, f.pendingCapability, f.pending.Record.Jkt)
		if err != nil {
			t.Fatal("lock pending signup restore fixture failed")
		}
		pending.Record.EmailTokenHash = tokenHash
		pending.Record.EmailTokenIssuedAt = timestamptz(time.Now().UTC().Truncate(time.Microsecond))
		pending.Record.EmailTokenExpiresAt = timestamptz(pending.Record.EmailTokenIssuedAt.Time.Add(registration.EmailLifetime))
		pending.Record.ChallengeRevision = 1
		f.pending, err = store.Save(ctx, tx, pending)
		if err != nil || tx.Commit(ctx) != nil {
			t.Fatal("save constrained pending signup proof clock failed")
		}
	}()
	f.pendingCipherDigest = sha256.Sum256(f.pending.Record.DetailsEncrypted)

	f.completedCapability, err = registration.NewCapability()
	if err != nil || bytes.Equal(f.completedCapability, f.pendingCapability) {
		t.Fatal("create independent completion capability failed")
	}
	completedHash, err := registration.HashCapability(f.completedCapability)
	if err != nil {
		t.Fatal("hash completion capability failed")
	}
	handle := make([]byte, 8)
	defer clear(handle)
	if _, err := rand.Read(handle); err != nil {
		t.Fatal("create random completed signup handle failed")
	}
	completedEmail, err := emailaddress.Canonicalize("\u062a\u06a9\u0645\u06cc\u0644+" + uuid.NewString()[:8] + "@Example.invalid")
	if err != nil {
		t.Fatal("canonicalize completed Unicode contact failed")
	}
	phonePlain := []byte(f.phone)
	phoneCipher, err := cipher.Encrypt(ctx, phonePlain)
	clear(phonePlain)
	if err != nil {
		t.Fatal("encrypt synthetic completed phone failed")
	}
	defer clear(phoneCipher)
	completedID, userID := uuid.New(), uuid.New()
	completedUsername, err := usernames.Normalizer().Normalize("\u0639\u0644\u064a.\u0645\u0624\u0645\u0646\u06cc")
	if err != nil {
		t.Fatal("normalize synthetic completed restore username failed")
	}
	f.usernameDisplay = completedUsername.Display()
	fingerprint := sha256.Sum256([]byte("registration-restore-completion:v1:" + completedID.String() + ":" + userID.String()))
	f.fingerprint = bytes.Clone(fingerprint[:])
	created := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Microsecond)
	terminal := created.Add(time.Minute)
	completedJKT := registrationRestoreJKT(t)
	if completedJKT == f.pending.Record.Jkt {
		t.Fatal("restore browser thumbprints must be independent")
	}
	tx = registrationRestoreTransaction(ctx, t, pool)
	func() {
		defer registrationRestoreRollback(t, tx)
		if err := usernames.Guard(ctx, tx); err != nil {
			t.Fatal("guard synthetic completed username authority failed")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.users(id,email,phone_encrypted,phone_blind_index,webauthn_user_handle,lifecycle_revision,created_at,updated_at)
VALUES($1,$2,$3,$4,$5,1,$6,$6)`, userID, completedEmail, phoneCipher, indexer.Compute(f.phone), handle, created); err != nil {
			t.Fatal("seed synthetic local signup user fixture failed")
		}
		if err := usernames.Assign(ctx, tx, userID, 0, completedUsername); err != nil {
			t.Fatal("assign account-bound synthetic restore username failed")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.registration_attempts(id,capability_hash,jkt,state,created_at,expires_at,
terminal_at,receipt_expires_at,email_verified_at,phone_verified_at,challenge_revision,row_revision,completion_fingerprint,result_user_id)
VALUES($1,$2,$3,'completed',$4,$5,$6,$7,$8,$9,3,4,$10,$11)`, completedID, completedHash, completedJKT, created,
			created.Add(registration.PendingLifetime), terminal, terminal.Add(registration.ReceiptLifetime), created.Add(10*time.Second),
			created.Add(20*time.Second), f.fingerprint, userID); err != nil {
			t.Fatal("seed constrained synthetic terminal signup receipt failed")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal("commit synthetic completed signup fixture failed")
		}
	}()
	f.completed, err = db.New(pool).GetRegistrationAttempt(ctx, completedID)
	if err != nil {
		t.Fatal("read terminal restore fixture failed")
	}
	f.user, err = db.New(pool).GetUserByID(ctx, userID)
	if err != nil || f.user.Email != completedEmail || !bytes.Equal(f.user.WebauthnUserHandle, handle) {
		t.Fatal("read bound local signup user fixture failed")
	}
	return f
}

func registrationRestoreUsernames(t *testing.T, pool *pgxpool.Pool, cipher Encryptor) *username.Store {
	t.Helper()
	policy := username.Policy{
		ID: uuid.MustParse("1bc0aee3-4d3f-48f7-a6d5-4960b412c5ac"), Normalization: username.NormalizationV1,
		Folds:         []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}},
		ReservedNames: []string{},
	}
	const syntax = `[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+(?:\.[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+)*`
	normalizer, err := username.New(policy, syntax, bytes.Repeat([]byte{0x64}, 32), "registration-restore-only")
	if err != nil {
		t.Fatal("construct approved restore username policy failed")
	}
	store, err := username.NewStore(pool, cipher, normalizer)
	if err != nil {
		t.Fatal("construct real restore username store failed")
	}
	return store
}

func seedRegistrationRestoreUsernamePolicy(ctx context.Context, t *testing.T, pool *pgxpool.Pool, normalizer *username.Normalizer) {
	t.Helper()
	// The caller has migrated its run-owned source child. Restore checks never
	// reseed this authority: its exact registry and active row must survive copying.
	a := normalizer.Authority()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, []any{a.PolicyID, a.Fingerprint[:], normalizer.CanonicalArtifact()}},
		{`INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)`, []any{a.KeyID, a.KeyVerifier[:]}},
		{`UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton`, []any{a.PolicyID, a.Fingerprint[:], a.KeyID, a.KeyVerifier[:]}},
	} {
		if tag, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("seed owned restore username authority failed")
		}
	}
}

// RFC 7638 public-key thumbprints are generated without retaining the signing
// secret. The drill checks persisted binding, not received DPoP proofs.
func registrationRestoreJKT(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("create restore browser public key failed")
	}
	public := struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"P-256", "EC", base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
	wire, err := json.Marshal(public)
	if err != nil {
		t.Fatal("encode canonical restore public key failed")
	}
	digest := sha256.Sum256(wire)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func checkRegistrationRestoredState(ctx context.Context, t *testing.T, pool *pgxpool.Pool, cipher Encryptor, f *registrationRestoreFixture) {
	t.Helper()
	var tables, appliedRegistration, appliedUsername, attemptCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind='r' AND c.relname<>'identity_schema_version'`).Scan(&tables); err != nil || tables != 38 {
		t.Fatal("restore lost the exact 38-table application inventory")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity_schema_version WHERE version_id=2 AND is_applied`).Scan(&appliedRegistration); err != nil || appliedRegistration != 1 {
		t.Fatal("restored registration migration metadata is missing")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity_schema_version WHERE version_id=3 AND is_applied`).Scan(&appliedUsername); err != nil || appliedUsername != 1 {
		t.Fatal("restored username migration metadata is missing")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM registration_attempts`).Scan(&attemptCount); err != nil || attemptCount != 2 {
		t.Fatal("restore lost pending or completed signup fixture")
	}
	usernames := registrationRestoreUsernames(t, pool, cipher)
	if err := usernames.CheckReady(ctx); err != nil {
		t.Fatal("restored immutable username policy or active key authority differs")
	}
	store, err := registration.NewStore(pool, cipher, 10, usernames)
	if err != nil {
		t.Fatal("construct restored signup authority store failed")
	}
	pending, err := store.Get(ctx, f.pending.Record.ID, f.pendingCapability, f.pending.Record.Jkt)
	if err != nil {
		t.Fatal("restored pending signup capability or envelope failed")
	}
	compareRegistrationRestoreValue(t, f.pending.Record, pending.Record)
	compareRegistrationRestoreValue(t, f.pending.Details, pending.Details)
	chosen, err := usernames.Normalizer().Normalize(pending.Details.UsernameDisplay)
	if err != nil || chosen.Display() != pending.Details.UsernameDisplay || chosen.SecurityName() != pending.Details.UsernameSecurity ||
		chosen.Authority() != pending.Details.UsernameAuthority || pending.Details.UsernameEpoch != 1 {
		t.Fatal("restored pending username spelling, security name or frozen authority differs")
	}
	capabilityHash, _ := registration.HashCapability(f.pendingCapability)
	tokenHash, _ := registration.HashCapability(f.emailToken)
	if !bytes.Equal(pending.Record.CapabilityHash, capabilityHash) || !bytes.Equal(pending.Record.EmailTokenHash, tokenHash) ||
		!registration.ValidJKT(pending.Record.Jkt) || !emailaddress.ValidCanonicalMailbox(pending.Details.Email) || len(pending.Details.UserHandle) != 8 ||
		sha256.Sum256(pending.Record.DetailsEncrypted) != f.pendingCipherDigest || !bytes.Equal(pending.Record.DetailsEncrypted, f.pending.Record.DetailsEncrypted) ||
		!pending.Record.ExpiresAt.Time.Equal(pending.Record.CreatedAt.Time.Add(registration.PendingLifetime)) ||
		!pending.Record.EmailTokenExpiresAt.Time.Equal(pending.Record.EmailTokenIssuedAt.Time.Add(registration.EmailLifetime)) ||
		pending.Record.EmailVerifiedAt.Valid || pending.Record.PhoneVerifiedAt.Valid || pending.Record.ResultUserID.Valid || pending.Record.TerminalAt.Valid ||
		pending.Record.ReceiptExpiresAt.Valid || pending.Record.ChallengeRevision != 1 || pending.Record.RowRevision != 1 {
		t.Fatal("restored pending ciphertext, bindings, proof clock or revision differ")
	}
	completed, err := store.Get(ctx, f.completed.ID, f.completedCapability, f.completed.Jkt)
	if err != nil {
		t.Fatal("restored terminal signup receipt authority failed")
	}
	compareRegistrationRestoreValue(t, f.completed, completed.Record)
	if completed.Record.State != "completed" || completed.Record.DetailsEncrypted != nil || completed.Record.EmailTokenHash != nil ||
		completed.Record.EmailTokenIssuedAt.Valid || completed.Record.EmailTokenExpiresAt.Valid || completed.Record.SmsVerificationRef.Valid ||
		completed.Record.PasskeyCreatedAt.Valid || completed.Record.PasskeyExpiresAt.Valid || len(completed.Record.CompletionFingerprint) != 32 ||
		!completed.Record.ResultUserID.Valid || completed.Record.ResultUserID.UUID != f.user.ID || completed.Record.ChallengeRevision != 3 ||
		completed.Record.RowRevision != 4 || !completed.Record.ReceiptExpiresAt.Time.Equal(completed.Record.TerminalAt.Time.Add(registration.ReceiptLifetime)) ||
		completed.Details.Email != "" || completed.Details.Phone != "" || len(completed.Details.UserHandle) != 0 || len(completed.Details.Ceremony) != 0 ||
		completed.Details.UsernameDisplay != "" || completed.Details.UsernameSecurity != "" || completed.Details.UsernameAuthority != (username.Authority{}) || completed.Details.UsernameEpoch != 0 {
		t.Fatal("restored completion metadata, deadline or transient NULLs differ")
	}
	user, replay, err := registration.CheckReplay(completed, f.fingerprint)
	if err != nil || !replay || user != f.user.ID {
		t.Fatal("restored identical completion fingerprint failed replay")
	}
	changed := bytes.Clone(f.fingerprint)
	defer clear(changed)
	changed[0] ^= 1
	if _, _, err := registration.CheckReplay(completed, changed); !errors.Is(err, registration.ErrConflict) {
		t.Fatal("restored receipt accepted changed completion fingerprint")
	}
	boundUser, err := db.New(pool).GetUserByID(ctx, f.user.ID)
	if err != nil {
		t.Fatal("restored completion FK target failed")
	}
	compareRegistrationRestoreValue(t, f.user, boundUser)
	name, err := usernames.Get(ctx, boundUser.ID, boundUser.AuthVersion)
	if err != nil || name == nil || name.Display != f.usernameDisplay {
		t.Fatal("restored account-bound username ciphertext or exact display differs")
	}
	phone, err := cipher.Decrypt(ctx, boundUser.PhoneEncrypted)
	defer clear(phone)
	if err != nil || string(phone) != f.phone || !emailaddress.ValidCanonicalMailbox(boundUser.Email) ||
		len(boundUser.WebauthnUserHandle) != 8 || !bytes.Equal(boundUser.WebauthnUserHandle, f.user.WebauthnUserHandle) || boundUser.LifecycleRevision != 1 {
		t.Fatal("restored canonical signup contacts, encrypted phone, handle or user revision differ")
	}
	var cascade bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.registration_attempts'::regclass
AND contype='f' AND confrelid='public.users'::regclass AND confdeltype='c' AND convalidated)`).Scan(&cascade); err != nil || !cascade {
		t.Fatal("restored completion user cascade foreign key differs")
	}
	if _, err := store.Get(ctx, f.pending.Record.ID, f.emailToken, f.pending.Record.Jkt); !errors.Is(err, registration.ErrUnauthorized) {
		t.Fatal("email token authorized signup capability after restore")
	}
	if _, err := store.Get(ctx, f.pending.Record.ID, f.pendingCapability, f.completed.Jkt); !errors.Is(err, registration.ErrUnauthorized) {
		t.Fatal("foreign browser thumbprint authorized pending signup after restore")
	}
	if _, err := store.Get(ctx, f.completed.ID, f.pendingCapability, f.completed.Jkt); !errors.Is(err, registration.ErrUnauthorized) {
		t.Fatal("pending capability authorized terminal receipt after restore")
	}
	tx := registrationRestoreTransaction(ctx, t, pool)
	func() {
		defer registrationRestoreRollback(t, tx)
		proof, err := store.LockEmailProof(ctx, tx, f.pending.Record.ID, f.emailToken, f.pending.Record.Jkt)
		if err != nil || proof.Record.EmailVerifiedAt.Valid {
			t.Fatal("restored independent email token binding failed or defaulted to verified")
		}
		if _, err := store.LockEmailProof(ctx, tx, f.pending.Record.ID, f.pendingCapability, f.pending.Record.Jkt); !errors.Is(err, registration.ErrUnauthorized) {
			t.Fatal("signup capability authorized email proof after restore")
		}
	}()
	wrongProvider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x63}, 32), 1)
	if err != nil {
		t.Fatal("construct wrong-key restore probe failed")
	}
	wrongCipher, err := envelope.New(wrongProvider)
	if err != nil {
		t.Fatal("construct wrong envelope restore probe failed")
	}
	wrongStore, err := registration.NewStore(pool, wrongCipher, 10, registrationRestoreUsernames(t, pool, wrongCipher))
	if err != nil {
		t.Fatal("construct wrong-key signup store failed")
	}
	if _, err := wrongStore.Get(ctx, f.pending.Record.ID, f.pendingCapability, f.pending.Record.Jkt); !errors.Is(err, registration.ErrInvalid) {
		t.Fatal("wrong key opened restored pending signup details")
	}
	for _, binding := range []string{"attempt", "JKT", "purpose"} {
		foreign := f.pending.Details
		switch binding {
		case "attempt":
			foreign.AttemptID = uuid.New()
		case "JKT":
			foreign.JKT = f.completed.Jkt
		case "purpose":
			foreign.Purpose = "recovery"
		}
		plain, err := json.Marshal(foreign)
		if err != nil {
			t.Fatal("encode transplanted restore details failed")
		}
		blob, err := cipher.Encrypt(ctx, plain)
		clear(plain)
		if err != nil {
			t.Fatal("encrypt transplanted restore details failed")
		}
		tx := registrationRestoreTransaction(ctx, t, pool)
		func() {
			defer registrationRestoreRollback(t, tx)
			if _, err := tx.Exec(ctx, `UPDATE registration_attempts SET details_encrypted=$2 WHERE id=$1`, f.pending.Record.ID, blob); err != nil {
				t.Fatal("prepare rolled-back signup binding probe failed")
			}
			if _, err := store.Lock(ctx, tx, f.pending.Record.ID, f.pendingCapability, f.pending.Record.Jkt); !errors.Is(err, registration.ErrInvalid) {
				t.Fatal("transplanted signup envelope binding accepted after restore")
			}
		}()
		clear(blob)
	}
	// All negative probes rollback; the caller also recomputes the full database
	// and sequence inventory digest after these checks, not just before them.
	row, err := db.New(pool).GetRegistrationAttempt(ctx, f.pending.Record.ID)
	if err != nil {
		t.Fatal("read pending signup after rollback probes failed")
	}
	compareRegistrationRestoreValue(t, f.pending.Record, row)
}

func compareRegistrationRestoreValue(t *testing.T, expected, actual any) {
	t.Helper()
	left, leftErr := json.Marshal(expected)
	defer clear(left)
	right, rightErr := json.Marshal(actual)
	defer clear(right)
	if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) || sha256.Sum256(left) != sha256.Sum256(right) {
		t.Fatal("restored exact signup record or digest differs")
	}
}

func registrationRestoreTransaction(ctx context.Context, t *testing.T, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal("open bounded signup restore transaction failed")
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='250ms'; SET LOCAL statement_timeout='2s'`); err != nil {
		registrationRestoreRollback(t, tx)
		t.Fatal("set bounded signup restore transaction limits failed")
	}
	return tx
}

func registrationRestoreRollback(t *testing.T, tx pgx.Tx) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Error("signup restore probe rollback failed")
	}
}
