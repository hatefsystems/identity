package registration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

const fixtureUsername = "\u0639\u0644\u06cc.\u0645\u0624\u0645\u0646\u06cc"

func usernameNormalizer(t *testing.T) *username.Normalizer {
	t.Helper()
	policy, err := username.DecodePolicy([]byte(`{"id":"4793a0e0-60b0-4571-a9b1-3879123819bb","normalization":"nfc-four-fold-v1","folds":[{"from":"\u064a","to":"\u06cc"},{"from":"\u0643","to":"\u06a9"},{"from":"\u0624","to":"\u0648"},{"from":"\u0626","to":"\u06cc"}],"reserved_names":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	n, err := username.New(policy, `[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+(?:\.[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+)*`, bytes.Repeat([]byte{0x62}, 32), "registration-fixture-v1")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func usernameValue(t *testing.T, n *username.Normalizer, input string) username.Value {
	t.Helper()
	v, err := n.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type signupUsernames struct {
	mu                  sync.Mutex
	normalizer          *username.Normalizer
	guardErr            error
	availableErr        error
	unavailable         bool
	guards              int
	availability        int
	assignments         int
	assignedID          uuid.UUID
	assignedAuthVersion int64
	assignedValue       username.Value
	epoch               int64
	onGuard             func(pgx.Tx)
}

func (n *signupUsernames) Normalizer() *username.Normalizer { return n.normalizer }
func (n *signupUsernames) Guard(_ context.Context, tx pgx.Tx) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.guards++
	if n.onGuard != nil {
		n.onGuard(tx)
	}
	if tx, ok := tx.(*testTx); ok {
		tx.ops = append(tx.ops, "username_guard")
		if err := tx.failures["username_guard"]; err != nil {
			return err
		}
	}
	return n.guardErr
}
func (n *signupUsernames) GuardAuthority(ctx context.Context, tx pgx.Tx) (username.GuardAuthority, error) {
	if err := n.Guard(ctx, tx); err != nil {
		return username.GuardAuthority{}, err
	}
	return username.GuardAuthority{Authority: n.normalizer.Authority(), Epoch: n.epoch}, nil
}
func (n *signupUsernames) Available(context.Context, username.Value) (bool, error) {
	n.availability++
	return !n.unavailable, n.availableErr
}
func (n *signupUsernames) Assign(_ context.Context, tx pgx.Tx, id uuid.UUID, authVersion int64, value username.Value) error {
	n.assignments++
	n.assignedID, n.assignedAuthVersion, n.assignedValue = id, authVersion, value
	if tx, ok := tx.(*testTx); ok {
		tx.ops = append(tx.ops, "username_assign")
		return tx.failures["username_assign"]
	}
	return errors.New("registration test assignment requires caller test transaction")
}

func testUsernames(t *testing.T) *signupUsernames {
	t.Helper()
	return &signupUsernames{normalizer: usernameNormalizer(t), epoch: 1}
}

func testCipher(t *testing.T) Encryptor {
	t.Helper()
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{7}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func pendingFixture(t *testing.T) (*Store, Attempt, []byte) {
	t.Helper()
	capability := bytes.Repeat([]byte{9}, 32)
	hash, _ := HashCapability(capability)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	namespace := testUsernames(t)
	s := &Store{cipher: testCipher(t), usernames: namespace, now: func() time.Time { return now.Add(time.Minute) }}
	chosen := usernameValue(t, namespace.normalizer, fixtureUsername)
	d := Details{AttemptID: uuid.New(), JKT: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)),
		Purpose: Purpose, Email: "person@example.com", Phone: "+989123456789", UserHandle: bytes.Repeat([]byte{5}, 8),
		UsernameDisplay: chosen.Display(), UsernameSecurity: chosen.SecurityName(), UsernameAuthority: chosen.Authority(), UsernameEpoch: 1}
	blob, err := s.seal(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	return s, Attempt{Record: db.RegistrationAttempt{ID: d.AttemptID, Jkt: d.JKT, CapabilityHash: hash, DetailsEncrypted: blob,
		State: "pending", CreatedAt: timestamp(now), ExpiresAt: timestamp(now.Add(PendingLifetime))}, Details: d}, capability
}

type registrationRow struct {
	record db.RegistrationAttempt
	err    error
}

func (r registrationRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	record := reflect.ValueOf(r.record)
	for i := range dest {
		reflect.ValueOf(dest[i]).Elem().Set(record.Field(i))
	}
	return nil
}

type booleanRow struct {
	value bool
	err   error
}

func (r booleanRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*bool) = r.value
	return nil
}

type testDatabase struct {
	Database
	txs      []*testTx
	begins   int
	beginErr error
	read     db.RegistrationAttempt
	readErr  error
}

func (d *testDatabase) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	d.begins++
	if d.beginErr != nil {
		return nil, d.beginErr
	}
	tx := d.txs[d.begins-1]
	tx.readCommitted = opts.IsoLevel == pgx.ReadCommitted
	return tx, nil
}
func (d *testDatabase) QueryRow(context.Context, string, ...any) pgx.Row {
	return registrationRow{d.read, d.readErr}
}

type testTx struct {
	pgx.Tx
	record                         db.RegistrationAttempt
	candidates                     []db.ListExpiredRegistrationAttemptsRow
	ops                            []string
	failures                       map[string]error
	affected                       int64
	held                           bool
	commits, rollbacks             int
	rollbackBounded, readCommitted bool
	onQuery                        func(string, []any) pgx.Row
}

func queryName(sql string) string {
	if strings.Contains(sql, "SET LOCAL") {
		return "timeouts"
	}
	if strings.Contains(sql, "pg_advisory_xact_lock($1::bigint)") {
		return "subject_lock"
	}
	if strings.HasPrefix(sql, "-- name: ") {
		return strings.Fields(sql)[2]
	}
	return "unknown"
}
func (tx *testTx) Exec(ctx context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	name := queryName(sql)
	tx.ops = append(tx.ops, name)
	if ctx.Err() != nil {
		return pgconn.CommandTag{}, ctx.Err()
	}
	if err := tx.failures[name]; err != nil {
		return pgconn.CommandTag{}, err
	}
	return pgconn.NewCommandTag("DELETE " + strconv.FormatInt(tx.affected, 10)), nil
}
func (tx *testTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	name := queryName(sql)
	tx.ops = append(tx.ops, name)
	if ctx.Err() != nil {
		return registrationRow{err: ctx.Err()}
	}
	if tx.onQuery != nil {
		return tx.onQuery(name, args)
	}
	if name == "RegistrationAttemptHeld" {
		return booleanRow{tx.held, tx.failures[name]}
	}
	return registrationRow{tx.record, tx.failures[name]}
}
func (tx *testTx) Commit(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := tx.failures["commit"]; err != nil {
		return err
	}
	tx.commits++
	return nil
}
func (tx *testTx) Rollback(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	tx.rollbackBounded = ok && time.Until(deadline) <= 2*time.Second && ctx.Err() == nil
	tx.rollbacks++
	return nil
}

func TestCapabilityAndExactJKT(t *testing.T) {
	a, err := NewCapability()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(a)
	b, err := NewCapability()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b)
	if len(a) != 32 || len(b) != 32 || bytes.Equal(a, b) {
		t.Fatal("capabilities are not independent 256-bit secrets")
	}
	if _, err := HashCapability(a[:31]); err != ErrUnauthorized {
		t.Fatal("short capability accepted")
	}
	s, attempt, capability := pendingFixture(t)
	for _, jkt := range []string{"", attempt.Details.JKT + "=", " " + attempt.Details.JKT, attempt.Details.JKT[:42] + "h"} {
		if ValidJKT(jkt) {
			t.Fatalf("noncanonical thumbprint accepted: %q", jkt)
		}
	}
	for _, change := range []string{"secret", "jkt", "id only"} {
		key, jkt := bytes.Clone(capability), attempt.Details.JKT
		switch change {
		case "secret":
			key[0]++
		case "jkt":
			jkt = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
		case "id only":
			key = nil
		}
		if _, err := s.authorize(context.Background(), attempt.Record, key, jkt); err != ErrUnauthorized {
			t.Fatalf("%s authorized: %v", change, err)
		}
	}
}

func TestEnvelopeBindingCorruptionAndFrozenIdentity(t *testing.T) {
	for _, change := range []string{"attempt", "jkt", "purpose", "email", "phone", "handle", "corruption", "ceremony", "unknown", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			s, a, _ := pendingFixture(t)
			d := a.Details
			switch change {
			case "attempt":
				d.AttemptID = uuid.New()
			case "jkt":
				d.JKT = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
			case "purpose":
				d.Purpose = "recovery"
			case "email":
				d.Email = "Person@example.com"
			case "phone":
				d.Phone = "09123456789"
			case "handle":
				d.UserHandle = d.UserHandle[:7]
			case "ceremony":
				d.Ceremony = json.RawMessage(`{"challenge":"server-state"}`)
				d.CeremonyRevision = 1
			}
			plain, _ := json.Marshal(d)
			if change == "unknown" {
				plain = append(plain[:len(plain)-1], []byte(`,"extra":true}`)...)
			}
			if change == "duplicate" {
				plain = append(plain[:len(plain)-1], []byte(`,"purpose":"registration"}`)...)
			}
			blob, err := s.cipher.Encrypt(context.Background(), plain)
			if err != nil {
				t.Fatal(err)
			}
			if change == "corruption" {
				blob[len(blob)-1] ^= 1
			}
			a.Record.DetailsEncrypted = blob
			if _, err := s.open(context.Background(), a.Record); err != ErrInvalid {
				t.Fatalf("%s accepted: %v", change, err)
			}
		})
	}
	s, a, _ := pendingFixture(t)
	tx := &testTx{record: a.Record}
	for _, change := range []string{"email", "phone", "handle", "expiry", "created", "capability", "revision", "username display", "username security", "username policy", "username fingerprint", "username key ID", "username key verifier", "username epoch"} {
		b := a
		b.Details.UserHandle = bytes.Clone(a.Details.UserHandle)
		b.Record.CapabilityHash = bytes.Clone(a.Record.CapabilityHash)
		switch change {
		case "email":
			b.Details.Email = "other@example.com"
		case "phone":
			b.Details.Phone = "+989123456780"
		case "handle":
			b.Details.UserHandle[0]++
		case "expiry":
			b.Record.ExpiresAt.Time = b.Record.ExpiresAt.Time.Add(time.Minute)
		case "created":
			b.Record.CreatedAt.Time = b.Record.CreatedAt.Time.Add(time.Minute)
		case "capability":
			b.Record.CapabilityHash[0]++
		case "revision":
			b.Record.ChallengeRevision = 2
		case "username display":
			b.Details.UsernameDisplay = "\u0639\u0644\u06cc.\u0645\u0648\u0645\u0646\u06cc"
		case "username security":
			b.Details.UsernameSecurity += "\u06cc"
		case "username policy":
			b.Details.UsernameAuthority.PolicyID = uuid.New()
		case "username fingerprint":
			b.Details.UsernameAuthority.Fingerprint[0] ^= 1
		case "username key ID":
			b.Details.UsernameAuthority.KeyID += "-changed"
		case "username key verifier":
			b.Details.UsernameAuthority.KeyVerifier[0] ^= 1
		case "username epoch":
			b.Details.UsernameEpoch++
		}
		if _, err := s.Save(context.Background(), tx, b); err != ErrInvalid {
			t.Fatalf("frozen %s changed: %v", change, err)
		}
	}
}

func TestTypedStateAndDeadlinesFailClosed(t *testing.T) {
	cases := map[string]func(*db.RegistrationAttempt){
		"state":                  func(r *db.RegistrationAttempt) { r.State = "verified" },
		"expiry extension":       func(r *db.RegistrationAttempt) { r.ExpiresAt.Time = r.ExpiresAt.Time.Add(time.Second) },
		"infinity":               func(r *db.RegistrationAttempt) { r.ExpiresAt.InfinityModifier = pgtype.Infinity },
		"short hash":             func(r *db.RegistrationAttempt) { r.CapabilityHash = r.CapabilityHash[:31] },
		"pending user":           func(r *db.RegistrationAttempt) { r.ResultUserID = uuid.NullUUID{UUID: uuid.New(), Valid: true} },
		"missing ciphertext":     func(r *db.RegistrationAttempt) { r.DetailsEncrypted = nil },
		"email without issuance": func(r *db.RegistrationAttempt) { r.EmailVerifiedAt = timestamp(r.CreatedAt.Time.Add(time.Minute)) },
		"email extension": func(r *db.RegistrationAttempt) {
			r.EmailTokenIssuedAt = r.CreatedAt
			r.EmailTokenExpiresAt = timestamp(r.CreatedAt.Time.Add(11 * time.Minute))
		},
		"phone send not proof": func(r *db.RegistrationAttempt) { r.PhoneVerifiedAt = r.CreatedAt },
		"negative revision":    func(r *db.RegistrationAttempt) { r.ChallengeRevision = -1 },
		"ceremony without proof": func(r *db.RegistrationAttempt) {
			r.PasskeyCreatedAt = r.CreatedAt
			r.PasskeyExpiresAt = timestamp(r.CreatedAt.Time.Add(time.Minute))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			_, a, _ := pendingFixture(t)
			change(&a.Record)
			if validateRecord(a.Record) != ErrInvalid {
				t.Fatal("invalid persisted state accepted")
			}
		})
	}
	s, a, secret := pendingFixture(t)
	s.now = func() time.Time { return a.Record.ExpiresAt.Time }
	if _, err := s.authorize(context.Background(), a.Record, secret, a.Details.JKT); err != ErrExpired {
		t.Fatal("deadline boundary accepted")
	}
}

func TestCompletedReceiptFingerprintAndTransientErasure(t *testing.T) {
	s, a, secret := pendingFixture(t)
	r := a.Record
	r.State = "completed"
	r.DetailsEncrypted = nil
	r.TerminalAt = timestamp(s.now())
	r.ReceiptExpiresAt = timestamp(s.now().Add(ReceiptLifetime))
	r.EmailVerifiedAt = timestamp(r.CreatedAt.Time.Add(10 * time.Second))
	r.PhoneVerifiedAt = timestamp(r.CreatedAt.Time.Add(20 * time.Second))
	r.ResultUserID = uuid.NullUUID{UUID: uuid.New(), Valid: true}
	r.CompletionFingerprint = bytes.Repeat([]byte{3}, 32)
	receipt, err := s.authorize(context.Background(), r, secret, r.Jkt)
	if err != nil || receipt.Details.Email != "" {
		t.Fatal("authorized receipt failed or exposed transient details")
	}
	user, replayed, err := CheckReplay(receipt, r.CompletionFingerprint)
	if err != nil || !replayed || user != r.ResultUserID.UUID {
		t.Fatal("identical completion was not replayed")
	}
	if _, _, err := CheckReplay(receipt, bytes.Repeat([]byte{4}, 32)); err != ErrConflict {
		t.Fatal("different completion fingerprint replayed")
	}
	r.EmailTokenHash = bytes.Repeat([]byte{1}, 32)
	if validateRecord(r) != ErrInvalid {
		t.Fatal("terminal token retained")
	}
	r.EmailTokenHash = nil
	s.now = func() time.Time { return r.ReceiptExpiresAt.Time }
	if _, err := s.authorize(context.Background(), r, secret, r.Jkt); err != ErrExpired {
		t.Fatal("expired receipt authorized")
	}
}

func TestAdmissionTransactionCapacityAndFailurePrivacy(t *testing.T) {
	private := errors.New("private-dsn-email-token")
	for _, stage := range []string{"success", "capacity", "begin", "policy guard", "lock", "insert", "commit"} {
		t.Run(stage, func(t *testing.T) {
			tx := &testTx{failures: map[string]error{}}
			database := &testDatabase{txs: []*testTx{tx}}
			namespace := testUsernames(t)
			s, err := NewStore(database, testCipher(t), 1, namespace)
			if err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "begin":
				database.beginErr = private
			case "lock":
				tx.failures["LockRegistrationAdmission"] = private
			case "policy guard":
				tx.failures["username_guard"] = private
			case "commit":
				tx.failures["commit"] = private
			}
			tx.onQuery = func(name string, args []any) pgx.Row {
				if stage == "capacity" {
					return registrationRow{err: pgx.ErrNoRows}
				}
				if stage == "insert" {
					return registrationRow{err: private}
				}
				if name != "CreateRegistrationAttempt" || args[6].(int32) != 1 {
					t.Fatal("wrong admission SQL")
				}
				return registrationRow{record: db.RegistrationAttempt{ID: args[0].(uuid.UUID), CapabilityHash: args[1].([]byte), Jkt: args[2].(string), DetailsEncrypted: args[3].([]byte),
					CreatedAt: args[4].(pgtype.Timestamptz), ExpiresAt: args[5].(pgtype.Timestamptz), State: "pending"}}
			}
			chosen := usernameValue(t, namespace.normalizer, fixtureUsername)
			a, secret, err := s.Create(context.Background(), "person@example.com", "+989123456789", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)), chosen)
			if stage == "success" {
				if err != nil || len(secret) != 32 || len(a.Details.UserHandle) != 8 || tx.commits != 1 || !tx.readCommitted {
					t.Fatal("valid pending admission failed")
				}
				if a.Details.UsernameDisplay != chosen.Display() || a.Details.UsernameSecurity != chosen.SecurityName() || a.Details.UsernameAuthority != chosen.Authority() || a.Details.UsernameEpoch != namespace.epoch || namespace.assignments != 0 {
					t.Fatal("admission did not freeze exact username authority or reserved early")
				}
			} else {
				if err == nil || len(secret) != 0 || strings.Contains(err.Error(), "private") {
					t.Fatal("failure succeeded or leaked authority/diagnostics")
				}
				if stage == "capacity" && err != ErrCapacity {
					t.Fatal("capacity refusal misclassified")
				}
			}
			if stage != "begin" && (!tx.rollbackBounded || tx.rollbacks != 1) {
				t.Fatal("transaction cleanup not detached and bounded")
			}
			if stage == "success" && !reflect.DeepEqual(tx.ops, []string{"timeouts", "username_guard", "LockRegistrationAdmission", "CreateRegistrationAttempt"}) {
				t.Fatalf("capacity read before shared lock: %v", tx.ops)
			}
		})
	}
}

func TestCompleteUsesCallerTransactionAndClearsTransientMaterial(t *testing.T) {
	for _, mode := range []string{"success", "stale revision", "email expiry", "passkey expiry", "future proof", "SQL failure", "wrong fingerprint length"} {
		t.Run(mode, func(t *testing.T) {
			s, a, _ := pendingFixture(t)
			start := a.Record.CreatedAt.Time
			a.Record.EmailTokenIssuedAt = timestamp(start)
			a.Record.EmailTokenExpiresAt = timestamp(start.Add(EmailLifetime))
			a.Record.EmailVerifiedAt = timestamp(start.Add(time.Second))
			a.Record.SmsVerificationRef = uuid.NullUUID{UUID: uuid.New(), Valid: true}
			a.Record.PhoneVerifiedAt = timestamp(start.Add(2 * time.Second))
			a.Record.ChallengeRevision = 1
			a.Record.PasskeyCreatedAt = timestamp(start.Add(3 * time.Second))
			a.Record.PasskeyExpiresAt = timestamp(start.Add(3*time.Second + PasskeyLifetime))
			a.Details.Ceremony = json.RawMessage(`{"challenge":"server-session"}`)
			a.Details.CeremonyRevision = 1
			fingerprint := bytes.Repeat([]byte{4}, 32)
			current := a.Record
			switch mode {
			case "stale revision":
				current.RowRevision++
			case "email expiry":
				s.now = func() time.Time { return start.Add(EmailLifetime) }
			case "passkey expiry":
				s.now = func() time.Time { return current.PasskeyExpiresAt.Time }
			case "future proof":
				current.PhoneVerifiedAt = timestamp(s.now().Add(time.Second))
				current.PasskeyCreatedAt = current.PhoneVerifiedAt
			case "wrong fingerprint length":
				fingerprint = fingerprint[:31]
			}
			blob, err := s.seal(context.Background(), a.Details)
			if err != nil {
				t.Fatal(err)
			}
			current.DetailsEncrypted = blob
			tx := &testTx{}
			userID := uuid.New()
			tx.onQuery = func(name string, args []any) pgx.Row {
				if name == "LockRegistrationAttempt" {
					return registrationRow{record: current}
				}
				if name != "CompleteRegistrationAttempt" {
					t.Fatal("unexpected completion SQL", name)
				}
				if mode == "SQL failure" {
					return registrationRow{err: errors.New("private-user-email-dsn")}
				}
				if args[3].(uuid.NullUUID).UUID != userID || !bytes.Equal(args[2].([]byte), fingerprint) || args[4].(uuid.UUID) != a.Record.ID {
					t.Fatal("completion authority binding changed")
				}
				result := current
				result.State = "completed"
				result.TerminalAt = args[0].(pgtype.Timestamptz)
				result.ReceiptExpiresAt = args[1].(pgtype.Timestamptz)
				result.CompletionFingerprint = fingerprint
				result.ResultUserID = uuid.NullUUID{UUID: userID, Valid: true}
				result.RowRevision++
				result.DetailsEncrypted = nil
				result.EmailTokenHash = nil
				result.EmailTokenIssuedAt = pgtype.Timestamptz{}
				result.EmailTokenExpiresAt = pgtype.Timestamptz{}
				result.SmsVerificationRef = uuid.NullUUID{}
				result.PasskeyCreatedAt = pgtype.Timestamptz{}
				result.PasskeyExpiresAt = pgtype.Timestamptz{}
				return registrationRow{record: result}
			}
			result, err := s.Complete(context.Background(), tx, a, userID, fingerprint)
			if mode == "success" {
				if err != nil || validateRecord(result.Record) != nil || result.Details.Email != "" || !reflect.DeepEqual(tx.ops, []string{"LockRegistrationAttempt", "CompleteRegistrationAttempt"}) {
					t.Fatalf("atomic terminal erasure failed: %v", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("unsafe completion accepted or leaked diagnostics")
			}
			if tx.commits != 0 || tx.rollbacks != 0 {
				t.Fatal("store took ownership of account-birth transaction")
			}
		})
	}
}

func TestEmailProofRequiresIndependentTokenOriginalJKTAndDeadline(t *testing.T) {
	s, a, capability := pendingFixture(t)
	token := bytes.Repeat([]byte{4}, 32)
	hash, _ := HashCapability(token)
	a.Record.EmailTokenHash = hash
	a.Record.EmailTokenIssuedAt = a.Record.CreatedAt
	a.Record.EmailTokenExpiresAt = timestamp(a.Record.CreatedAt.Time.Add(EmailLifetime))
	for _, mode := range []string{"success", "signup capability", "foreign JKT", "expired token", "terminal state"} {
		t.Run(mode, func(t *testing.T) {
			row, key, jkt := a.Record, token, a.Record.Jkt
			local := *s
			switch mode {
			case "signup capability":
				key = capability
			case "foreign JKT":
				jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			case "expired token":
				local.now = func() time.Time { return row.EmailTokenExpiresAt.Time }
			case "terminal state":
				row.State = "completed"
			}
			tx := &testTx{record: row}
			got, err := local.LockEmailProof(context.Background(), tx, row.ID, key, jkt)
			if mode == "success" {
				if err != nil || got.Details.Email != a.Details.Email {
					t.Fatal("valid email proof refused", err)
				}
			} else if err == nil {
				t.Fatal("foreign or expired email proof accepted")
			}
			if !reflect.DeepEqual(tx.ops, []string{"LockRegistrationAttempt"}) || tx.commits != 0 {
				t.Fatal("email token minted or mutated authority")
			}
		})
	}
}
