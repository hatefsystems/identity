package contactmanager

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func testCipher(t *testing.T) contactproof.Cipher {
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
func capability(b byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

type unavailableDB struct{ calls int }

func (d *unavailableDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	d.calls++
	return nil, errors.New("private database diagnostic")
}

type testSessions struct {
	current session.Session
	err     error
	calls   int
}

func (s *testSessions) LookupByID(context.Context, string, string) (session.Session, error) {
	s.calls++
	return s.current, s.err
}

func TestPendingEnvelopeAuthenticatesEveryFrozenBinding(t *testing.T) {
	s := &Service{deps: Deps{Cipher: testCipher(t)}}
	deadline := time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)
	row := db.ContactChangeAttempt{Digest: bytes.Repeat([]byte{1}, 32), UserID: uuid.New(), SessionID: "session-a", DpopJkt: capability(2), AuthVersion: 3, Target: "email", AuthorizationMethod: "webauthn_uv", AuthorizationExpiresAt: stamp(deadline.Add(time.Minute)), OriginalStateDigest: bytes.Repeat([]byte{4}, 32), ExpiresAt: stamp(deadline)}
	var err error
	row.DestinationEncrypted, err = s.seal(t.Context(), row, "person@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(row.DestinationEncrypted, []byte("person@example.invalid")) {
		t.Fatal("pending destination stored plaintext")
	}
	if got, err := s.open(t.Context(), row); err != nil || got != "person@example.invalid" {
		t.Fatal("exact pending destination unavailable")
	}
	for name, mutate := range map[string]func(*db.ContactChangeAttempt){
		"attempt": func(r *db.ContactChangeAttempt) { r.Digest = bytes.Repeat([]byte{9}, 32) },
		"account": func(r *db.ContactChangeAttempt) { r.UserID = uuid.New() },
		"session": func(r *db.ContactChangeAttempt) { r.SessionID = "session-b" },
		"jkt":     func(r *db.ContactChangeAttempt) { r.DpopJkt = capability(5) },
		"version": func(r *db.ContactChangeAttempt) { r.AuthVersion++ },
		"target":  func(r *db.ContactChangeAttempt) { r.Target = "phone" },
		"method":  func(r *db.ContactChangeAttempt) { r.AuthorizationMethod = "totp" },
		"authority deadline": func(r *db.ContactChangeAttempt) {
			r.AuthorizationExpiresAt.Time = r.AuthorizationExpiresAt.Time.Add(time.Second)
		},
		"channel":            func(r *db.ContactChangeAttempt) { r.Channel = new("email") },
		"evidence":           func(r *db.ContactChangeAttempt) { r.ContactMac = bytes.Repeat([]byte{1}, 32) },
		"target state":       func(r *db.ContactChangeAttempt) { r.OriginalStateDigest = bytes.Repeat([]byte{9}, 32) },
		"ownership deadline": func(r *db.ContactChangeAttempt) { r.ExpiresAt.Time = r.ExpiresAt.Time.Add(time.Second) },
		"ciphertext": func(r *db.ContactChangeAttempt) {
			r.DestinationEncrypted = bytes.Clone(r.DestinationEncrypted)
			r.DestinationEncrypted[len(r.DestinationEncrypted)-1] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			substituted := row
			mutate(&substituted)
			if value, err := s.open(t.Context(), substituted); !errors.Is(err, ErrUnauthorized) || value != "" {
				t.Fatal("substituted pending binding accepted")
			}
		})
	}
}

func TestPendingEnvelopeSurvivesPostgresTimestampLocationRoundtrip(t *testing.T) {
	s := &Service{deps: Deps{Cipher: testCipher(t)}}
	for _, method := range []string{"webauthn_uv", "totp", "password_contact"} {
		t.Run(method, func(t *testing.T) {
			at := time.Now().UTC().Truncate(time.Microsecond)
			row := db.ContactChangeAttempt{Digest: bytes.Repeat([]byte{1}, 32), UserID: uuid.New(), SessionID: "session-a", DpopJkt: capability(2), AuthVersion: 3, Target: "email", AuthorizationMethod: method, AuthorizationExpiresAt: stamp(at.Add(90 * time.Second)), OriginalStateDigest: bytes.Repeat([]byte{4}, 32), ExpiresAt: stamp(at.Add(time.Minute).Truncate(time.Millisecond))}
			if method == "password_contact" {
				row.Channel = new("email")
				row.ContactMac = bytes.Repeat([]byte{5}, 32)
			}
			var err error
			row.DestinationEncrypted, err = s.seal(t.Context(), row, "person@example.invalid")
			if err != nil {
				t.Fatal(err)
			}
			originalAuthority, originalExpiry := row.AuthorizationExpiresAt.Time, row.ExpiresAt.Time
			// Exercise the real pgx codec, which can return the same SQL instant in
			// the process's local zone. No service, global TZ or clock mutation.
			mapping := pgtype.NewMap()
			mapping.RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID, Codec: &pgtype.TimestamptzCodec{ScanLocation: time.FixedZone("database-result", 12600)}})
			for _, value := range []*pgtype.Timestamptz{&row.AuthorizationExpiresAt, &row.ExpiresAt} {
				encoded, err := mapping.Encode(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, *value, nil)
				if err != nil {
					t.Fatal("timestamp binary encoding failed")
				}
				if err := mapping.Scan(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, encoded, value); err != nil {
					t.Fatal("timestamp binary decoding failed")
				}
				if _, offset := value.Time.Zone(); offset != 12600 {
					t.Fatal("codec fixture did not return a non-UTC location")
				}
			}
			if !row.AuthorizationExpiresAt.Time.Equal(originalAuthority) || !row.ExpiresAt.Time.Equal(originalExpiry) {
				t.Fatal("SQL codec changed the captured deadline or precision")
			}
			if value, err := s.open(t.Context(), row); err != nil || value != "person@example.invalid" {
				t.Fatal("same-instant SQL timestamp location invalidated pending envelope")
			}
			row.AuthorizationExpiresAt.Time = row.AuthorizationExpiresAt.Time.Add(time.Microsecond)
			if value, err := s.open(t.Context(), row); !errors.Is(err, ErrUnauthorized) || value != "" {
				t.Fatal("timestamp location repair admitted a changed authority deadline")
			}
		})
	}
}

func TestCurrentContactViewNeverFabricatesEvidence(t *testing.T) {
	s := &Service{deps: Deps{Cipher: testCipher(t)}}
	id := uuid.New()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	for _, method := range []string{contactproof.EmailLink, contactproof.EmailOTP} {
		blob, err := contactproof.Seal(t.Context(), s.deps.Cipher, id, "email", "person@example.invalid", method, at)
		if err != nil {
			t.Fatal(err)
		}
		view := s.contact(t.Context(), id, "email", "person@example.invalid", blob)
		if !view.Verified || view.VerifiedAt == nil || !view.VerifiedAt.Equal(at) {
			t.Fatal("truthful original provenance lost")
		}
		for _, corrupt := range [][]byte{nil, []byte("corrupt"), blob} {
			view = s.contact(t.Context(), id, "email", "different@example.invalid", corrupt)
			if view.Verified || view.VerifiedAt != nil {
				t.Fatal("populated or substituted evidence became verification")
			}
		}
	}
	encoded, err := json.Marshal(Contacts{Email: &Contact{Value: "person@example.invalid"}})
	if err != nil || string(encoded) != `{"email":{"value":"person@example.invalid","verified":false,"verified_at":null},"phone":null}` {
		t.Fatal("minimal nullable contact JSON changed")
	}
}

func TestStrongAuthorizationRequiresExactEarnedBindings(t *testing.T) {
	sess := session.Session{UserID: uuid.NewString(), ID: "sid", DPoPJKT: capability(1), AuthVersion: 2, AuthVersionSet: true}
	grant := StrongAuthorization{UserID: sess.UserID, SessionID: sess.ID, DPoPJKT: sess.DPoPJKT, AuthVersion: sess.AuthVersion, Method: "webauthn_uv", ExpiresAt: time.Now().Add(time.Minute)}
	for _, method := range []string{"webauthn_uv", "totp"} {
		grant.Method = method
		if err := strong(sess, &grant); err != nil {
			t.Fatal("genuinely strong method rejected")
		}
	}
	for name, mutate := range map[string]func(*StrongAuthorization){
		"user": func(g *StrongAuthorization) { g.UserID = uuid.NewString() }, "session": func(g *StrongAuthorization) { g.SessionID = "foreign" }, "jkt": func(g *StrongAuthorization) { g.DPoPJKT = capability(3) }, "version": func(g *StrongAuthorization) { g.AuthVersion++ }, "method": func(g *StrongAuthorization) { g.Method = "password" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := grant
			mutate(&bad)
			if !errors.Is(strong(sess, &bad), ErrUnauthorized) {
				t.Fatal("unearned or foreign grant accepted")
			}
		})
	}
	grant.ExpiresAt = time.Now()
	if !errors.Is(strong(sess, &grant), ErrExpired) {
		t.Fatal("deadline is not half-open")
	}
}

func TestMalformedOwnershipNeverTouchesSQLOrRedis(t *testing.T) {
	d := &unavailableDB{}
	s := &Service{deps: Deps{DB: d}}
	for _, tc := range []struct{ target, handle, code string }{{"backup", capability(1), "000001"}, {"email", "bad", "000001"}, {"phone", capability(1), "12345"}, {"email", capability(1), "123 45"}, {"email", capability(1), "\u06f0\u06f0\u06f0\u06f0\u06f0\u06f1"}} {
		if _, err := s.Finish(t.Context(), session.Session{}, tc.target, tc.handle, tc.code); !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed ownership admission accepted")
		}
	}
	if d.calls != 0 {
		t.Fatal("malformed input opened transaction")
	}
}

func TestLiveLookupNeverRenewsAndRejectsForeignOrStaleState(t *testing.T) {
	now := time.Now()
	sess := session.Session{UserID: uuid.NewString(), ID: "sid", DPoPJKT: capability(1), AuthVersion: 2, AuthVersionSet: true, Kind: session.KindAuthenticated, IdleExpiry: now.Add(time.Minute), AbsoluteExpiry: now.Add(time.Hour)}
	id, _ := uuid.Parse(sess.UserID)
	user := db.User{ID: id, Status: "active", AuthVersion: 2}
	reader := &testSessions{current: sess}
	s := &Service{deps: Deps{Sessions: reader}}
	if _, err := s.live(t.Context(), sess, user); err != nil || reader.calls != 1 {
		t.Fatal("live nonrenewing lookup unavailable")
	}
	for _, change := range []func(*session.Session){func(v *session.Session) { v.DPoPJKT = capability(4) }, func(v *session.Session) { v.AuthVersion++ }, func(v *session.Session) { v.Kind = session.KindRecoveryEnrollment }, func(v *session.Session) { v.IdleExpiry = time.Now() }} {
		reader.current = sess
		change(&reader.current)
		if _, err := s.live(t.Context(), sess, user); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("stale live session admitted")
		}
	}
	reader.err = errors.New("redis://private:secret@host")
	if _, err := s.live(t.Context(), sess, user); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatal("session diagnostics leaked")
	}
}

func TestErrorCategoriesAndDisabledReadDependencies(t *testing.T) {
	for _, err := range []error{contactcode.ErrOutcomeUnknown, contactcode.ErrInvalidCode, contactcode.ErrRateLimited, errors.New("person@example.invalid database secret")} {
		got := safeError(err)
		if strings.Contains(got.Error(), "person@") || strings.Contains(got.Error(), "secret") {
			t.Fatal("private diagnostics exposed")
		}
	}
	if _, err := New(Deps{DB: &unavailableDB{}, Queries: db.New(nil), Sessions: &testSessions{}, Cipher: testCipher(t)}); err != nil {
		t.Fatal("provider-free read/remove requires an index key")
	}
}
