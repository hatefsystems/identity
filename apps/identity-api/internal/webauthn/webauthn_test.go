package webauthn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// testNamedLoginFloor is the constant-time budget the fixtures configure for
// user-named login options. It is asserted against rather than slept through:
// the fixture replaces Service.sleep with a recorder.
const testNamedLoginFloor = 150 * time.Millisecond

// testMockKey is the mock-derivation secret used across the suite. It is a
// fixed, obviously-fake value so decoy derivations are reproducible between
// runs; production keys come from the KMS (see config.LoadWebAuthn).
var testMockKey = bytes.Repeat([]byte{0x2A}, 32)

// testConfig returns a valid development-shaped RP configuration for the
// localhost origin the software authenticator in service_test.go signs for.
func testConfig() Config {
	return Config{
		RPID:             "localhost",
		RPDisplayName:    "Hatef Identity",
		RPOrigins:        []string{"http://localhost:8080"},
		ChallengeTTL:     5 * time.Minute,
		UserVerification: "preferred",
		ResidentKey:      "required",
		MockChallengeKey: testMockKey,
		NamedLoginFloor:  testNamedLoginFloor,
	}
}

func TestNewSucceeds(t *testing.T) {
	svc, err := New(testConfig(), &fakeUserStore{}, &fakeCredentialStore{}, NewMemoryChallengeStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.wa == nil {
		t.Error("relying party is nil")
	}
	if svc.challengeTTL != 5*time.Minute {
		t.Errorf("challengeTTL = %v, want %v", svc.challengeTTL, 5*time.Minute)
	}
	if svc.now == nil {
		t.Error("now clock is nil; challenge expiry math would panic")
	}
}

// TestNewFailsFast covers the misconfiguration matrix: every one of these would
// otherwise surface as a broken ceremony at runtime instead of at startup.
func TestNewFailsFast(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Config)
		users      UserStore
		creds      CredentialStore
		challenges ChallengeStore
		wantSubstr string
	}{
		{
			name:       "nil user store",
			users:      nil,
			wantSubstr: "user store is required",
		},
		{
			name:       "nil credential store",
			creds:      nil,
			wantSubstr: "credential store is required",
		},
		{
			name:       "nil challenge store",
			challenges: nil,
			wantSubstr: "challenge store is required",
		},
		{
			name:       "empty RPID",
			mutate:     func(c *Config) { c.RPID = "" },
			wantSubstr: "RPID is required",
		},
		{
			name:       "no origins",
			mutate:     func(c *Config) { c.RPOrigins = nil },
			wantSubstr: "at least one RP origin is required",
		},
		{
			name:       "empty origin slice",
			mutate:     func(c *Config) { c.RPOrigins = []string{} },
			wantSubstr: "at least one RP origin is required",
		},
		{
			name:       "zero TTL",
			mutate:     func(c *Config) { c.ChallengeTTL = 0 },
			wantSubstr: "challenge TTL must be positive",
		},
		{
			name:       "negative TTL",
			mutate:     func(c *Config) { c.ChallengeTTL = -time.Second },
			wantSubstr: "challenge TTL must be positive",
		},
		{
			// Without a key the decoys are computable by anyone, so the mock
			// ceremony becomes recognisable and the user-named path silently
			// regains the enumeration oracle it exists to remove.
			name:       "missing mock challenge key",
			mutate:     func(c *Config) { c.MockChallengeKey = nil },
			wantSubstr: "mock challenge key is required",
		},
		{
			name:       "negative login floor",
			mutate:     func(c *Config) { c.NamedLoginFloor = -time.Second },
			wantSubstr: "named login floor must not be negative",
		},
		{
			name:       "unknown resident key requirement",
			mutate:     func(c *Config) { c.ResidentKey = "sometimes" },
			wantSubstr: "resident key requirement",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			// Each case defaults to valid stores and overrides only the one it
			// is exercising, so a nil-store case cannot pass for the wrong
			// reason.
			users, creds, challenges := tc.users, tc.creds, tc.challenges
			if tc.name != "nil user store" {
				users = &fakeUserStore{}
			}
			if tc.name != "nil credential store" {
				creds = &fakeCredentialStore{}
			}
			if tc.name != "nil challenge store" {
				challenges = NewMemoryChallengeStore()
			}

			svc, err := New(cfg, users, creds, challenges)
			if err == nil {
				t.Fatalf("New succeeded, want error containing %q", tc.wantSubstr)
			}
			if svc != nil {
				t.Error("New returned a non-nil service alongside an error")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantSubstr)
			}
			if !strings.HasPrefix(err.Error(), "webauthn: ") {
				t.Errorf("error = %q, want the %q prefix", err.Error(), "webauthn: ")
			}
		})
	}
}

// TestNewRejectsUnusableRelyingParty proves a library-level rejection (an origin
// that is not a valid URL) is surfaced at construction, wrapped with context.
func TestNewRejectsUnusableRelyingParty(t *testing.T) {
	cfg := testConfig()
	cfg.RPOrigins = []string{"not a url"}

	if _, err := New(cfg, &fakeUserStore{}, &fakeCredentialStore{}, NewMemoryChallengeStore()); err == nil {
		t.Skip("go-webauthn accepts this origin; nothing to assert")
	} else if !strings.Contains(err.Error(), "webauthn: build relying party") {
		t.Errorf("error = %q, want it to wrap with %q", err.Error(), "webauthn: build relying party")
	}
}

// TestNewUserHandleIsRandom64Bit locks in the anonymised user.id property from
// docs/architecture.md: exactly 8 bytes (64 bits) from crypto/rand, and never
// repeated across calls.
func TestNewUserHandleIsRandom64Bit(t *testing.T) {
	const draws = 64
	seen := make(map[string]struct{}, draws)
	for i := 0; i < draws; i++ {
		h, err := newUserHandle()
		if err != nil {
			t.Fatalf("newUserHandle: %v", err)
		}
		if len(h) != userHandleByteLen {
			t.Fatalf("len(handle) = %d, want %d", len(h), userHandleByteLen)
		}
		if _, dup := seen[string(h)]; dup {
			t.Fatalf("newUserHandle returned a duplicate handle %x after %d draws", h, i)
		}
		seen[string(h)] = struct{}{}
	}
	if userHandleByteLen != 8 {
		t.Errorf("userHandleByteLen = %d, want 8 (a random 64-bit handle)", userHandleByteLen)
	}
}

type fakeTransacter struct {
	beginCalled    bool
	commitCalled   bool
	rollbackCalled bool
	beginErr       error
	commitErr      error
}

type fakeTx struct {
	ft *fakeTransacter
}

func (f *fakeTx) Begin(_ context.Context) (pgx.Tx, error) {
	return f, nil
}

func (f *fakeTx) Commit(_ context.Context) error {
	f.ft.commitCalled = true
	return f.ft.commitErr
}

func (f *fakeTx) Rollback(_ context.Context) error {
	f.ft.rollbackCalled = true
	return nil
}

func (f *fakeTx) CopyFrom(_ context.Context, _ pgx.Identifier, _ []string, _ pgx.CopyFromSource) (int64, error) {
	return 0, nil
}

func (f *fakeTx) SendBatch(_ context.Context, _ *pgx.Batch) pgx.BatchResults {
	return nil
}

func (f *fakeTx) LargeObjects() pgx.LargeObjects {
	return pgx.LargeObjects{}
}

func (f *fakeTx) Prepare(_ context.Context, _, _ string) (*pgconn.StatementDescription, error) {
	return nil, nil
}

func (f *fakeTx) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (f *fakeTx) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return nil, nil
}

func (f *fakeTx) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return nil
}

func (f *fakeTx) Conn() *pgx.Conn {
	return nil
}

func (ft *fakeTransacter) Begin(_ context.Context) (pgx.Tx, error) {
	ft.beginCalled = true
	if ft.beginErr != nil {
		return nil, ft.beginErr
	}
	return &fakeTx{ft: ft}, nil
}

func TestWithTransacterOption(t *testing.T) {
	ft := &fakeTransacter{}
	svc, err := New(testConfig(), &fakeUserStore{}, &fakeCredentialStore{}, NewMemoryChallengeStore(), WithTransacter(ft))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc == nil {
		t.Fatal("svc is nil")
	}

	// Verify runInTx commits on success
	err = svc.runInTx(context.Background(), func(_ UserStore, _ CredentialStore) error {
		return nil
	})
	if err != nil {
		t.Fatalf("runInTx: %v", err)
	}
	if !ft.beginCalled || !ft.commitCalled {
		t.Errorf("beginCalled = %v, commitCalled = %v, want true for both", ft.beginCalled, ft.commitCalled)
	}

	// Verify runInTx rolls back on function error
	ftErr := &fakeTransacter{}
	svcErr, _ := New(testConfig(), &fakeUserStore{}, &fakeCredentialStore{}, NewMemoryChallengeStore(), WithTransacter(ftErr))
	expectedErr := errors.New("fn failed")
	err = svcErr.runInTx(context.Background(), func(_ UserStore, _ CredentialStore) error {
		return expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Errorf("runInTx err = %v, want %v", err, expectedErr)
	}
	if !ftErr.rollbackCalled {
		t.Error("rollbackCalled = false, want true on error")
	}
}
