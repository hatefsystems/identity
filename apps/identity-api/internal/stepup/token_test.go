package stepup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const testIssuer = "https://identity.test"

// testNow is a fixed instant so every lifetime assertion is deterministic.
var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// newTestService builds a Service pinned to the fixed testNow instant.
func newTestService(t *testing.T) (*Service, *keys.Manager) {
	t.Helper()
	return newTestServiceAt(t, func() time.Time { return testNow })
}

// newTestServiceAt builds a Service over ephemeral ES256 keys driven by the given
// clock, returning the keystore so a test can sign deliberately malformed or
// wrong-purpose tokens with the very key the validator trusts.
//
// The replay guard is given the same clock on purpose: it judges entry expiry
// against its own clock using instants stamped by the Service, so leaving it on
// time.Now while the Service runs on a fixed instant would make every entry look
// already expired and silently disable single-use enforcement.
func newTestServiceAt(t *testing.T, clock func() time.Time) (*Service, *keys.Manager) {
	t.Helper()

	active, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	next, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	km, err := keys.NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("keys.NewManager: %v", err)
	}

	svc, err := New(
		Config{Issuer: testIssuer},
		km,
		&fakeUserStore{},
		&fakePasskeys{},
		&fakeTOTP{valid: "123456"},
		NewMemoryReplayGuard(WithReplayClock(clock)),
		WithClock(clock),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, km
}

// testSession returns a session a minted grant will be bound to.
func testSession() session.Session {
	return session.Session{ID: "sess-1", UserID: "user-1"}
}

// mint issues a grant for the standard test session.
func mint(t *testing.T, svc *Service) string {
	t.Helper()

	compact, _, err := svc.Mint(MintParams{
		UserID:    "user-1",
		SessionID: "sess-1",
		AMR:       amrTOTP,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return compact
}

// signWith signs an arbitrary claim set with the active key, so a test can vary
// exactly one property of an otherwise-valid grant.
func signWith(t *testing.T, km *keys.Manager, typ string, claims token.Claims) string {
	t.Helper()

	compact, err := token.Sign(km.ActiveSigner(), typ, claims)
	if err != nil {
		t.Fatalf("token.Sign: %v", err)
	}
	return compact
}

// validClaims is the claim set of a well-formed grant, for tests that mutate one
// field at a time.
func validClaims() token.Claims {
	return token.Claims{
		"iss":       testIssuer,
		"sub":       "user-1",
		"aud":       testIssuer,
		"acr":       ACRStepUp,
		"amr":       []string{"otp"},
		"auth_time": testNow.Unix(),
		"sid":       "sess-1",
		"jti":       uuid.NewString(),
		"iat":       testNow.Unix(),
		"exp":       testNow.Add(5 * time.Minute).Unix(),
	}
}

// --- Mint -------------------------------------------------------------------

func TestMintProducesAValidatableGrant(t *testing.T) {
	svc, _ := newTestService(t)

	compact, expiresAt, err := svc.Mint(MintParams{
		UserID:    "user-1",
		SessionID: "sess-1",
		AMR:       amrWebAuthnUV,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if want := testNow.Add(DefaultTokenTTL); !expiresAt.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, want)
	}

	grant, err := svc.Validate(context.Background(), compact, testSession())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if grant.UserID != "user-1" || grant.SessionID != "sess-1" {
		t.Fatalf("grant bound to %s/%s, want user-1/sess-1", grant.UserID, grant.SessionID)
	}
	if strings.Join(grant.AMR, ",") != strings.Join(amrWebAuthnUV, ",") {
		t.Fatalf("amr = %v, want %v", grant.AMR, amrWebAuthnUV)
	}
	if !grant.AuthTime.Equal(testNow) {
		t.Fatalf("auth_time = %v, want %v", grant.AuthTime, testNow)
	}
}

// TestMintStampsTheDocumentedTyp is the structural half of the
// token-substitution defence: the header must name the step-up media type so the
// validator can reject anything else without inspecting claims.
func TestMintStampsTheDocumentedTyp(t *testing.T) {
	svc, _ := newTestService(t)

	parts := strings.Split(mint(t, svc), ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Typ != token.TypStepUpToken {
		t.Fatalf("typ = %q, want %q", header.Typ, token.TypStepUpToken)
	}
	if header.Alg != keys.AlgES256 {
		t.Fatalf("alg = %q, want %q", header.Alg, keys.AlgES256)
	}
}

// TestMintBindsDPoPThumbprintWhenPresent covers the forward hook: the cnf claim
// appears only for a sender-constrained session.
func TestMintBindsDPoPThumbprintWhenPresent(t *testing.T) {
	svc, km := newTestService(t)

	withJKT, _, err := svc.Mint(MintParams{UserID: "user-1", SessionID: "sess-1", DPoPJKT: "thumb"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	claims, err := token.Verify(withJKT, km.ActiveSigner())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok || cnf["jkt"] != "thumb" {
		t.Fatalf("cnf = %v, want {jkt: thumb}", claims["cnf"])
	}

	plain := mint(t, svc)
	claims, err = token.Verify(plain, km.ActiveSigner())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, present := claims["cnf"]; present {
		t.Fatal("a bearer session's grant must not carry a cnf claim")
	}
}

func TestMintRequiresSubjectAndSession(t *testing.T) {
	svc, _ := newTestService(t)

	if _, _, err := svc.Mint(MintParams{SessionID: "sess-1"}); err == nil {
		t.Fatal("expected an error when minting without a user id")
	}
	if _, _, err := svc.Mint(MintParams{UserID: "user-1"}); err == nil {
		t.Fatal("expected an error when minting without a session id")
	}
}

// --- Validate: token substitution -------------------------------------------

// TestValidateRejectsWrongPurposeTokens is the single most important test in
// this package.
//
// Access tokens, ID tokens, and step-up grants are signed by the same keystore,
// and access tokens already set aud == iss (see internal/oidc/token/service.go),
// so a token minted for another purpose carries a genuine signature from a
// trusted key. Only the typ header and the acr claim distinguish it. Each case
// below is signed with the active key and differs from a valid grant in exactly
// one respect.
func TestValidateRejectsWrongPurposeTokens(t *testing.T) {
	tests := []struct {
		name   string
		typ    string
		mutate func(token.Claims)
	}{
		{
			name:   "access token typ",
			typ:    token.TypAccessToken,
			mutate: func(token.Claims) {},
		},
		{
			name:   "id token typ",
			typ:    token.TypJWT,
			mutate: func(token.Claims) {},
		},
		{
			name:   "empty typ",
			typ:    "",
			mutate: func(token.Claims) {},
		},
		{
			name:   "missing acr",
			typ:    token.TypStepUpToken,
			mutate: func(c token.Claims) { delete(c, "acr") },
		},
		{
			name:   "weaker acr",
			typ:    token.TypStepUpToken,
			mutate: func(c token.Claims) { c["acr"] = "urn:example:password" },
		},
		{
			name:   "foreign issuer",
			typ:    token.TypStepUpToken,
			mutate: func(c token.Claims) { c["iss"] = "https://evil.test" },
		},
		{
			name:   "foreign audience",
			typ:    token.TypStepUpToken,
			mutate: func(c token.Claims) { c["aud"] = "https://evil.test" },
		},
		{
			name:   "missing jti defeats single-use tracking",
			typ:    token.TypStepUpToken,
			mutate: func(c token.Claims) { delete(c, "jti") },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, km := newTestService(t)

			claims := validClaims()
			tc.mutate(claims)

			_, err := svc.Validate(context.Background(), signWith(t, km, tc.typ, claims), testSession())
			if !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("expected ErrInvalidGrant, got %v", err)
			}
		})
	}

	// Control: the same helper with nothing mutated must be accepted, so the
	// rejections above are attributable to the property under test rather than to
	// the helper producing an unusable token.
	svc, km := newTestService(t)
	if _, err := svc.Validate(
		context.Background(),
		signWith(t, km, token.TypStepUpToken, validClaims()),
		testSession(),
	); err != nil {
		t.Fatalf("control grant was rejected: %v", err)
	}
}

// --- Validate: signature and structure --------------------------------------

func TestValidateRejectsMalformedAndUnsignedTokens(t *testing.T) {
	svc, km := newTestService(t)
	valid := mint(t, svc)
	parts := strings.Split(valid, ".")

	// An "alg": "none" token with a valid-looking header and payload. token.Verify
	// pins alg to the resolved key's algorithm, so this can never verify.
	headerNone := base64.RawURLEncoding.EncodeToString([]byte(
		`{"alg":"none","typ":"stepup+jwt","kid":"` + km.ActiveSigner().KID + `"}`))
	payload, err := json.Marshal(validClaims())
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	algNone := headerNone + "." + base64.RawURLEncoding.EncodeToString(payload) + "."

	tests := []struct {
		name    string
		compact string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"two segments", parts[0] + "." + parts[1]},
		{"garbage header", "!!!." + parts[1] + "." + parts[2]},
		{"alg none", algNone},
		{"tampered payload", parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]},
		{"truncated signature", parts[0] + "." + parts[1] + ".AAAA"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Validate(context.Background(), tc.compact, testSession())
			if err == nil {
				t.Fatal("expected the token to be rejected")
			}
			// An empty header is reported as "no grant" so the middleware can log
			// the difference; everything else is an invalid grant.
			if tc.compact == "" || strings.TrimSpace(tc.compact) == "" {
				if !errors.Is(err, ErrNoGrant) {
					t.Fatalf("expected ErrNoGrant, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("expected ErrInvalidGrant, got %v", err)
			}
		})
	}
}

// TestValidateRejectsUnknownKid covers a grant signed by a key that has rotated
// entirely out of the keystore.
func TestValidateRejectsUnknownKid(t *testing.T) {
	svc, _ := newTestService(t)

	// A separate keystore stands in for a retired key.
	foreign, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	compact, err := token.Sign(foreign, token.TypStepUpToken, validClaims())
	if err != nil {
		t.Fatalf("token.Sign: %v", err)
	}

	if _, err := svc.Validate(context.Background(), compact, testSession()); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected ErrInvalidGrant, got %v", err)
	}
}

// TestValidateAcceptsAGrantSignedByARotatedKey confirms a grant minted moments
// before a rotation still verifies, since VerificationKey searches every slot.
func TestValidateAcceptsAGrantSignedByARotatedKey(t *testing.T) {
	svc, km := newTestService(t)
	compact := mint(t, svc)

	newNext, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	if err := km.Rotate(newNext); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if _, err := svc.Validate(context.Background(), compact, testSession()); err != nil {
		t.Fatalf("a grant signed by the now-previous key was rejected: %v", err)
	}
}

// --- Validate: temporal -----------------------------------------------------

func TestValidateEnforcesExpiryExactly(t *testing.T) {
	svc, km := newTestService(t)

	expired := validClaims()
	expired["exp"] = testNow.Add(-time.Second).Unix()
	if _, err := svc.Validate(
		context.Background(), signWith(t, km, token.TypStepUpToken, expired), testSession(),
	); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected an expired grant to be rejected, got %v", err)
	}

	// Expiry is enforced with no leeway, so a grant expiring exactly now is dead.
	atBoundary := validClaims()
	atBoundary["exp"] = testNow.Unix()
	if _, err := svc.Validate(
		context.Background(), signWith(t, km, token.TypStepUpToken, atBoundary), testSession(),
	); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected a grant expiring at exactly now to be rejected, got %v", err)
	}
}

func TestValidateRejectsPreDatedGrantsBeyondSkew(t *testing.T) {
	svc, km := newTestService(t)

	// Inside the skew allowance: accepted.
	nearFuture := validClaims()
	nearFuture["iat"] = testNow.Add(clockSkewLeeway - time.Second).Unix()
	if _, err := svc.Validate(
		context.Background(), signWith(t, km, token.TypStepUpToken, nearFuture), testSession(),
	); err != nil {
		t.Fatalf("a grant inside the clock-skew allowance was rejected: %v", err)
	}

	// Well beyond it: rejected, so a grant cannot be pre-dated to extend its life.
	farFuture := validClaims()
	farFuture["iat"] = testNow.Add(time.Hour).Unix()
	if _, err := svc.Validate(
		context.Background(), signWith(t, km, token.TypStepUpToken, farFuture), testSession(),
	); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected a pre-dated grant to be rejected, got %v", err)
	}
}

// --- Validate: session binding and single use -------------------------------

func TestValidateEnforcesSessionBinding(t *testing.T) {
	tests := []struct {
		name string
		sess session.Session
	}{
		{"different session, same subject", session.Session{ID: "sess-2", UserID: "user-1"}},
		{"different subject, same session id", session.Session{ID: "sess-1", UserID: "user-2"}},
		{"both different", session.Session{ID: "sess-2", UserID: "user-2"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			_, err := svc.Validate(context.Background(), mint(t, svc), tc.sess)
			if !errors.Is(err, ErrGrantNotForSession) {
				t.Fatalf("expected ErrGrantNotForSession, got %v", err)
			}
		})
	}
}

// TestValidateConsumesTheGrant confirms single use, which is what makes a grant
// authorise one operation rather than every operation inside its TTL.
func TestValidateConsumesTheGrant(t *testing.T) {
	svc, _ := newTestService(t)
	compact := mint(t, svc)

	if _, err := svc.Validate(context.Background(), compact, testSession()); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := svc.Validate(context.Background(), compact, testSession()); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("expected ErrGrantConsumed on reuse, got %v", err)
	}
}

// TestValidateDoesNotConsumeOnMismatchedSession confirms a grant presented
// against the wrong session is not burned, so an attacker cannot invalidate a
// victim's in-flight grant by replaying it into their own session.
func TestValidateDoesNotConsumeOnMismatchedSession(t *testing.T) {
	svc, _ := newTestService(t)
	compact := mint(t, svc)

	if _, err := svc.Validate(
		context.Background(), compact, session.Session{ID: "sess-2", UserID: "user-1"},
	); !errors.Is(err, ErrGrantNotForSession) {
		t.Fatalf("expected ErrGrantNotForSession, got %v", err)
	}
	// The legitimate owner must still be able to spend it.
	if _, err := svc.Validate(context.Background(), compact, testSession()); err != nil {
		t.Fatalf("the grant was burned by a failed foreign attempt: %v", err)
	}
}

// --- Config -----------------------------------------------------------------

func TestNewRejectsAnOverlongTTL(t *testing.T) {
	km, _ := keys.NewEphemeralES256()
	next, _ := keys.NewEphemeralES256()
	manager, err := keys.NewManager(km, next, nil)
	if err != nil {
		t.Fatalf("keys.NewManager: %v", err)
	}

	_, err = New(
		Config{Issuer: testIssuer, TokenTTL: time.Hour},
		manager, &fakeUserStore{}, &fakePasskeys{}, nil, NewMemoryReplayGuard(),
	)
	if err == nil {
		t.Fatal("expected a TTL above the documented 5-minute ceiling to be rejected")
	}
}

func TestNewRequiresAtLeastOneFactor(t *testing.T) {
	active, _ := keys.NewEphemeralES256()
	next, _ := keys.NewEphemeralES256()
	manager, err := keys.NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("keys.NewManager: %v", err)
	}

	// A service that can verify nothing would leave every gated route
	// permanently unreachable, so it must fail at construction.
	if _, err := New(
		Config{Issuer: testIssuer},
		manager, &fakeUserStore{}, nil, nil, NewMemoryReplayGuard(),
	); err == nil {
		t.Fatal("expected construction without any factor verifier to fail")
	}
}

func TestNewRequiresCollaborators(t *testing.T) {
	active, _ := keys.NewEphemeralES256()
	next, _ := keys.NewEphemeralES256()
	manager, err := keys.NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("keys.NewManager: %v", err)
	}

	tests := []struct {
		name  string
		build func() error
	}{
		{"no issuer", func() error {
			_, err := New(Config{}, manager, &fakeUserStore{}, &fakePasskeys{}, nil, NewMemoryReplayGuard())
			return err
		}},
		{"no key store", func() error {
			_, err := New(Config{Issuer: testIssuer}, nil, &fakeUserStore{}, &fakePasskeys{}, nil, NewMemoryReplayGuard())
			return err
		}},
		{"no user store", func() error {
			_, err := New(Config{Issuer: testIssuer}, manager, nil, &fakePasskeys{}, nil, NewMemoryReplayGuard())
			return err
		}},
		{"no replay guard", func() error {
			_, err := New(Config{Issuer: testIssuer}, manager, &fakeUserStore{}, &fakePasskeys{}, nil, nil)
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.build(); err == nil {
				t.Fatal("expected construction to fail")
			}
		})
	}
}
