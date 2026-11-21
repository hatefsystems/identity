package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

func testCapability(value byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(value), 32)))
}

type loginUsers struct {
	mu         sync.Mutex
	user       db.User
	lookupErr  error
	readErr    error
	names      []string
	normalizer *username.Normalizer
}

func (u *loginUsers) NormalizeLookup(name string) (username.Value, error) {
	return u.normalizer.NormalizeLookup(name)
}

func (u *loginUsers) Lookup(_ context.Context, name string) (uuid.UUID, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.names = append(u.names, name)
	if u.lookupErr != nil {
		return uuid.Nil, u.lookupErr
	}
	if name != "fixture_user" {
		return uuid.Nil, username.ErrNotFound
	}
	return u.user.ID, nil
}

func (u *loginUsers) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.readErr != nil {
		return db.User{}, u.readErr
	}
	if id != u.user.ID {
		return db.User{}, pgx.ErrNoRows
	}
	return u.user, nil
}

type loginAccounts struct {
	users *loginUsers
	err   error
}

func (a *loginAccounts) Validate(ctx context.Context, id string, version int64) error {
	if a.err != nil {
		return a.err
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return session.ErrAccountIneligible
	}
	u, err := a.users.GetUserByID(ctx, parsed)
	if err != nil || u.Status != "active" || u.DeletedAt.Valid || u.AuthVersion != version {
		return session.ErrAccountIneligible
	}
	return nil
}
func (a *loginAccounts) WithActive(ctx context.Context, id string, version int64, fn func() error) error {
	if err := a.Validate(ctx, id, version); err != nil {
		return err
	}
	return fn()
}
func (*loginAccounts) Epoch(context.Context) (int64, error) { return 1, nil }

type loginLimiter struct {
	err  error
	deny bool
	keys []string
}

func (l *loginLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	l.keys = append(l.keys, key)
	return !l.deny, l.err
}

type loginTOTP struct {
	calls  atomic.Int32
	verify func() error
}

func (v *loginTOTP) VerifyEnabledCode(_ context.Context, _ uuid.UUID, code string) error {
	v.calls.Add(1)
	if v.verify != nil {
		return v.verify()
	}
	if code != "123456" {
		return mfa.ErrInvalidCode
	}
	return nil
}

type loginContacts struct{ proof *contactproof.Evidence }

func (c *loginContacts) Contact(_ context.Context, _ uuid.UUID, _ string) (*contactproof.Evidence, error) {
	return c.proof, nil
}

type loginSender struct {
	code  string
	calls int
	err   error
}

func (s *loginSender) SendCode(_ context.Context, _, code string, _ time.Time) error {
	s.code = code
	s.calls++
	return s.err
}

type loginFixture struct {
	svc      *Service
	users    *loginUsers
	factor   *loginTOTP
	redis    *miniredis.Miniredis
	client   *redis.Client
	pending  *RedisPending
	accounts *loginAccounts
	limiter  *loginLimiter
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()
	r := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: r.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = client.Close() })
	pending, err := NewRedisPending(client)
	if err != nil {
		t.Fatal(err)
	}
	// This explicit candidate is a fixture, never a production policy default.
	normalizer, err := username.New(username.Policy{ID: uuid.New(), Normalization: username.NormalizationV1, Folds: []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}}, ReservedNames: []string{}}, `[\x{0621}-\x{06CC}]+`, []byte(strings.Repeat("K", 32)), "login-quota-fixture")
	if err != nil {
		t.Fatal(err)
	}
	users := &loginUsers{user: db.User{ID: uuid.New(), Status: "active", AuthVersion: 7}, normalizer: normalizer}
	factor := &loginTOTP{}
	accounts := &loginAccounts{users: users}
	limiter := &loginLimiter{}
	svc, err := New(Deps{Usernames: users, Users: users, Pending: pending, TOTP: factor, Replay: stepup.NewMemoryReplayGuard(), Accounts: accounts, Limiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	return &loginFixture{svc, users, factor, r, client, pending, accounts, limiter}
}

func (f *loginFixture) prepare(t *testing.T, method string) Result {
	t.Helper()
	uv := session.UVNotApplicable
	if method == session.MethodPasskey {
		uv = session.UVVerified
	}
	result, err := f.svc.Prepare(t.Context(), session.IssueParams{UserID: f.users.user.ID.String(), AuthVersion: 7, AuthVersionSet: true, DPoPJKT: testCapability('b'), Evidence: session.Evidence{PrimaryMethod: method, UV: uv, TOTPSet: true, AuthenticatedAt: f.svc.now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func requireNoAuthority(t *testing.T, result Result) {
	t.Helper()
	if result.Issue != nil || result.Preauthentication != "" || !result.ExpiresAt.IsZero() {
		t.Fatal("failed proof returned authentication authority")
	}
}

func TestPasswordCredentialConfigurationsAndGenericFailures(t *testing.T) {
	const secret = " exact password bytes  "
	hash, err := password.HashContext(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, identifier, secret string
		hash                     *string
		success                  bool
		lookupErr                error
	}{
		{"password_only", "fixture_user", secret, &hash, true, nil},
		{"dual_credentials", "fixture_user", secret, &hash, true, nil},
		{"passkey_only", "fixture_user", secret, nil, false, nil},
		{"missing_account", "absent_user", secret, nil, false, nil},
		{"wrong_password", "fixture_user", "incorrect password", &hash, false, nil},
		{"untrimmed_password", "fixture_user", strings.TrimSpace(secret), &hash, false, nil},
		{"email_is_not_identifier", "fixture@example.invalid", secret, &hash, false, nil},
		{"invalid_username", "!invalid", secret, &hash, false, username.ErrInvalidUsername},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginFixture(t)
			f.users.user.PasswordHash, f.users.lookupErr = tc.hash, tc.lookupErr
			result, err := f.svc.Password(t.Context(), tc.identifier, tc.secret, testCapability('b'), "203.0.113.7")
			if !tc.success {
				if !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("failure classification: %v", err)
				}
				requireNoAuthority(t, result)
				if len(f.redis.Keys()) != 0 {
					t.Fatal("failed password created preauthentication")
				}
				return
			}
			if err != nil || result.Issue == nil || result.Preauthentication != "" {
				t.Fatalf("successful password result: %v", err)
			}
			e := result.Issue.Evidence
			if e.PrimaryMethod != session.MethodPassword || e.UV != session.UVNotApplicable || !e.TOTPSet || e.TOTP || e.AuthenticatedAt.IsZero() || e.AdminEligible() {
				t.Fatal("password acquired unearned MFA/administrative evidence")
			}
			if result.Issue.AuthVersion != 7 || result.Issue.DPoPJKT != testCapability('b') || len(f.users.names) != 1 || f.users.names[0] != tc.identifier {
				t.Fatal("password changed captured account/browser/identifier")
			}
		})
	}
}

func TestPrepareRequiresCapturedAuthorityAndPreservesPrimaryMethod(t *testing.T) {
	for _, method := range []string{session.MethodPassword, session.MethodContactCode, session.MethodPasskey} {
		t.Run(method, func(t *testing.T) {
			f := newLoginFixture(t)
			f.users.user.IsMfaEnabled = true
			authenticatedAt := time.Now().UTC().Truncate(time.Millisecond)
			f.svc.now = func() time.Time { return authenticatedAt }
			var first Result
			if method == session.MethodContactCode {
				first, _ = f.verifyContact(t)
			} else {
				first = f.prepare(t, method)
			}
			if first.Issue != nil || first.Preauthentication == "" || first.ExpiresAt.After(time.Now().Add(5*time.Minute)) {
				t.Fatal("MFA first factor issued session or extended deadline")
			}
			f.svc.now = func() time.Time { return authenticatedAt.Add(30 * time.Second) }
			result, err := f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
			if err != nil || result.Issue == nil || result.Preauthentication != "" {
				t.Fatalf("MFA completion: %v", err)
			}
			if e := result.Issue.Evidence; e.PrimaryMethod != method || !e.TOTP || !e.TOTPSet || !e.AuthenticatedAt.Equal(authenticatedAt) || method == session.MethodContactCode && e.AdminEligible() {
				t.Fatal("MFA rewrote first factor or fabricated administrative evidence")
			}
			result, err = f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
			if !errors.Is(err, ErrChallengeExpired) {
				t.Fatalf("consumed MFA challenge accepted: %v", err)
			}
			requireNoAuthority(t, result)
		})
	}
	for _, change := range []string{"version", "status"} {
		t.Run(change, func(t *testing.T) {
			f := newLoginFixture(t)
			p := session.IssueParams{UserID: f.users.user.ID.String(), AuthVersion: 7, AuthVersionSet: true, DPoPJKT: testCapability('b'), Evidence: session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, AuthenticatedAt: time.Now()}}
			if change == "version" {
				f.users.user.AuthVersion++
			} else {
				f.users.user.Status = "suspended"
			}
			result, err := f.svc.Prepare(t.Context(), p)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("stale authority accepted: %v", err)
			}
			requireNoAuthority(t, result)
		})
	}
}

func TestMFAWrongBrowserAttemptsAndUnknownVerification(t *testing.T) {
	f := newLoginFixture(t)
	f.users.user.IsMfaEnabled = true
	first := f.prepare(t, session.MethodPassword)
	result, err := f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('x'), "123456")
	if !errors.Is(err, ErrChallengeExpired) || f.factor.calls.Load() != 0 {
		t.Fatalf("wrong browser reached TOTP: %v", err)
	}
	requireNoAuthority(t, result)
	for _, code := range []string{"111111", "222222", "333333"} {
		result, err = f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), code)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong code classification: %v", err)
		}
		requireNoAuthority(t, result)
	}
	result, err = f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
	if !errors.Is(err, ErrChallengeExpired) || f.factor.calls.Load() != 3 {
		t.Fatalf("exhausted attempts reset: %v", err)
	}
	requireNoAuthority(t, result)

	f = newLoginFixture(t)
	f.users.user.IsMfaEnabled = true
	first = f.prepare(t, session.MethodPassword)
	f.factor.verify = func() error { return errors.New("unknown verification commit") }
	result, err = f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unknown verification classified as confirmed: %v", err)
	}
	requireNoAuthority(t, result)
	result, err = f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "654321")
	if !errors.Is(err, ErrChallengeExpired) || f.factor.calls.Load() != 1 {
		t.Fatalf("uncertain MFA automatically retried: %v", err)
	}
	requireNoAuthority(t, result)
}

func TestMFARechecksAuthorityBeforeAndAfterTOTP(t *testing.T) {
	for _, phase := range []string{"before", "during"} {
		for _, change := range []string{"role_version", "suspended"} {
			t.Run(phase+"_"+change, func(t *testing.T) {
				f := newLoginFixture(t)
				f.users.user.IsMfaEnabled = true
				first := f.prepare(t, session.MethodPassword)
				mutate := func() error {
					if change == "role_version" {
						f.users.user.AuthVersion++
					} else {
						f.users.user.Status = "suspended"
					}
					return nil
				}
				if phase == "before" {
					_ = mutate()
				} else {
					f.factor.verify = mutate
				}
				result, err := f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
				if !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("changed authority accepted: %v", err)
				}
				requireNoAuthority(t, result)
				if phase == "before" && f.factor.calls.Load() != 0 {
					t.Fatal("stale account consumed TOTP")
				}
			})
		}
	}
}

func TestMFAConcurrentCompletionHasSingleWinner(t *testing.T) {
	f := newLoginFixture(t)
	f.users.user.IsMfaEnabled = true
	first := f.prepare(t, session.MethodPassword)
	start := make(chan struct{})
	type outcome struct {
		result Result
		err    error
	}
	results := make(chan outcome, 12)
	for range 12 {
		go func() {
			<-start
			r, e := f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
			results <- outcome{r, e}
		}()
	}
	close(start)
	winners := 0
	for range 12 {
		o := <-results
		if o.err == nil {
			winners++
			if o.result.Issue == nil {
				t.Fatal("winner had no authority")
			}
		} else {
			if !errors.Is(o.err, ErrChallengeExpired) {
				t.Fatalf("concurrent loser: %v", o.err)
			}
			requireNoAuthority(t, o.result)
		}
	}
	if winners != 1 || f.factor.calls.Load() != 1 {
		t.Fatalf("completion winners=%d factor calls=%d", winners, f.factor.calls.Load())
	}
}

func TestContactCodeDecoysAndCurrentDestinationRecheck(t *testing.T) {
	for _, scenario := range []string{"password_only", "passkey_only", "dual", "missing", "unverified", "disabled_sms", "unknown_delivery", "changed_contact", "changed_version"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLoginFixture(t)
			store, err := contactcode.NewRedisStore(f.client)
			if err != nil {
				t.Fatal(err)
			}
			sender := &loginSender{}
			codes, err := contactcode.New(contactcode.Config{HashKey: []byte(strings.Repeat("k", 32))}, store, nil, sender)
			if err != nil {
				t.Fatal(err)
			}
			contacts := &loginContacts{proof: &contactproof.Evidence{AccountID: f.users.user.ID, Channel: contactproof.Email, Destination: "owned@example.invalid"}}
			f.svc.deps.Codes, f.svc.deps.Contacts = codes, contacts
			name, channel := "fixture_user", contactcode.ChannelEmail
			if scenario == "missing" {
				name = "absent_user"
			}
			if scenario == "unverified" {
				contacts.proof = nil
			}
			if scenario == "disabled_sms" {
				channel = contactcode.ChannelSMS
			}
			if scenario == "unknown_delivery" {
				sender.err = errors.New("transport result unknown")
			}
			handle, deadline, err := f.svc.RequestCode(t.Context(), name, channel, testCapability('b'), "203.0.113.8")
			if err != nil || len(handle) != 43 || deadline.IsZero() {
				t.Fatalf("nonuniform request response: %v", err)
			}
			if scenario == "changed_contact" {
				contacts.proof.Destination = "new@example.invalid"
			}
			if scenario == "changed_version" {
				f.users.user.AuthVersion++
			}
			result, err := f.svc.VerifyCode(t.Context(), handle, testCapability('b'), sender.code)
			switch scenario {
			case "password_only", "passkey_only", "dual":
				if err != nil || result.Issue == nil || result.Issue.UserID != f.users.user.ID.String() || result.Issue.Evidence.PrimaryMethod != session.MethodContactCode || result.Issue.Evidence.AdminEligible() {
					t.Fatalf("contact account/method binding: %v", err)
				}
			case "changed_contact", "changed_version":
				if !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("changed contact/authority accepted: %v", err)
				}
				requireNoAuthority(t, result)
			default:
				if !errors.Is(err, ErrChallengeExpired) {
					t.Fatalf("decoy created authority: %v", err)
				}
				requireNoAuthority(t, result)
			}
			if scenario == "unknown_delivery" && sender.calls != 1 {
				t.Fatal("unknown delivery retried")
			}
		})
	}
}

func TestLoginRateLimitFailsClosedBeforeLookup(t *testing.T) {
	for _, fault := range []string{"denied", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			f := newLoginFixture(t)
			want := ErrRateLimited
			if fault == "unknown" {
				f.limiter.err = errors.New("lost limiter response")
				want = ErrOutcomeUnknown
			} else {
				f.limiter.deny = true
			}
			result, err := f.svc.Password(t.Context(), "fixture_user", "secret", testCapability('b'), "203.0.113.8")
			if !errors.Is(err, want) || len(f.users.names) != 0 || len(f.limiter.keys) != 1 || !strings.HasPrefix(f.limiter.keys[0], "rate:login:source:") {
				t.Fatalf("rate-limit admission: %v", err)
			}
			requireNoAuthority(t, result)
		})
	}
}

func (f *loginFixture) verifyContact(t *testing.T) (Result, *loginContacts) {
	t.Helper()
	store, err := contactcode.NewRedisStore(f.client)
	if err != nil {
		t.Fatal(err)
	}
	sender := &loginSender{}
	codes, err := contactcode.New(contactcode.Config{HashKey: []byte(strings.Repeat("k", 32))}, store, nil, sender)
	if err != nil {
		t.Fatal(err)
	}
	contacts := &loginContacts{proof: &contactproof.Evidence{AccountID: f.users.user.ID, Channel: contactproof.Email, Destination: "original@example.invalid"}}
	f.svc.deps.Codes, f.svc.deps.Contacts = codes, contacts
	handle, _, err := f.svc.RequestCode(t.Context(), "fixture_user", contactcode.ChannelEmail, testCapability('b'), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.svc.VerifyCode(t.Context(), handle, testCapability('b'), sender.code)
	if err != nil {
		t.Fatal(err)
	}
	return result, contacts
}

func TestContactCodeOriginalBindingSurvivesPendingAndMFA(t *testing.T) {
	f := newLoginFixture(t)
	f.users.user.IsMfaEnabled = true
	first, contacts := f.verifyContact(t)
	if first.Issue != nil || first.Preauthentication == "" {
		t.Fatal("contact first factor did not require MFA")
	}
	key, err := pendingKey(first.Preauthentication)
	if err != nil {
		t.Fatal(err)
	}
	var stored Pending
	if err := json.Unmarshal([]byte(f.redis.HGet(key, "payload")), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Contact == nil || stored.Contact.Channel != contactproof.Email || stored.Contact.Destination != contacts.proof.Destination || stored.Issue.CheckPrimaryFactor != nil {
		t.Fatal("private pending state lost original contact binding or serialized an issuance callback")
	}
	result, err := f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
	if err != nil || result.Issue == nil || result.Issue.CheckPrimaryFactor == nil {
		t.Fatalf("MFA did not reconstruct final primary-factor check: %v", err)
	}
	if result.Issue.Evidence.PrimaryMethod != session.MethodContactCode || !result.Issue.Evidence.TOTP {
		t.Fatal("MFA changed the contact authentication method")
	}
	if err := result.Issue.CheckPrimaryFactor(t.Context()); err != nil {
		t.Fatalf("unchanged contact failed final check: %v", err)
	}
	contacts.proof.Destination = "replacement@example.invalid"
	if err := result.Issue.CheckPrimaryFactor(t.Context()); err == nil {
		t.Fatal("MFA restamped the original contact binding with a replacement destination")
	}
}

func TestContactCodeChangedOrRevokedBeforeMFACompletion(t *testing.T) {
	for _, change := range []string{"destination_changed", "evidence_revoked"} {
		t.Run(change, func(t *testing.T) {
			f := newLoginFixture(t)
			f.users.user.IsMfaEnabled = true
			first, contacts := f.verifyContact(t)
			if change == "destination_changed" {
				contacts.proof.Destination = "replacement@example.invalid"
			} else {
				contacts.proof = nil
			}
			result, err := f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("invalidated contact still completed MFA: %v", err)
			}
			requireNoAuthority(t, result)
			if f.users.user.AuthVersion != 7 {
				t.Fatal("test invalidation advanced account authority instead of checking the contact")
			}
		})
	}
}

func TestContactCodeReturnedIssueRechecksCurrentProofAndExcludesCallbackFromJSON(t *testing.T) {
	for _, change := range []string{"destination_changed", "evidence_revoked"} {
		t.Run(change, func(t *testing.T) {
			f := newLoginFixture(t)
			result, contacts := f.verifyContact(t)
			if result.Issue == nil || result.Issue.CheckPrimaryFactor == nil {
				t.Fatal("normal contact verification omitted final issuance check")
			}
			encoded, err := json.Marshal(result.Issue)
			if err != nil || strings.Contains(string(encoded), "CheckPrimaryFactor") {
				t.Fatalf("process-local final check leaked into serialized state: %v", err)
			}
			if err := result.Issue.CheckPrimaryFactor(t.Context()); err != nil {
				t.Fatalf("unchanged proof rejected: %v", err)
			}
			if change == "destination_changed" {
				contacts.proof.Destination = "replacement@example.invalid"
			} else {
				contacts.proof = nil
			}
			if err := result.Issue.CheckPrimaryFactor(t.Context()); err == nil {
				t.Fatal("returned issuance parameters retained revoked contact authority")
			}
		})
	}
}

func TestLoginEquivalentUsernameSpellingsShareTenPerMinuteBudget(t *testing.T) {
	f := newLoginFixture(t)
	limiter, err := ratelimit.NewRedisLimiter(f.client)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.deps.Limiter = limiter
	spellings := []string{"\u06a9\u06cc\u0648\u06cc", "\u0643\u064a\u0624\u0626", "\u0643\u064a\u0648\u0654\u0626"}
	canonical, err := f.users.NormalizeLookup(spellings[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range spellings {
		value, err := f.users.NormalizeLookup(spelling)
		if err != nil || value.Key() != canonical.Key() {
			t.Fatal("test aliases do not name the same admitted lookup identity")
		}
	}
	for attempt := range 10 {
		if err := f.svc.limit(t.Context(), spellings[attempt%len(spellings)], "203.0.113.8"); err != nil {
			t.Fatalf("shared budget rejected attempt %d before ten: %v", attempt+1, err)
		}
	}
	for _, spelling := range spellings {
		if err := f.svc.limit(t.Context(), spelling, "198.51.100.8"); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("equivalent spelling or new source bypassed ten-per-minute budget: %v", err)
		}
	}
	identifierBuckets := 0
	for _, key := range f.redis.Keys() {
		if strings.HasPrefix(key, "rate:login:identifier:") {
			identifierBuckets++
			if strings.Contains(key, spellings[0]) {
				t.Fatal("quota key exposed a plaintext username")
			}
		}
	}
	if identifierBuckets != 1 {
		t.Fatalf("equivalent spellings created %d identifier buckets", identifierBuckets)
	}
}

func TestContactCodePrepareRejectsMissingOriginalBinding(t *testing.T) {
	f := newLoginFixture(t)
	result, err := f.svc.Prepare(t.Context(), session.IssueParams{UserID: f.users.user.ID.String(), AuthVersion: 7, AuthVersionSet: true, DPoPJKT: testCapability('b'), Evidence: session.Evidence{PrimaryMethod: session.MethodContactCode, UV: session.UVNotApplicable, TOTPSet: true, AuthenticatedAt: time.Now().UTC()}})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("synthetic contact evidence without a consumed binding accepted: %v", err)
	}
	requireNoAuthority(t, result)
}

func TestContactCodePendingWithoutOriginalBindingCannotCompleteMFA(t *testing.T) {
	f := newLoginFixture(t)
	f.users.user.IsMfaEnabled = true
	first, _ := f.verifyContact(t)
	key, err := pendingKey(first.Preauthentication)
	if err != nil {
		t.Fatal(err)
	}
	var stored Pending
	if err := json.Unmarshal([]byte(f.redis.HGet(key, "payload")), &stored); err != nil {
		t.Fatal(err)
	}
	stored.Contact = nil
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	f.redis.HSet(key, "payload", string(encoded))
	result, err := f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
	if !errors.Is(err, ErrInvalidCredentials) || f.factor.calls.Load() != 0 {
		t.Fatalf("missing original binding reached TOTP or session authority: %v", err)
	}
	requireNoAuthority(t, result)
}
