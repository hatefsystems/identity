package token

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type tokenAccountState struct {
	version int64
	active  bool
	err     error
}

func (a *tokenAccountState) Validate(_ context.Context, _ string, version int64) error {
	if a.err != nil {
		return a.err
	}
	if !a.active || a.version != version {
		return session.ErrAccountIneligible
	}
	return nil
}
func (a *tokenAccountState) WithActive(ctx context.Context, id string, version int64, fn func() error) error {
	if err := a.Validate(ctx, id, version); err != nil {
		return err
	}
	return fn()
}
func (*tokenAccountState) Epoch(context.Context) (int64, error) { return 1, nil }

type tokenEvidenceAccountState struct {
	*tokenAccountState
	required bool
}

func (a *tokenEvidenceAccountState) ValidateEvidence(ctx context.Context, id string, version int64, kind session.Kind, evidence session.Evidence) error {
	if err := a.Validate(ctx, id, version); err != nil {
		return err
	}
	if kind != session.KindAuthenticated || (a.required && (!evidence.TOTPSet || !evidence.TOTP || evidence.AuthenticatedAt.IsZero())) {
		return session.ErrAccountIneligible
	}
	return nil
}

func (a *tokenEvidenceAccountState) WithActiveEvidence(ctx context.Context, id string, version int64, kind session.Kind, evidence session.Evidence, fn func() error) error {
	if err := a.ValidateEvidence(ctx, id, version, kind, evidence); err != nil {
		return err
	}
	return fn()
}

func TestTokenBoundariesRequireCurrentMFAEvidence(t *testing.T) {
	for _, evidence := range []session.Evidence{
		{},
		{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, TOTPSet: true, AuthenticatedAt: time.Now().UTC()},
		{PrimaryMethod: session.MethodContactCode, UV: session.UVNotApplicable, TOTPSet: true, AuthenticatedAt: time.Now().UTC()},
		{PrimaryMethod: session.MethodPasskey, UV: session.UVVerified, TOTPSet: true, AuthenticatedAt: time.Now().UTC()},
	} {
		svc, store := newTestService(t, nil, nil)
		accounts := &tokenEvidenceAccountState{tokenAccountState: &tokenAccountState{active: true}}
		svc.cfg.AccountState = accounts
		userID := uuid.NewString()
		seedTestSession(svc, userID, "evidence-session", 0)
		sessions := svc.cfg.Sessions.(*testSessions)
		parent := sessions.values["evidence-session"]
		parent.Evidence = evidence
		sessions.values[parent.ID] = parent
		verifier := strings.Repeat("v", 50)
		data := AuthorizationCodeData{UserID: userID, SessionID: parent.ID, AuthVersionSet: true,
			ClientID: testPublicID, RedirectURI: testRedirectURI, Scope: "openid", CodeChallenge: challengeFor(verifier)}
		code, err := svc.IssueCode(data)
		if err != nil {
			t.Fatal(err)
		}
		oldCode, err := svc.IssueCode(data)
		if err != nil {
			t.Fatal(err)
		}
		response, err := svc.Exchange(t.Context(), authCodeForm(code, verifier))
		if err != nil {
			t.Fatal(err)
		}
		validator, err := NewAccessValidator(AccessValidatorConfig{Issuer: testIssuer, Keys: svc.keys.(VerificationKeys), Clients: svc.registry,
			Grants: store, Sessions: sessions, Accounts: accounts})
		if err != nil {
			t.Fatal(err)
		}
		accounts.required = true
		if _, err := svc.IssueCode(data); !errors.Is(err, session.ErrAccountIneligible) {
			t.Fatalf("MFA code issuance bypass method=%q: %v", evidence.PrimaryMethod, err)
		}
		if denied, err := svc.Exchange(t.Context(), authCodeForm(oldCode, verifier)); denied != nil || wantTokenError(t, err, ErrCodeInvalidGrant) != 400 {
			t.Fatal("MFA auth-code exchange returned tokens")
		}
		form := url.Values{"grant_type": {GrantRefreshToken}, "client_id": {testPublicID}, "refresh_token": {response.RefreshToken}}
		if denied, err := svc.Exchange(t.Context(), form); denied != nil || wantTokenError(t, err, ErrCodeInvalidGrant) != 400 {
			t.Fatal("MFA refresh returned tokens")
		}
		if _, err := validator.Validate(t.Context(), response.AccessToken, testIssuer); !errors.Is(err, ErrInactiveToken) {
			t.Fatalf("MFA access-use bypass: %v", err)
		}
		if got, err := sessions.LookupByID(t.Context(), userID, parent.ID); err != nil || got.Evidence != evidence {
			t.Fatalf("token boundary fabricated evidence: %+v %v", got.Evidence, err)
		}
	}
}

func TestTokenRefreshPreservesAuthenticationTimeAndUnknownEvidence(t *testing.T) {
	for _, known := range []bool{false, true} {
		svc, _ := newTestService(t, nil, nil)
		now := time.Now().UTC()
		svc.now = func() time.Time { return now }
		sessions := svc.cfg.Sessions.(*testSessions)
		parent := sessions.values["session-1"]
		if known {
			parent.Evidence = session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, TOTP: true, TOTPSet: true, AuthenticatedAt: now.Add(-time.Hour)}
			sessions.values[parent.ID] = parent
		}
		for round := range 2 {
			code, verifier := issueTestCode(t, svc)
			response, err := svc.Exchange(t.Context(), authCodeForm(code, verifier))
			if err != nil {
				t.Fatal(err)
			}
			claims := decodeTestClaims(t, response.IDToken)
			if known {
				if got := claims["auth_time"]; got == nil || got.(json.Number).String() != strconv.FormatInt(parent.Evidence.AuthenticatedAt.Unix(), 10) {
					t.Fatalf("auth_time advanced on round %d: %v", round, got)
				}
			} else if _, exists := claims["auth_time"]; exists {
				t.Fatal("unknown auth_time was synthesized")
			}
			form := url.Values{"grant_type": {GrantRefreshToken}, "client_id": {testPublicID}, "refresh_token": {response.RefreshToken}}
			if _, err := svc.Exchange(t.Context(), form); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Minute)
			if current, err := sessions.LookupByID(t.Context(), parent.UserID, parent.ID); err != nil || current.Evidence != parent.Evidence {
				t.Fatalf("refresh changed evidence: %+v %v", current.Evidence, err)
			}
		}
	}
}

func TestCredentialVersionsPersistThroughCodeAndRotation(t *testing.T) {
	svc, refresh := newTestService(t, nil, nil)
	state := &tokenAccountState{active: true, version: 5}
	svc.cfg.AccountState = state
	verifier := strings.Repeat("v", 50)
	seedTestSession(svc, "subject", "account-session", 5)
	data := AuthorizationCodeData{UserID: "subject", SessionID: "account-session", ClientID: testPublicID, RedirectURI: testRedirectURI, CodeChallenge: challengeFor(verifier), AuthVersion: 5, AuthVersionSet: true}
	code, err := svc.IssueCode(data)
	if err != nil {
		t.Fatal(err)
	}
	oldCode, err := svc.IssueCode(data)
	if err != nil {
		t.Fatal(err)
	}
	response, err := svc.Exchange(context.Background(), authCodeForm(code, verifier))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := refresh.Get(context.Background(), HashSecret(response.RefreshToken))
	if err != nil || stored.AuthVersion != 5 || !stored.AuthVersionSet {
		t.Fatalf("snapshot lost: %+v %v", stored, err)
	}
	form := url.Values{"grant_type": {GrantRefreshToken}, "client_id": {testPublicID}, "refresh_token": {response.RefreshToken}}
	rotated, err := svc.Exchange(context.Background(), form)
	if err != nil {
		t.Fatal(err)
	}
	stored, err = refresh.Get(context.Background(), HashSecret(rotated.RefreshToken))
	if err != nil || stored.AuthVersion != 5 {
		t.Fatalf("rotation restamped: %+v %v", stored, err)
	}
	form.Set("refresh_token", rotated.RefreshToken)
	state.active, state.version = false, 6
	_, err = svc.Exchange(context.Background(), form)
	wantTokenError(t, err, ErrCodeInvalidGrant)
	state.active, state.version = true, 7
	_, err = svc.Exchange(context.Background(), form)
	wantTokenError(t, err, ErrCodeInvalidGrant)
	_, err = svc.Exchange(context.Background(), authCodeForm(oldCode, verifier))
	wantTokenError(t, err, ErrCodeInvalidGrant)
	if _, err := svc.IssueCode(data); !errors.Is(err, session.ErrAccountIneligible) {
		t.Fatalf("stale session issued code: %v", err)
	}
	data.AuthVersion = 7
	data.SessionID = "new-account-session"
	seedTestSession(svc, "subject", data.SessionID, 7)
	if _, err := svc.IssueCode(data); err != nil {
		t.Fatal(err)
	}
}

func TestTokenAccountStateUnavailableOrUnstamped(t *testing.T) {
	svc, _ := newTestService(t, nil, nil)
	code, verifier := issueTestCode(t, svc)
	state := &tokenAccountState{active: true, version: 1}
	svc.cfg.AccountState = state
	_, err := svc.Exchange(context.Background(), authCodeForm(code, verifier))
	wantTokenError(t, err, ErrCodeInvalidGrant)
	if _, err := svc.IssueCode(AuthorizationCodeData{UserID: "user-1"}); !errors.Is(err, session.ErrAccountIneligible) {
		t.Fatal(err)
	}
	state.err = errors.New("db down")
	_, err = svc.withAccount(context.Background(), "user-1", "session-1", 0, true, func() (*Response, error) { t.Fatal("issued during outage"); return nil, nil })
	wantTokenError(t, err, ErrCodeServerError)
}

func TestRefreshRotationIsCompareAndSet(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	grant, data := storeFixture("family", "user")
	if err := store.CreateGrant(context.Background(), grant, "hash", data); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- store.Rotate(context.Background(), "hash", data, "next", data) }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("rotation winners = %d", winners)
	}
}

type tokenAccountBarrier struct {
	*tokenAccountState
	entered chan struct{}
	release chan struct{}
}

func (b *tokenAccountBarrier) WithActive(ctx context.Context, id string, version int64, fn func() error) error {
	close(b.entered)
	select {
	case <-b.release:
		return b.tokenAccountState.WithActive(ctx, id, version, fn)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestTokenIssuanceCannotRestampAcrossConcurrentReactivation(t *testing.T) {
	for _, operation := range []string{"issue code", "exchange code", "rotate refresh"} {
		t.Run(operation, func(t *testing.T) {
			svc, _ := newTestService(t, nil, nil)
			state := &tokenAccountState{active: true}
			svc.cfg.AccountState = state
			verifier := strings.Repeat("v", 50)
			seedTestSession(svc, "subject", "account-session", 0)
			data := AuthorizationCodeData{UserID: "subject", SessionID: "account-session", ClientID: testPublicID, RedirectURI: testRedirectURI, CodeChallenge: challengeFor(verifier), AuthVersionSet: true}
			code, err := svc.IssueCode(data)
			if err != nil {
				t.Fatal(err)
			}
			form := authCodeForm(code, verifier)
			if operation == "rotate refresh" {
				response, err := svc.Exchange(context.Background(), form)
				if err != nil {
					t.Fatal(err)
				}
				form = url.Values{"grant_type": {GrantRefreshToken}, "client_id": {testPublicID}, "refresh_token": {response.RefreshToken}}
			}
			barrier := &tokenAccountBarrier{tokenAccountState: state, entered: make(chan struct{}), release: make(chan struct{})}
			svc.cfg.AccountState = barrier
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				var err error
				if operation == "issue code" {
					var code string
					code, err = svc.IssueCodeContext(ctx, data)
					if code != "" {
						err = errors.New("pre-ban session minted a code")
					}
				} else {
					var response *Response
					response, err = svc.Exchange(ctx, form)
					if response != nil {
						err = errors.New("pre-ban credential minted tokens")
					}
				}
				result <- err
			}()
			select {
			case <-barrier.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			state.version = 2
			close(barrier.release)
			err = <-result
			if operation == "issue code" {
				if !errors.Is(err, session.ErrAccountIneligible) {
					t.Fatal(err)
				}
			} else {
				wantTokenError(t, err, ErrCodeInvalidGrant)
			}
		})
	}
}

func TestTokenCutoffAcrossIndependentInstances(t *testing.T) {
	state := &tokenAccountState{active: true}
	var services []*Service
	var codes, refreshes []url.Values
	for range 2 {
		svc, _ := newTestService(t, nil, nil)
		svc.cfg.AccountState = state
		verifier := strings.Repeat("v", 50)
		seedTestSession(svc, "subject", "account-session", 0)
		data := AuthorizationCodeData{UserID: "subject", SessionID: "account-session", ClientID: testPublicID, RedirectURI: testRedirectURI, CodeChallenge: challengeFor(verifier), AuthVersionSet: true}
		code, err := svc.IssueCode(data)
		if err != nil {
			t.Fatal(err)
		}
		response, err := svc.Exchange(context.Background(), authCodeForm(code, verifier))
		if err != nil {
			t.Fatal(err)
		}
		oldCode, err := svc.IssueCode(data)
		if err != nil {
			t.Fatal(err)
		}
		services = append(services, svc)
		codes = append(codes, authCodeForm(oldCode, verifier))
		refreshes = append(refreshes, url.Values{"grant_type": {GrantRefreshToken}, "client_id": {testPublicID}, "refresh_token": {response.RefreshToken}})
	}
	state.active, state.version = false, 1
	for i, svc := range services {
		_, err := svc.Exchange(context.Background(), refreshes[i])
		wantTokenError(t, err, ErrCodeInvalidGrant)
	}
	state.active, state.version = true, 2
	for i, svc := range services {
		for _, form := range []url.Values{codes[i], refreshes[i]} {
			response, err := svc.Exchange(context.Background(), form)
			wantTokenError(t, err, ErrCodeInvalidGrant)
			if response != nil {
				t.Fatal("reactivation revived a credential on another instance")
			}
		}
	}
}
