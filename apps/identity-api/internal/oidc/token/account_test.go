package token

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestCredentialVersionsPersistThroughCodeAndRotation(t *testing.T) {
	svc, refresh := newTestService(t, nil, nil)
	state := &tokenAccountState{active: true, version: 5}
	svc.cfg.AccountState = state
	verifier := strings.Repeat("v", 50)
	data := AuthorizationCodeData{UserID: "subject", ClientID: testPublicID, RedirectURI: testRedirectURI, CodeChallenge: challengeFor(verifier), AuthVersion: 5, AuthVersionSet: true}
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
	stored, err := refresh.Get(HashSecret(response.RefreshToken))
	if err != nil || stored.AuthVersion != 5 || !stored.AuthVersionSet {
		t.Fatalf("snapshot lost: %+v %v", stored, err)
	}
	form := url.Values{"grant_type": {GrantRefreshToken}, "client_id": {testPublicID}, "refresh_token": {response.RefreshToken}}
	rotated, err := svc.Exchange(context.Background(), form)
	if err != nil {
		t.Fatal(err)
	}
	stored, err = refresh.Get(HashSecret(rotated.RefreshToken))
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
	if _, err := svc.IssueCode(data); err != nil {
		t.Fatal(err)
	}
}

func TestTokenAccountStateUnavailableOrUnstamped(t *testing.T) {
	svc, _ := newTestService(t, nil, nil)
	code, verifier := issueTestCode(t, svc)
	state := &tokenAccountState{active: true}
	svc.cfg.AccountState = state
	_, err := svc.Exchange(context.Background(), authCodeForm(code, verifier))
	wantTokenError(t, err, ErrCodeInvalidGrant)
	if _, err := svc.IssueCode(AuthorizationCodeData{UserID: "user-1"}); !errors.Is(err, session.ErrAccountIneligible) {
		t.Fatal(err)
	}
	state.err = errors.New("db down")
	_, err = svc.withAccount(context.Background(), "user-1", 0, true, func() (*Response, error) { t.Fatal("issued during outage"); return nil, nil })
	wantTokenError(t, err, ErrCodeServerError)
}

func TestRefreshRotationIsCompareAndSet(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	if err := store.Save("hash", RefreshTokenData{Status: StatusActive, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- store.MarkRotated("hash") }()
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
			data := AuthorizationCodeData{UserID: "subject", ClientID: testPublicID, RedirectURI: testRedirectURI, CodeChallenge: challengeFor(verifier), AuthVersionSet: true}
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
		data := AuthorizationCodeData{UserID: "subject", ClientID: testPublicID, RedirectURI: testRedirectURI, CodeChallenge: challengeFor(verifier), AuthVersionSet: true}
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
