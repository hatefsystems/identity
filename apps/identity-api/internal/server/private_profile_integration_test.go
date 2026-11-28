//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Catalog membership is covered with the real importer in profile integration;
// this fixture isolates the HTTP/session/transaction composition at one revision.
type privateHTTPCatalog struct{}

func (privateHTTPCatalog) ValidateForUpdate(_ context.Context, _ pgx.Tx, in geography.LocationInput) (geography.ValidatedLocation, error) {
	if in.Country != "IR" || in.ProvinceID != "7001" || in.LocalityID != "7002" {
		return geography.ValidatedLocation{}, geography.ErrInvalid
	}
	return geography.ValidatedLocation{LocationInput: in, CatalogRevision: "1"}, nil
}

type privateCommitFault struct {
	*pgxpool.Pool
	commitFirst      bool
	explicitRollback bool
	begins, commits  int
}

func (f *privateCommitFault) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	f.begins++
	tx, err := f.Pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return privateCommitFaultTx{Tx: tx, fault: f}, nil
}

type privateCommitFaultTx struct {
	pgx.Tx
	fault *privateCommitFault
}

func (tx privateCommitFaultTx) Commit(ctx context.Context) error {
	tx.fault.commits++
	if tx.fault.explicitRollback {
		// Force PostgreSQL to acknowledge ROLLBACK in response to COMMIT.
		_, _ = tx.Exec(ctx, "SELECT 1/0")
		return tx.Tx.Commit(ctx)
	}
	if tx.fault.commitFirst {
		if err := tx.Tx.Commit(ctx); err != nil {
			return err
		}
	}
	// With no COMMIT, the service's deferred cleanup rolls the edit back.
	return io.ErrUnexpectedEOF
}

func TestPrivateHTTPRealPostgresSessionAndRevisionIntegration(t *testing.T) {
	ctx, pool, _ := phoneIntegrationServices(t)
	email := uuid.NewString() + "@private-http.invalid"
	u, err := db.New(pool).CreateUser(ctx, db.CreateUserParams{Email: &email, Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET lifecycle_revision=9007199254740993,display_name='Independent public' WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	_, manager, browser := newSessionTestServer(t)
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x66}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	private, err := profile.NewPrivate(pool, cipher, nil, privateHTTPCatalog{}, manager)
	if err != nil {
		t.Fatal(err)
	}
	public, err := profile.New(pool, cipher)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.PortalOrigin = browser.origin
	recorder := &profileAuditRecorder{}
	deps := Deps{Profile: public, PrivateProfile: private, SessionManager: manager, DPoPValidator: browser.validator, AuditRecorder: recorder}
	srv := New(cfg, nil, deps)
	current, cookies := browser.issueSession(t, manager, session.IssueParams{UserID: u.ID.String(), AuthVersion: u.AuthVersion, AuthVersionSet: true})
	send := func(srv *Server, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		browser.authorize(t, r, current, cookies...)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		return send(srv, method, path, body)
	}
	read := request(http.MethodGet, "/api/v1/users/me/private-data", "")
	var result profile.PrivateSnapshot
	if read.Code != 200 || json.Unmarshal(read.Body.Bytes(), &result) != nil || result.PrivateData != nil || result.Username != nil || result.LifecycleRevision != "9007199254740993" {
		t.Fatal("real HTTP uninitialized private snapshot was not null/exact")
	}
	full := `{"expected_revision":"9007199254740993","given_name":"\u0639\u0644\u06cc","family_name":"\u0645\u0624\u0645\u0646\u06cc","birthday":{"calendar":"gregorian","date":"2000-03-20"},"gender":"female","location":{"country":"IR","province_id":"7001","locality_id":"7002"}}`
	first := request(http.MethodPatch, "/api/v1/users/me/private-data", full)
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &result) != nil || result.PrivateData == nil || result.LifecycleRevision != "9007199254740994" {
		t.Fatal("real private HTTP first save failed")
	}
	var ciphertext []byte
	if err := pool.QueryRow(ctx, `SELECT details_encrypted FROM private_profile WHERE account_id=$1`, u.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	noop := request(http.MethodPatch, "/api/v1/users/me/private-data", `{"expected_revision":"9007199254740994","gender":"female"}`)
	if noop.Code != 200 {
		t.Fatal("real private HTTP no-op failed")
	}
	var stable []byte
	if err := pool.QueryRow(ctx, `SELECT details_encrypted FROM private_profile WHERE account_id=$1`, u.ID).Scan(&stable); err != nil || !bytes.Equal(ciphertext, stable) {
		t.Fatal("real HTTP no-op changed encrypted bytes")
	}
	stale := request(http.MethodPatch, "/api/v1/users/me/private-data", `{"expected_revision":"9007199254740993","gender":"female"}`)
	if stale.Code != 409 || !strings.Contains(stale.Body.String(), "profile_conflict") {
		t.Fatal("real HTTP stale no-op bypassed revision")
	}
	bootstrap := request(http.MethodGet, "/api/v1/users/me", "")
	if bootstrap.Code != 200 || strings.Contains(bootstrap.Body.String(), "private_data") || strings.Contains(bootstrap.Body.String(), "given_name") || strings.Contains(bootstrap.Body.String(), "birthday") {
		t.Fatal("routine bootstrap exposed private attributes")
	}
	for _, scenario := range []struct {
		name             string
		commitFirst      bool
		explicitRollback bool
		wantError        string
	}{
		{name: "acknowledged rollback", explicitRollback: true, wantError: "temporarily_unavailable"},
		{name: "lost acknowledgement before commit", wantError: "outcome_unknown"},
		{name: "lost acknowledgement after commit", commitFirst: true, wantError: "outcome_unknown"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fault := &privateCommitFault{Pool: pool, commitFirst: scenario.commitFirst, explicitRollback: scenario.explicitRollback}
			service, err := profile.NewPrivate(fault, cipher, nil, privateHTTPCatalog{}, manager)
			if err != nil {
				t.Fatal(err)
			}
			faultDeps := deps
			faultDeps.PrivateProfile = service
			const path = "/api/v1/users/me/private-data"
			const edit = `{"expected_revision":"9007199254740994","gender":"male"}`
			response := send(New(cfg, nil, faultDeps), http.MethodPatch, path, edit)
			var failure map[string]string
			if response.Code != http.StatusServiceUnavailable || json.Unmarshal(response.Body.Bytes(), &failure) != nil ||
				len(failure) != 1 || failure["error"] != scenario.wantError ||
				response.Header().Get("Cache-Control") != "private, no-store" || len(response.Result().Cookies()) != 0 ||
				fault.begins != 1 || fault.commits != 1 || len(recorder.events) != 1 {
				t.Fatal("unconfirmed edit leaked a snapshot, retried, or emitted success audit")
			}

			wantRevision, wantGender, wantIntents := "9007199254740994", profile.GenderFemale, 1
			if scenario.commitFirst {
				wantRevision, wantGender, wantIntents = "9007199254740995", profile.GenderMale, 2
			}
			read := request(http.MethodGet, path, "")
			var after profile.PrivateSnapshot
			if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &after) != nil || after.PrivateData == nil ||
				after.LifecycleRevision != wantRevision || after.PrivateData.Gender != wantGender ||
				after.PrivateData.Birthday != result.PrivateData.Birthday {
				t.Fatal("fresh GET did not reconcile the actual database outcome")
			}
			var intents int
			var stored []byte
			var storedRevision string
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1`, u.ID).Scan(&intents); err != nil || intents != wantIntents {
				t.Fatal("private edit did not commit its single intent atomically")
			}
			if err := pool.QueryRow(ctx, `SELECT details_encrypted, profile_revision::text FROM private_profile WHERE account_id=$1`, u.ID).Scan(&stored, &storedRevision); err != nil ||
				storedRevision != wantRevision || bytes.Equal(ciphertext, stored) == scenario.commitFirst {
				t.Fatal("private storage did not match the actual outcome")
			}
			if scenario.commitFirst {
				if replay := request(http.MethodPatch, path, edit); replay.Code != http.StatusConflict || len(recorder.events) != 1 {
					t.Fatal("old revision was accepted after lost commit acknowledgement")
				}
			}
		})
	}
	if _, err := manager.RevokeByID(ctx, current.UserID, current.ID); err != nil {
		t.Fatal(err)
	}
	denied := request(http.MethodGet, "/api/v1/users/me/private-data", "")
	if denied.Code != 401 {
		t.Fatal("real private HTTP kept individually revoked session authority")
	}
}
