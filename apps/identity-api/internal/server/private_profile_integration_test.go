//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

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

func (privateHTTPCatalog) Validate(_ context.Context, in geography.LocationInput) (geography.ValidatedLocation, error) {
	if in.Country != "IR" || in.ProvinceID != "7001" || in.LocalityID != "7002" {
		return geography.ValidatedLocation{}, geography.ErrInvalid
	}
	return geography.ValidatedLocation{LocationInput: in, CatalogRevision: "1"}, nil
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
	srv := New(cfg, nil, Deps{Profile: public, PrivateProfile: private, SessionManager: manager, DPoPValidator: browser.validator})
	current, cookies := browser.issueSession(t, manager, session.IssueParams{UserID: u.ID.String(), AuthVersion: u.AuthVersion, AuthVersionSet: true})
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		browser.authorize(t, r, current, cookies...)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
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
	if _, err := manager.RevokeByID(ctx, current.UserID, current.ID); err != nil {
		t.Fatal(err)
	}
	denied := request(http.MethodGet, "/api/v1/users/me/private-data", "")
	if denied.Code != 401 {
		t.Fatal("real private HTTP kept individually revoked session authority")
	}
}
