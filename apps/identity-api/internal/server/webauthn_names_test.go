package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type webAuthnNameAudit struct{ events []audit.Event }

func (a *webAuthnNameAudit) Record(_ context.Context, event audit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func TestWebAuthnRenameKeyRequiresStepUpAndReturnsSafeProjection(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)
	row := fx.seedCredential([]byte("owned-passkey"))
	fx.creds.byUser[fx.user.ID][0].Name = "Old label"
	sess, cookies := fx.browser.issueSession(t, fx.mgr, session.IssueParams{UserID: fx.user.ID.String()})
	path := "/api/v1/auth/webauthn/keys/" + base64.RawURLEncoding.EncodeToString(row.ID)
	if rec := fx.do(http.MethodPatch, path, []byte(`{"name":"New label"}`), cookies); rec.Code != http.StatusForbidden {
		t.Fatalf("rename without step-up: %d", rec.Code)
	}
	recorder := &webAuthnNameAudit{}
	fx.srv.deps.AuditRecorder = recorder
	rec := fx.doWithGrantBody(t, http.MethodPatch, path, []byte(`{"name":"  New label  "}`), cookies, sess)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body.String())
	}
	var response webauthnCredentialResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Name != "New label" || response.ID != base64.RawURLEncoding.EncodeToString(row.ID) {
		t.Fatalf("named projection: %+v", response)
	}
	for _, private := range []string{"public_key", "user_id", "webauthn_user_handle"} {
		if bytes.Contains(rec.Body.Bytes(), []byte(`"`+private+`"`)) {
			t.Fatalf("rename projection exposes %s", private)
		}
	}
	if len(recorder.events) != 1 || recorder.events[0].EventType != webauthnRenamedEvent || recorder.events[0].Security != nil {
		t.Fatal("cosmetic rename must be audit-only")
	}
	payload, err := json.Marshal(recorder.events[0].Payload)
	if err != nil || bytes.Contains(payload, []byte("label")) || bytes.Contains(payload, row.ID) {
		t.Fatalf("name/credential ID entered audit payload: %s %v", payload, err)
	}
	listed := fx.do(http.MethodGet, "/api/v1/auth/webauthn/keys", nil, cookies)
	var keys []webauthnCredentialResponse
	if json.Unmarshal(listed.Body.Bytes(), &keys) != nil || len(keys) != 1 || keys[0].Name != "New label" {
		t.Fatalf("list lost credential name: %s", listed.Body.String())
	}
	cleared := fx.doWithGrantBody(t, http.MethodPatch, path, []byte(`{"name":""}`), cookies, sess)
	if cleared.Code != http.StatusOK || fx.creds.byUser[fx.user.ID][0].Name != "" {
		t.Fatalf("clear name: %d %s", cleared.Code, cleared.Body.String())
	}
	if rec := fx.doWithGrant(t, http.MethodDelete, path, cookies, sess); rec.Code != http.StatusConflict || decodeWebAuthnError(t, rec).Error != "last_credential" {
		t.Fatalf("rename weakened final-key protection: %d %s", rec.Code, rec.Body.String())
	}
}

func TestWebAuthnNameBodiesAreStrict(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)
	row := fx.seedCredential([]byte("owned"))
	sess, cookies := fx.browser.issueSession(t, fx.mgr, session.IssueParams{UserID: fx.user.ID.String()})
	for _, path := range []string{"/api/v1/auth/webauthn/register/generate-options", "/api/v1/auth/webauthn/keys/" + base64.RawURLEncoding.EncodeToString(row.ID)} {
		method := http.MethodPost
		if strings.Contains(path, "/keys/") {
			method = http.MethodPatch
		}
		for _, body := range []string{`null`, `[]`, `{"unknown":"x"}`, `{"name":null}`, `{"name":1}`, `{"name":"x","extra":true}`, `{"name":"x","name":"y"}`, `{"name":"bad\nname"}`, `{"name":"\ud800"}`, `{"name":"\udc00"}`, `{"name":"\udc00\ud800"}`, `{"name":"` + strings.Repeat("x", 81) + `"}`} {
			rec := fx.doWithGrantBody(t, method, path, []byte(body), cookies, sess)
			if rec.Code != http.StatusBadRequest || decodeWebAuthnError(t, rec).Error != "invalid_request" {
				t.Fatalf("%s invalid name body: %d %s", method, rec.Code, rec.Body.String())
			}
		}
		rec := fx.doWithGrantBody(t, method, path, []byte(`{}`), cookies, sess)
		want := http.StatusOK
		if method == http.MethodPatch {
			want = http.StatusBadRequest
		}
		if rec.Code != want {
			t.Fatalf("%s missing name: %d want %d", method, rec.Code, want)
		}
		for _, body := range []string{`{"name":"\ud83d\udd11"}`, `{"name":"\ufffd"}`, "{\"name\":\"\ufffd\"}"} {
			if rec := fx.doWithGrantBody(t, method, path, []byte(body), cookies, sess); rec.Code != http.StatusOK {
				t.Fatalf("%s valid Unicode name: %d %s", method, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestWebAuthnRenameForeignAndMissingKeysAreIndistinguishable(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)
	sess, cookies := fx.browser.issueSession(t, fx.mgr, session.IssueParams{UserID: fx.user.ID.String()})
	foreignID := uuid.New()
	fx.creds.byUser[foreignID] = []db.WebauthnCredential{{ID: []byte("foreign"), UserID: foreignID, Name: "Unchanged"}}
	for _, id := range []string{base64.RawURLEncoding.EncodeToString([]byte("foreign")), base64.RawURLEncoding.EncodeToString([]byte("absent")), "-"} {
		rec := fx.doWithGrantBody(t, http.MethodPatch, "/api/v1/auth/webauthn/keys/"+id, []byte(`{"name":"Not allowed"}`), cookies, sess)
		if rec.Code != http.StatusNotFound || decodeWebAuthnError(t, rec).Error != "credential_not_found" {
			t.Fatalf("foreign/missing/malformed ID: %d %s", rec.Code, rec.Body.String())
		}
	}
	if fx.creds.byUser[foreignID][0].Name != "Unchanged" {
		t.Fatal("foreign credential changed")
	}
}

func TestWebAuthnLoginCapturesInitiatingBrowserKeyInSession(t *testing.T) {
	fx := newWebAuthnTestServer(t)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         int64(webauthncose.P256), XCoord: point[1:33], YCoord: point[33:],
	})
	if err != nil {
		t.Fatal(err)
	}
	user := fx.user
	user.WebauthnUserHandle = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	fx.users.byID[user.ID] = user
	credentialID := []byte("real-passkey-credential")
	fx.creds.byUser[user.ID] = []db.WebauthnCredential{{ID: credentialID, UserID: user.ID, PublicKey: cose, UserPresent: true, UserVerified: true}}
	options := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", []byte(`{}`), nil)
	var begin struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if options.Code != http.StatusOK || json.Unmarshal(options.Body.Bytes(), &begin) != nil || begin.PublicKey.Challenge == "" {
		t.Fatalf("login options: %d %s", options.Code, options.Body.String())
	}
	clientData := clientDataJSONFor(t, "webauthn.get", begin.PublicKey.Challenge)
	clientHash := sha256.Sum256(clientData)
	authData := syntheticAuthData()
	digest := sha256.Sum256(append(append([]byte(nil), authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id": enc(credentialID), "rawId": enc(credentialID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": enc(clientData), "authenticatorData": enc(authData), "signature": enc(signature), "userHandle": enc(user.WebauthnUserHandle)},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/auth/webauthn/login/verify"
	foreign := newPortalTestClient(t, fx.browser.origin)
	foreign.validator = fx.browser.validator
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	foreign.sign(t, req)
	rec := httptest.NewRecorder()
	fx.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || decodeWebAuthnError(t, rec).Error != "invalid_credentials" {
		t.Fatalf("foreign browser completed login: %d %s", rec.Code, rec.Body.String())
	}
	rec = fx.do(http.MethodPost, path, body, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("wrong-key attempt burned login: %d %s", rec.Code, rec.Body.String())
	}
	authenticated := httptest.NewRequest(http.MethodGet, "/", nil)
	addCookies(authenticated, rec.Result().Cookies())
	current, err := fx.mgr.Resolve(authenticated)
	if err != nil || current.DPoPJKT != fx.browser.jkt || current.UserID != fx.user.ID.String() || !current.AuthVersionSet {
		t.Fatalf("issued session lost captured authority: %+v %v", current, err)
	}
	if rec := fx.do(http.MethodPost, path, body, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("successful login assertion replayed: %d", rec.Code)
	}
}
