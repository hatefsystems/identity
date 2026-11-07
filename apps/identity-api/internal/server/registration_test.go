package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/registration"
)

func registrationTestBody(operation string) string {
	if operation == "start" {
		return `{"email":"person@example.com","phone":"+989123456789"}`
	}
	key := "capability"
	if operation == "email/verify" {
		key = "token"
	}
	body := map[string]any{"attempt_id": uuid.NewString(), key: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))}
	if operation == "phone/verify" {
		body["verification_id"] = body[key]
		body["code"] = "000123"
	}
	if operation == "" {
		body["credential"] = map[string]any{"id": "AQ", "rawId": "AQ", "type": "public-key", "response": map[string]any{"clientDataJSON": "AQ", "attestationObject": "AQ", "transports": []string{"internal"}}, "clientExtensionResults": map[string]any{"credProps": map[string]bool{"rk": true}}}
	}
	encoded, _ := json.Marshal(body)
	return string(encoded)
}
func TestRegistrationDeclaredFieldsAndAuthority(t *testing.T) {
	for _, operation := range []string{"start", "email/resend", "email/verify", "phone/send", "phone/verify", "passkey/options", "", "result"} {
		t.Run(operation, func(t *testing.T) {
			body := registrationTestBody(operation)
			if _, err := readRegistrationRequest(httptest.NewRequest(http.MethodPost, registrationPath, strings.NewReader(body)), operation); err != nil {
				t.Fatal("declared body rejected", err)
			}
			for _, bad := range []string{strings.TrimSuffix(body, "}") + `,"user_id":"` + uuid.NewString() + `"}`, strings.TrimSuffix(body, "}") + `,"roles":[]}`, strings.TrimSuffix(body, "}") + `,"email_verified":true}`, strings.Replace(body, `"attempt_id"`, `"Attempt_ID"`, 1), strings.Replace(body, `"capability"`, `"Capability"`, 1)} {
				if bad == body {
					continue
				}
				if _, err := readRegistrationRequest(httptest.NewRequest(http.MethodPost, registrationPath, strings.NewReader(bad)), operation); err == nil {
					t.Fatal("undeclared authority accepted")
				}
			}
			if _, err := readRegistrationRequest(httptest.NewRequest(http.MethodPost, registrationPath+"?token=secret", strings.NewReader(body)), operation); err == nil {
				t.Fatal("query authority accepted")
			}
		})
	}
	for _, body := range []string{`{"email":"\ud800@example.com","phone":"+989123456789"}`, `{"email":"a@example.com","email":"b@example.com","phone":"+989123456789"}`} {
		if _, err := readRegistrationRequest(httptest.NewRequest(http.MethodPost, registrationPath, strings.NewReader(body)), "start"); err == nil {
			t.Fatal("malformed Unicode/duplicate accepted")
		}
	}
}
func TestRegistrationAllRoutesOriginDPoPNoStoreAndDisabled(t *testing.T) {
	client := newPortalTestClient(t, testPortalOrigin)
	s := New(config.Config{PortalOrigin: testPortalOrigin}, nil, Deps{Registration: &registration.Service{}, DPoPValidator: client.validator})
	for _, operation := range []string{"start", "email/resend", "email/verify", "phone/send", "phone/verify", "passkey/options", "", "result"} {
		path := registrationPath
		if operation != "" {
			path += "/" + operation
		}
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(registrationTestBody(operation)))
		client.prepare(request)
		boundaryServe(t, s, request, http.StatusUnauthorized)
		request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(registrationTestBody(operation)))
		client.prepare(request)
		request.Header.Set("Origin", "https://attacker.example.com")
		boundaryServe(t, s, request, http.StatusForbidden)
	}
	disabled := New(config.Config{PortalOrigin: testPortalOrigin}, nil, Deps{})
	request := httptest.NewRequest(http.MethodPost, registrationPath+"/start", strings.NewReader(registrationTestBody("start")))
	client.prepare(request)
	boundaryServe(t, disabled, request, http.StatusNotFound)
}
func TestRegistrationErrorsNeverExposeDiagnostics(t *testing.T) {
	s := &Server{}
	for _, err := range []error{errors.New("SQL private@example.com capability secret"), registration.ErrConflict, registration.ErrRestartRequired, registration.ErrOutcomeUnknown} {
		w := httptest.NewRecorder()
		s.writeRegistrationError(w, err)
		if strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "secret") {
			t.Fatal("raw diagnostic exposed")
		}
	}
}
