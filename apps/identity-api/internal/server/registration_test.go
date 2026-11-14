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
		return `{"email":"person@example.com","phone":"+989123456789","username":"\u0639\u0644\u06cc"}`
	}
	if operation == "validate" {
		return `{"stage":"username","registration":{"username":"\u0639\u0644\u06cc"}}`
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
	for _, operation := range []string{"validate", "start", "email/resend", "email/verify", "phone/send", "phone/verify", "passkey/options", "", "result"} {
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
	for _, operation := range []string{"validate", "start", "email/resend", "email/verify", "phone/send", "phone/verify", "passkey/options", "", "result"} {
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

func TestRegistrationUsernameWireRejectsCallerAuthorityAndDeferredFields(t *testing.T) {
	for _, body := range []string{
		`{"stage":"full","registration":{"username":"\u0639\u0644\u06cc"}}`,
		`{"stage":"username","registration":{"username":"\u0639\u0644\u06cc","username_security":"forged"}}`,
		`{"stage":"username","registration":{"username":"\u0639\u0644\u06cc","username_key":"forged"}}`,
		`{"stage":"username","registration":{"username":"\u0639\u0644\u06cc","policy_id":"forged"}}`,
		`{"stage":"username","registration":{"username":"\u0639\u0644\u06cc","given_name":"deferred"}}`,
		`{"stage":"username","registration":{"username":"\u0639\u0644\u06cc","username":"\u0635"}}`,
		`{"stage":"username","registration":{"Username":"\u0639\u0644\u06cc"}}`,
		`{"stage":"username","registration":{"username":null}}`,
		`{"stage":"username","registration":{"username":"\ud800"}}`,
		`{"stage":"username","registration":{"username":true}}`,
		`{"stage":"username","registration":null}`,
		`{"stage":"username","registration":{"username":"\u0639\u0644\u06cc"},"password":"deferred"}`,
	} {
		if _, err := readRegistrationRequest(httptest.NewRequest(http.MethodPost, registrationPath+"/validate", strings.NewReader(body)), "validate"); err == nil {
			t.Fatal("undeclared username input or malformed Unicode admitted")
		}
	}
	for _, body := range []string{
		`{"email":"person@example.com","phone":"+989123456789"}`,
		`{"email":"person@example.com","phone":"+989123456789","username":null}`,
		`{"email":"person@example.com","phone":"+989123456789","username":"\ud800"}`,
		strings.TrimSuffix(registrationTestBody("start"), "}") + `,"username_display":"forged"}`,
	} {
		if _, err := readRegistrationRequest(httptest.NewRequest(http.MethodPost, registrationPath+"/start", strings.NewReader(body)), "start"); err == nil {
			t.Fatal("start accepted missing username or caller-normalized authority")
		}
	}
}

func TestRegistrationUsernameErrorStatusAndMinimalFields(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
		field  bool
	}{
		{registration.ErrInvalidUsername, http.StatusBadRequest, "invalid_username", true},
		{registration.ErrUsernameUnavailable, http.StatusConflict, "username_unavailable", true},
		{registration.ErrUsernamePolicyChanged, http.StatusConflict, "username_policy_changed", false},
	} {
		w := httptest.NewRecorder()
		(&Server{}).writeRegistrationError(w, tc.err)
		var body map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != tc.status || string(body["error"]) != `"`+tc.code+`"` {
			t.Fatalf("username error contract changed: status=%d body=%s", w.Code, w.Body.String())
		}
		if tc.field {
			var fields map[string]string
			if json.Unmarshal(body["field_errors"], &fields) != nil || len(fields) != 1 || fields["username"] != tc.code || len(body) != 2 {
				t.Fatal("username field error disclosed additional identity data")
			}
		} else if len(body) != 1 {
			t.Fatal("policy mismatch exposed authority or private diagnostics")
		}
	}
}
