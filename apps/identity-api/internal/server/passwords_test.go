package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/passwordmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

func TestReadPasswordRequestExactBytesAndStrictShape(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body, operation, secret string
		valid                                       bool
	}{
		{"add", "PUT", passwordPath, `{"operation":"add","new_password":"private fixture secret"}`, "add", "private fixture secret", true},
		{"spaces preserved", "PUT", passwordPath, `{"operation":"change","new_password":"  private fixture secret  "}`, "change", "  private fixture secret  ", true},
		{"combining preserved", "PUT", passwordPath, `{"operation":"change","new_password":"fixture\u0065\u0301 secret"}`, "change", "fixturee\u0301 secret", true},
		{"surrogate pair", "PUT", passwordPath, `{"operation":"add","new_password":"fixture \ud83d\ude00 secret"}`, "add", "fixture \U0001f600 secret", true},
		{"empty delete", "DELETE", passwordPath, "", "remove", "", true},
		{"delete object", "DELETE", passwordPath, `{}`, "", "", false},
		{"delete whitespace", "DELETE", passwordPath, " ", "", "", false},
		{"query", "PUT", passwordPath + "?operation=add", `{"operation":"add","new_password":"private fixture secret"}`, "", "", false},
		{"empty query", "DELETE", passwordPath + "?", "", "", "", false},
		{"missing password", "PUT", passwordPath, `{"operation":"add"}`, "", "", false},
		{"missing operation", "PUT", passwordPath, `{"new_password":"private fixture secret"}`, "", "", false},
		{"unknown field", "PUT", passwordPath, `{"operation":"add","new_password":"private fixture secret","password":"ignored"}`, "", "", false},
		{"duplicate operation", "PUT", passwordPath, `{"operation":"change","operation":"add","new_password":"private fixture secret"}`, "", "", false},
		{"escaped duplicate", "PUT", passwordPath, `{"operation":"add","new_password":"private fixture secret","new_\u0070assword":"other"}`, "", "", false},
		{"case alias", "PUT", passwordPath, `{"Operation":"add","new_password":"private fixture secret"}`, "", "", false},
		{"null", "PUT", passwordPath, `{"operation":"add","new_password":null}`, "", "", false},
		{"number", "PUT", passwordPath, `{"operation":"add","new_password":123}`, "", "", false},
		{"nested", "PUT", passwordPath, `{"operation":"add","new_password":{"value":"private fixture secret"}}`, "", "", false},
		{"array", "PUT", passwordPath, `[{"operation":"add","new_password":"private fixture secret"}]`, "", "", false},
		{"trailing value", "PUT", passwordPath, `{"operation":"add","new_password":"private fixture secret"}{}`, "", "", false},
		{"PUT removal", "PUT", passwordPath, `{"operation":"remove","new_password":""}`, "", "", false},
		{"unpaired high surrogate", "PUT", passwordPath, `{"operation":"add","new_password":"fixture \ud800 secret"}`, "", "", false},
		{"unpaired low surrogate", "PUT", passwordPath, `{"operation":"add","new_password":"fixture \udc00 secret"}`, "", "", false},
		{"interrupted pair", "PUT", passwordPath, `{"operation":"add","new_password":"\ud800x\udc00"}`, "", "", false},
		{"reversed pair", "PUT", passwordPath, `{"operation":"add","new_password":"\udc00\ud800"}`, "", "", false},
		{"invalid UTF8", "PUT", passwordPath, "{\"operation\":\"add\",\"new_password\":\"fixture\xffsecret\"}", "", "", false},
		{"oversized", "PUT", passwordPath, `{"operation":"add","new_password":"` + strings.Repeat("x", 8192) + `"}`, "", "", false},
		{"empty body", "PUT", passwordPath, "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			operation, secret, valid := readPasswordRequest(r)
			if valid != tc.valid || operation != tc.operation || secret != tc.secret {
				t.Fatalf("strict parser result valid=%v operation=%q exact bytes preserved=%v", valid, operation, secret == tc.secret)
			}
		})
	}
}

type passwordUnreadableBody struct{}

func (passwordUnreadableBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (passwordUnreadableBody) Close() error             { return nil }

func TestReadPasswordRequestRejectsReadFailure(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		r := httptest.NewRequest(method, passwordPath, nil)
		r.Body = passwordUnreadableBody{}
		if _, _, ok := readPasswordRequest(r); ok {
			t.Fatal("failed body read accepted")
		}
	}
}

func TestPasswordErrorsRemainCoarse(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		key    string
	}{
		{passwordmanager.ErrInvalid, 400, "invalid_request"},
		{password.ErrTooShort, 400, "invalid_request"},
		{password.ErrTooLong, 400, "invalid_request"},
		{password.ErrInvalidUTF8, 400, "invalid_request"},
		{password.ErrCompromisedPassword, 400, "invalid_request"},
		{passwordmanager.ErrUnauthorized, 403, "insufficient_user_authentication"},
		{stepup.ErrGrantConsumed, 403, "insufficient_user_authentication"},
		{actionproof.ErrUnauthorized, 403, "insufficient_user_authentication"},
		{passwordmanager.ErrConflict, 409, "password_state_conflict"},
		{accountpolicy.ErrLastCredential, 409, "last_credential"},
		{accountpolicy.ErrLastFactor, 409, "last_factor"},
		{passwordmanager.ErrRateLimited, 429, "rate_limited"},
		{passwordmanager.ErrOutcomeUnknown, 503, "outcome_unknown"},
		{actionproof.ErrOutcomeUnknown, 503, "outcome_unknown"},
		{passwordmanager.ErrUnavailable, 503, "temporarily_unavailable"},
		{errors.New("private database diagnostic"), 503, "temporarily_unavailable"},
	} {
		t.Run(tc.key+"/"+tc.err.Error(), func(t *testing.T) {
			w := httptest.NewRecorder()
			writePasswordError(w, tc.err)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), `"error":"`+tc.key+`"`) || strings.Contains(w.Body.String(), "private") || len(w.Result().Cookies()) != 0 {
				t.Fatalf("unexpected password failure status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
