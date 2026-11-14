package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/registration"
)

const registrationPath = "/api/v1/auth/register"

func (s *Server) registerRegistrationRoutes() {
	for _, operation := range []string{"validate", "start", "email/resend", "email/verify", "phone/send", "phone/verify", "passkey/options", "", "result"} {
		path := registrationPath
		if operation != "" {
			path += "/" + operation
		}
		s.router.Post(path, s.handleRegistration(operation))
	}
}

type registrationRequest struct {
	Email, Phone, Username, Capability, Token, VerificationID, Code string
	AttemptID                                                       uuid.UUID
	Credential                                                      json.RawMessage
}

// Request bodies are exact, case-sensitive contracts, including nested
// authenticator JSON. Validate before consuming the public nonce/replay claim.
func readRegistrationRequest(r *http.Request, operation string) (registrationRequest, error) {
	invalid := registration.ErrInvalid
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Body == nil {
		return registrationRequest{}, invalid
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebAuthnBodyBytes+1))
	if err != nil || len(body) > maxWebAuthnBodyBytes || !utf8.Valid(body) || !json.Valid(body) || !uniqueJSONFields(body) {
		return registrationRequest{}, invalid
	}
	fields := map[string]json.RawMessage{}
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return registrationRequest{}, invalid
	}
	names := []string{"attempt_id", "capability"}
	switch operation {
	case "validate":
		names = []string{"stage", "registration"}
	case "start":
		names = []string{"email", "phone", "username"}
	case "email/verify":
		names = []string{"attempt_id", "token"}
	case "phone/verify":
		names = append(names, "verification_id", "code")
	case "":
		names = append(names, "credential")
	}
	if len(fields) != len(names) {
		return registrationRequest{}, invalid
	}
	values := map[string]string{}
	var request registrationRequest
	for _, name := range names {
		raw, ok := fields[name]
		if !ok {
			return registrationRequest{}, invalid
		}
		if name == "credential" {
			if !validSignupCredential(raw) {
				return registrationRequest{}, invalid
			}
			request.Credential = raw
			continue
		}
		if name == "registration" {
			nested, ok := exactObject(raw, []string{"username"}, nil)
			if !ok {
				return registrationRequest{}, invalid
			}
			raw = nested["username"]
			name = "username"
		}
		var value *string
		if json.Unmarshal(raw, &value) != nil || value == nil || len(raw) < 2 || raw[0] != '"' || !validNameJSONString(raw) {
			return registrationRequest{}, invalid
		}
		values[name] = *value
	}
	request.Email = values["email"]
	request.Phone = values["phone"]
	request.Username = values["username"]
	request.Capability = values["capability"]
	request.Token = values["token"]
	request.VerificationID = values["verification_id"]
	request.Code = values["code"]
	if operation == "validate" && values["stage"] != "username" {
		return registrationRequest{}, invalid
	}
	if operation != "start" && operation != "validate" {
		id, err := uuid.Parse(values["attempt_id"])
		if err != nil || id == uuid.Nil || id.String() != values["attempt_id"] {
			return registrationRequest{}, invalid
		}
		request.AttemptID = id
		secret := request.Capability
		if operation == "email/verify" {
			secret = request.Token
		}
		if _, err := registrationSecret(secret); err != nil {
			return registrationRequest{}, invalid
		}
	}
	if operation == "phone/verify" {
		if _, err := registrationSecret(request.VerificationID); err != nil || len(request.Code) != 6 || strings.IndexFunc(request.Code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return registrationRequest{}, invalid
		}
	}
	return request, nil
}

func registrationSecret(encoded string) ([]byte, error) {
	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(value) != 32 || base64.RawURLEncoding.EncodeToString(value) != encoded {
		return nil, registration.ErrInvalid
	}
	return value, nil
}

func exactObject(raw json.RawMessage, required, optional []string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, false
		}
	}
	for name := range fields {
		allowed := false
		for _, key := range append(append([]string{}, required...), optional...) {
			allowed = allowed || name == key
		}
		if !allowed {
			return nil, false
		}
	}
	return fields, true
}
func validSignupCredential(raw json.RawMessage) bool {
	fields, ok := exactObject(raw, []string{"id", "rawId", "type", "response"}, []string{"authenticatorAttachment", "clientExtensionResults"})
	if !ok {
		return false
	}
	stringsEqual := func(raw json.RawMessage, want string) bool {
		var text string
		return json.Unmarshal(raw, &text) == nil && text == want
	}
	if !stringsEqual(fields["type"], "public-key") || !bytes.Equal(fields["id"], fields["rawId"]) {
		return false
	}
	response, ok := exactObject(fields["response"], []string{"clientDataJSON", "attestationObject"}, []string{"transports"})
	if !ok {
		return false
	}
	for _, raw := range []json.RawMessage{fields["id"], fields["rawId"], response["clientDataJSON"], response["attestationObject"]} {
		var text string
		if json.Unmarshal(raw, &text) != nil || text == "" {
			return false
		}
		decoded, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != text {
			return false
		}
	}
	if raw, ok := response["transports"]; ok {
		var transports []string
		if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &transports) != nil || len(transports) > 5 {
			return false
		}
		for _, transport := range transports {
			if transport != "usb" && transport != "nfc" && transport != "ble" && transport != "internal" && transport != "hybrid" {
				return false
			}
		}
	}
	if raw, ok := fields["authenticatorAttachment"]; ok && string(raw) != "null" && !stringsEqual(raw, "platform") && !stringsEqual(raw, "cross-platform") {
		return false
	}
	if raw, ok := fields["clientExtensionResults"]; ok {
		extensions, ok := exactObject(raw, nil, []string{"credProps"})
		if !ok {
			return false
		}
		if props, ok := extensions["credProps"]; ok {
			properties, ok := exactObject(props, []string{"rk"}, nil)
			if !ok || !bytes.Equal(properties["rk"], []byte("true")) {
				return false
			}
		}
	}
	return true
}

func (s *Server) handleRegistration(operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, err := readRegistrationRequest(r, operation)
		if err != nil {
			s.writeRegistrationError(w, err)
			return
		}
		s.browserLogin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proof := dpop.ProofFromContext(r.Context())
			if proof == nil {
				s.writeRegistrationError(w, registration.ErrUnauthorized)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if operation == "validate" {
				result, err := s.deps.Registration.ValidateUsername(ctx, request.Username, clientip.FromRequest(r))
				if err != nil {
					s.writeRegistrationError(w, err)
					return
				}
				writeJSON(w, http.StatusOK, result)
				return
			}
			if operation == "start" {
				result, err := s.deps.Registration.Start(ctx, request.Email, request.Phone, request.Username, proof.JKT, clientip.FromRequest(r))
				if err != nil {
					s.writeRegistrationError(w, err)
					return
				}
				defer clear(result.Capability)
				writeJSON(w, http.StatusCreated, map[string]any{"attempt_id": result.Attempt.Record.ID.String(), "capability": base64.RawURLEncoding.EncodeToString(result.Capability), "canonical_email": result.Attempt.Details.Email, "username_display": result.Attempt.Details.UsernameDisplay, "expires_at": result.Attempt.Record.ExpiresAt.Time, "email_sent": result.EmailSent})
				return
			}
			if operation == "email/verify" {
				token, _ := registrationSecret(request.Token)
				defer clear(token)
				if err := s.deps.Registration.VerifyEmail(ctx, request.AttemptID, token, proof.JKT); err != nil {
					s.writeRegistrationError(w, err)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			capability, _ := registrationSecret(request.Capability)
			defer clear(capability)
			authority := registration.Authority{AttemptID: request.AttemptID, Capability: capability, JKT: proof.JKT}
			switch operation {
			case "email/resend":
				err = s.deps.Registration.ResendEmail(ctx, authority)
			case "phone/send":
				id, sendErr := s.deps.Registration.SendPhone(ctx, authority, clientip.FromRequest(r))
				err = sendErr
				if err == nil {
					writeJSON(w, http.StatusOK, map[string]string{"verification_id": id})
					return
				}
			case "phone/verify":
				err = s.deps.Registration.VerifyPhone(ctx, authority, request.VerificationID, request.Code)
			case "passkey/options":
				options, optionsErr := s.deps.Registration.PasskeyOptions(ctx, authority)
				err = optionsErr
				if err == nil {
					writeJSON(w, http.StatusOK, options)
					return
				}
			case "":
				result, completeErr := s.deps.Registration.Complete(ctx, authority, request.Credential)
				err = completeErr
				if err == nil {
					writeJSON(w, http.StatusOK, result)
					return
				}
			case "result":
				result, resultErr := s.deps.Registration.Result(ctx, authority)
				err = resultErr
				if err == nil {
					writeJSON(w, http.StatusOK, result)
					return
				}
			}
			if err != nil {
				s.writeRegistrationError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
	}
}

func (s *Server) writeRegistrationError(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "temporarily_unavailable"
	fieldError := ""
	switch {
	case errors.Is(err, registration.ErrInvalidUsername):
		status, code, fieldError = http.StatusBadRequest, "invalid_username", "invalid_username"
	case errors.Is(err, registration.ErrUsernameUnavailable):
		status, code, fieldError = http.StatusConflict, "username_unavailable", "username_unavailable"
	case errors.Is(err, registration.ErrUsernamePolicyChanged):
		status, code = http.StatusConflict, "username_policy_changed"
	case errors.Is(err, registration.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, registration.ErrUnauthorized):
		status, code = http.StatusUnauthorized, "invalid_registration"
	case errors.Is(err, registration.ErrExpired):
		status, code = http.StatusGone, "registration_expired"
	case errors.Is(err, registration.ErrConflict):
		status, code = http.StatusConflict, "registration_conflict"
	case errors.Is(err, registration.ErrNewCeremony):
		status, code = http.StatusConflict, "restart_registration"
	case errors.Is(err, registration.ErrProofRequired):
		status, code = http.StatusConflict, "proof_required"
	case errors.Is(err, registration.ErrRestartRequired):
		status, code = http.StatusConflict, "restart_phone_proof"
	case errors.Is(err, registration.ErrOutcomeUnknown):
		status, code = http.StatusServiceUnavailable, "result_required"
	case errors.Is(err, registration.ErrSendFailed):
		status, code = http.StatusServiceUnavailable, "send_failed"
	case errors.Is(err, registration.ErrRateLimited), errors.Is(err, registration.ErrCapacity):
		status, code = http.StatusTooManyRequests, "rate_limited"
		w.Header().Set("Retry-After", "60")
	}
	// Never log the underlying error: DB/provider diagnostics can contain PII.
	response := map[string]any{"error": code}
	if fieldError != "" {
		response["field_errors"] = map[string]string{"username": fieldError}
	}
	writeJSON(w, status, response)
}
