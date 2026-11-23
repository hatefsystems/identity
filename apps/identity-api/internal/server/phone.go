package server

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

const phoneFactorSMS = "sms"
const contactChangeProofPath = "/api/v1/auth/action-proofs/contact-change"
const contactRemovalProofPath = "/api/v1/auth/action-proofs/contact-removal"
const contactChangeAction = "contact_change"
const contactRemovalAction = "contact_remove"

// ContactManager is the sole contact-maintenance writer, including the old phone URLs.
type ContactManager interface {
	Preflight(target, value, sourceIP string) (string, error)
	Start(context.Context, session.Session, string, string, contactmanager.Authorization, string) (contactmanager.StartResult, error)
	Finish(context.Context, session.Session, string, string, string) (bool, error)
	Remove(context.Context, session.Session, string, contactmanager.Authorization) (bool, error)
	Read(context.Context, session.Session) (contactmanager.Contacts, error)
}

// ContactManagementProofs binds password/contact authority to one action and target.
type ContactManagementProofs interface {
	ContactChallenge(context.Context, session.Session, string, string, string, string, string) (string, time.Time, error)
	ContactVerify(context.Context, session.Session, string, string, string) (string, time.Time, error)
}

type contactErrorResponse struct {
	Error     string `json:"error"`
	ACRValues string `json:"acr_values,omitempty"`
}

type phoneSendCodeResponse struct {
	Status         string    `json:"status"`
	VerificationID string    `json:"verification_id"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (s *Server) registerContactRoutes() {
	guard, ok := s.sessionGuard("contacts")
	if !ok {
		return
	}
	s.router.With(guard.Handler).Get("/api/v1/users/me/contacts", s.handleCurrentContacts())
	for _, target := range []string{"phone", "email"} {
		path := "/api/v1/users/me/" + target
		// Finite readers remain mounted even when issuance and sending are disabled.
		s.router.With(guard.Handler).Post(path+"/verify", s.handleContactFinish(target))
		if s.deps.StepUp != nil || s.deps.ContactManagementProofs != nil {
			s.router.With(guard.Handler).Post(path+"/send-code", s.handleContactStart(target))
			s.router.With(guard.Handler).Delete(path, s.handleContactRemove(target))
		}
	}
}

func (s *Server) registerContactProofRoutes() {
	guard, ok := s.sessionGuard("contact proofs")
	if !ok {
		return
	}
	for _, route := range []struct{ path, action string }{
		{contactChangeProofPath, contactChangeAction},
		{contactRemovalProofPath, contactRemovalAction},
	} {
		s.router.With(guard.Handler).Post(route.path+"/challenge", s.handleContactProof(false, route.action))
		s.router.With(guard.Handler).Post(route.path+"/verify", s.handleContactProof(true, route.action))
	}
}

func canonicalContactHandle(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

func contactCode(value string) bool {
	return len(value) == 6 && strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

// Inspect keys as well as values: an empty or noncanonical-cased header is not absence.
func contactAuthorityHeaders(header http.Header) (grant, proof []string, count int) {
	for name, values := range header {
		if strings.EqualFold(name, stepup.HeaderStepUpAuth) {
			count++
			grant = append(grant, values...)
		} else if strings.EqualFold(name, "X-Action-Proof") {
			count++
			proof = append(proof, values...)
		}
	}
	return
}

func noContactAuthority(r *http.Request) bool {
	_, _, count := contactAuthorityHeaders(r.Header)
	return count == 0
}

func (s *Server) contactAuthorization(r *http.Request, sess session.Session) (contactmanager.Authorization, error) {
	grants, proofs, count := contactAuthorityHeaders(r.Header)
	if count != 1 || len(grants)+len(proofs) != 1 {
		return contactmanager.Authorization{}, stepup.ErrNoGrant
	}
	if len(proofs) == 1 {
		if s.deps.ContactManagementProofs == nil || !canonicalContactHandle(proofs[0]) {
			return contactmanager.Authorization{}, stepup.ErrInvalidGrant
		}
		return contactmanager.Authorization{Proof: proofs[0]}, nil
	}
	if s.deps.StepUp == nil || grants[0] == "" || len(grants[0]) > 16*1024 || strings.ContainsAny(grants[0], ", \t\r\n") {
		return contactmanager.Authorization{}, stepup.ErrInvalidGrant
	}
	grant, err := s.deps.StepUp.Validate(r.Context(), grants[0], sess)
	if err != nil {
		return contactmanager.Authorization{}, err
	}
	method := ""
	if slices.Equal(grant.AMR, []string{"hwk", "user"}) {
		method = "webauthn_uv"
	} else if slices.Equal(grant.AMR, []string{"otp"}) {
		method = "totp"
	}
	if method == "" || !grant.AuthVersionSet {
		return contactmanager.Authorization{}, stepup.ErrInvalidGrant
	}
	return contactmanager.Authorization{Grant: &contactmanager.StrongAuthorization{
		UserID: grant.UserID, SessionID: grant.SessionID, DPoPJKT: grant.DPoPJKT,
		AuthVersion: grant.AuthVersion, Method: method, ExpiresAt: grant.ExpiresAt,
	}}, nil
}

func (s *Server) handleCurrentContacts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _, ok := profileSession(w, r)
		if !ok {
			return
		}
		if !noContactAuthority(r) {
			writeContactError(w, stepup.ErrInvalidGrant)
			return
		}
		if !emptyMFARequest(r) {
			writeContactError(w, contactmanager.ErrInvalid)
			return
		}
		contacts, err := s.deps.Contacts.Read(r.Context(), sess)
		if err != nil {
			writeContactError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, contacts)
	}
}

func (s *Server) handleContactStart(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _, ok := profileSession(w, r)
		if !ok {
			return
		}
		values, ok := readProofStringObject(r, []string{target})
		if !ok || values[target] == "" {
			writeContactError(w, contactmanager.ErrInvalid)
			return
		}
		source := clientip.FromRequest(r)
		canonical, err := s.deps.Contacts.Preflight(target, values[target], source)
		if err != nil {
			writeContactError(w, err)
			return
		}
		// Validate/spend exactly once, only after input and transport-policy preflight.
		auth, err := s.contactAuthorization(r, sess)
		if err != nil {
			writeContactError(w, err)
			return
		}
		result, err := s.deps.Contacts.Start(r.Context(), sess, target, canonical, auth, source)
		if err != nil {
			writeContactError(w, err)
			return
		}
		if !canonicalContactHandle(result.VerificationID) || result.ExpiresAt.IsZero() {
			writeContactError(w, contactmanager.ErrOutcomeUnknown)
			return
		}
		session.OutcomeCommitted(r.Context())
		writeJSON(w, http.StatusOK, phoneSendCodeResponse{"sent", result.VerificationID, result.ExpiresAt})
	}
}

func (s *Server) handleContactFinish(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, userID, ok := profileSession(w, r)
		if !ok {
			return
		}
		if !noContactAuthority(r) {
			writeContactError(w, stepup.ErrInvalidGrant)
			return
		}
		values, ok := readProofStringObject(r, []string{"verification_id", "code"})
		if !ok || !canonicalContactHandle(values["verification_id"]) || !contactCode(values["code"]) {
			writeContactError(w, contactmanager.ErrInvalid)
			return
		}
		changed, err := s.deps.Contacts.Finish(r.Context(), sess, target, values["verification_id"], values["code"])
		if err != nil {
			writeContactError(w, err)
			return
		}
		if changed {
			session.SecurityChangeCommitted(r.Context())
			if target == "phone" {
				s.record(r, audit.Event{EventType: audit.EventPhoneVerified, ActionStatus: audit.StatusSuccess,
					ActorID: userID, SubjectID: &userID, Payload: map[string]any{"factor": phoneFactorSMS},
					Security: &audit.SecurityContext{AccountRef: userID}})
			}
		} else {
			session.OutcomeCommitted(r.Context())
		}
		writeJSON(w, http.StatusOK, struct {
			Status string `json:"status"`
		}{"verified"})
	}
}

func (s *Server) handleContactRemove(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, userID, ok := profileSession(w, r)
		if !ok {
			return
		}
		if !emptyMFARequest(r) {
			writeContactError(w, contactmanager.ErrInvalid)
			return
		}
		auth, err := s.contactAuthorization(r, sess)
		if err != nil {
			writeContactError(w, err)
			return
		}
		changed, err := s.deps.Contacts.Remove(r.Context(), sess, target, auth)
		if err != nil {
			writeContactError(w, err)
			return
		}
		if changed {
			session.SecurityChangeCommitted(r.Context())
			if target == "phone" {
				s.record(r, audit.Event{EventType: audit.EventPhoneRemoved, ActionStatus: audit.StatusSuccess,
					ActorID: userID, SubjectID: &userID, Payload: map[string]any{"factor": phoneFactorSMS},
					Security: &audit.SecurityContext{AccountRef: userID}})
			}
		} else {
			session.OutcomeCommitted(r.Context())
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleContactProof(verify bool, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _, ok := profileSession(w, r)
		if !ok {
			return
		}
		if !noContactAuthority(r) {
			writeContactError(w, stepup.ErrInvalidGrant)
			return
		}
		names := []string{"password", "channel", "target"}
		if verify {
			names = []string{"challenge", "code"}
		}
		values, ok := readProofStringObject(r, names)
		if !ok || verify && (!canonicalContactHandle(values["challenge"]) || !contactCode(values["code"])) ||
			!verify && (values["password"] == "" || values["channel"] != "email" && values["channel"] != "sms" || values["target"] != "email" && values["target"] != "phone") {
			writeContactError(w, contactmanager.ErrInvalid)
			return
		}
		var handle string
		var deadline time.Time
		var err error
		if verify {
			handle, deadline, err = s.deps.ContactManagementProofs.ContactVerify(r.Context(), sess, values["challenge"], values["code"], action)
		} else {
			handle, deadline, err = s.deps.ContactManagementProofs.ContactChallenge(r.Context(), sess, values["password"], values["channel"], action, values["target"], clientip.FromRequest(r))
		}
		if err != nil {
			writeContactError(w, err)
			return
		}
		if !canonicalContactHandle(handle) || deadline.IsZero() {
			writeContactError(w, contactmanager.ErrOutcomeUnknown)
			return
		}
		session.OutcomeCommitted(r.Context())
		if verify {
			writeJSON(w, http.StatusOK, struct {
				Proof     string    `json:"action_proof"`
				ExpiresAt time.Time `json:"expires_at"`
			}{handle, deadline})
		} else {
			writeJSON(w, http.StatusAccepted, struct {
				Challenge string    `json:"challenge"`
				ExpiresAt time.Time `json:"expires_at"`
			}{handle, deadline})
		}
	}
}

func writeContactError(w http.ResponseWriter, err error) {
	status, key, acr := http.StatusServiceUnavailable, "temporarily_unavailable", ""
	switch {
	case errors.Is(err, contactmanager.ErrOutcomeUnknown), errors.Is(err, actionproof.ErrOutcomeUnknown), errors.Is(err, contactcode.ErrOutcomeUnknown):
		key = "outcome_unknown"
	case errors.Is(err, contactmanager.ErrEmailRemovalUnavailable), errors.Is(err, actionproof.ErrEmailRemovalUnavailable):
		status, key = http.StatusConflict, "email_removal_unavailable"
	case errors.Is(err, accountpolicy.ErrLastVerifiedContact):
		status, key = http.StatusConflict, "last_verified_contact"
	case errors.Is(err, accountpolicy.ErrLastFactor):
		status, key = http.StatusConflict, "last_factor"
	case errors.Is(err, accountpolicy.ErrLastCredential):
		status, key = http.StatusConflict, "last_credential"
	case errors.Is(err, contactmanager.ErrConflict):
		status, key = http.StatusConflict, "contact_conflict"
	case errors.Is(err, contactmanager.ErrUnauthorized), errors.Is(err, contactmanager.ErrExpired), errors.Is(err, actionproof.ErrUnauthorized), errors.Is(err, actionproof.ErrContactExpired),
		errors.Is(err, stepup.ErrNoGrant), errors.Is(err, stepup.ErrInvalidGrant), errors.Is(err, stepup.ErrGrantConsumed), errors.Is(err, stepup.ErrGrantNotForSession):
		status, key, acr = http.StatusForbidden, "insufficient_user_authentication", stepup.ACRStepUp
	case errors.Is(err, session.ErrSessionNotFound), errors.Is(err, stepup.ErrUserNotFound), errors.Is(err, stepup.ErrAccountNotActive):
		status, key = http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, contactmanager.ErrInvalid), errors.Is(err, actionproof.ErrInvalid), errors.Is(err, contactcode.ErrInvalid):
		status, key = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, contactmanager.ErrRateLimited), errors.Is(err, contactcode.ErrRateLimited), errors.Is(err, contactcode.ErrLockedOut), errors.Is(err, actionproof.ErrRateLimited):
		status, key = http.StatusTooManyRequests, "rate_limited"
	case errors.Is(err, contactmanager.ErrInvalidCode), errors.Is(err, contactcode.ErrInvalidCode), errors.Is(err, contactcode.ErrNoActiveCode):
		status, key = http.StatusBadRequest, "invalid_code"
	}
	// Never disclose SQL identities, destinations, provider errors or authority.
	writeJSON(w, status, contactErrorResponse{Error: key, ACRValues: acr})
}
