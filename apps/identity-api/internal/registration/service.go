package registration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// ErrRateLimited and the following errors expose fixed signup failure reasons.
var (
	ErrRateLimited           = errors.New("registration: rate limited")
	ErrProofRequired         = errors.New("registration: ownership proof required")
	ErrSendFailed            = errors.New("registration: delivery not confirmed")
	ErrRestartRequired       = errors.New("registration: fresh phone proof required")
	ErrOutcomeUnknown        = errors.New("registration: inspect durable result")
	ErrNewCeremony           = errors.New("registration: restart registration with a new ceremony")
	ErrInvalidUsername       = errors.New("registration: invalid username")
	ErrUsernameUnavailable   = errors.New("registration: username unavailable")
	ErrUsernamePolicyChanged = errors.New("registration: username policy changed; restart required")
)

// PhoneProof issues and consumes signup-purpose proofs for frozen contacts.
type PhoneProof interface {
	SendSignupCode(context.Context, uuid.UUID, string, string, string, time.Time) (string, error)
	ConsumeSignupCode(context.Context, uuid.UUID, string, string, string, string) error
}

// PasskeyProof verifies signup ceremonies without persisting account state.
type PasskeyProof interface {
	BeginSignup(context.Context, string, []byte, string, time.Time) (*protocol.CredentialCreation, json.RawMessage, error)
	VerifySignup(context.Context, string, []byte, string, json.RawMessage, []byte) (db.CreateWebauthnCredentialParams, error)
}

// PhoneIndexer computes the blind index for a verified frozen phone.
type PhoneIndexer interface{ Compute(string) string }

// Deps supplies signup authority, proof services, and finite admission policy.
type Deps struct {
	Store                              *Store
	Usernames                          UsernameNamespace
	Database                           Database
	Email                              *Email
	Phone                              PhoneProof
	WebAuthn                           PasskeyProof
	Encryptor                          Encryptor
	Indexer                            PhoneIndexer
	Limiter                            ratelimit.Limiter
	GlobalDailyLimit, EmailHourlyLimit int
}

// Service orchestrates ownership proofs and atomic account birth.
type Service struct {
	deps Deps
	now  func() time.Time
}

// Authority binds an attempt capability to its original browser key.
type Authority struct {
	AttemptID  uuid.UUID
	Capability []byte
	JKT        string
}

// StartResult returns pending authority and email delivery acceptance only.
type StartResult struct {
	Attempt    Attempt
	Capability []byte
	EmailSent  bool
}

// Outcome reports authorized signup status without authenticating the caller.
type Outcome struct {
	State            string     `json:"state"`
	Next             string     `json:"next,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ReceiptExpiresAt *time.Time `json:"receipt_expires_at,omitempty"`
	EmailVerified    bool       `json:"email_verified"`
	PhoneVerified    bool       `json:"phone_verified"`
}

// NewService requires complete collaborators and bounded admission limits.
func NewService(deps Deps) (*Service, error) {
	if deps.Store == nil || nilDependency(deps.Store.usernames) || nilDependency(deps.Usernames) || deps.Usernames.Normalizer() == nil || deps.Store.usernames.Normalizer() != deps.Usernames.Normalizer() || nilDependency(deps.Database) || deps.Email == nil || nilDependency(deps.Phone) || nilDependency(deps.WebAuthn) || nilDependency(deps.Encryptor) || nilDependency(deps.Indexer) || nilDependency(deps.Limiter) || deps.GlobalDailyLimit < 1 || deps.GlobalDailyLimit > 100000 || deps.EmailHourlyLimit < 1 || deps.EmailHourlyLimit > 10 {
		return nil, ErrInvalid
	}
	return &Service{deps: deps, now: time.Now}, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	switch reflect.ValueOf(value).Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return reflect.ValueOf(value).IsNil()
	}
	return false
}

// Start charges shared finite admission budgets before generating pending PII.
// Provider acceptance is never ownership and an uncertain send is not retried.
func (s *Service) Start(ctx context.Context, email, phone, chosenUsername, jkt, ip string) (StartResult, error) {
	chosen, err := s.deps.Usernames.Normalizer().Normalize(chosenUsername)
	if err != nil {
		return StartResult{}, ErrInvalidUsername
	}
	canonical, err := emailaddress.Canonicalize(email)
	if err != nil {
		return StartResult{}, ErrInvalid
	}
	// The form sends the original identifier. Canonicalize its Iranian aliases
	// before rate-limit keys, pending encryption and provider binding are derived.
	if len(phone) == 11 && strings.HasPrefix(phone, "09") {
		phone = "+98" + phone[1:]
	} else if len(phone) == 12 && strings.HasPrefix(phone, "989") {
		phone = "+" + phone
	}
	phone, err = smsotp.NormalizePhone(phone)
	if err != nil || len(phone) != 13 || !strings.HasPrefix(phone, "+989") || !ValidJKT(jkt) {
		return StartResult{}, ErrInvalid
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" {
		return StartResult{}, ErrInvalid
	}
	for _, budget := range []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{"rate:registration:global:1d", s.deps.GlobalDailyLimit, 24 * time.Hour},
		{"rate:registration:subnet:" + ratelimit.Subnet(ip), 10, time.Hour},
		{"rate:registration:phone:" + digest(phone), 5, time.Hour},
		{"rate:registration:email:" + digest(canonical), s.deps.EmailHourlyLimit, time.Hour},
	} {
		if err := s.allow(ctx, budget.key, budget.limit, budget.window); err != nil {
			return StartResult{}, err
		}
	}
	available, err := s.deps.Usernames.Available(ctx, chosen)
	if err != nil {
		return StartResult{}, usernameError(err)
	}
	if !available {
		return StartResult{}, ErrUsernameUnavailable
	}
	attempt, capability, err := s.deps.Store.Create(ctx, canonical, phone, jkt, chosen)
	if err != nil {
		return StartResult{}, err
	}
	result := StartResult{Attempt: attempt, Capability: capability}
	// Admission already charged this email; do not charge the same send twice.
	sent, err := s.issueEmail(ctx, Authority{attempt.Record.ID, capability, jkt}, false)
	result.EmailSent = err == nil
	if err == nil {
		result.Attempt = sent
	}
	return result, nil
}

func (s *Service) allow(ctx context.Context, key string, limit int, window time.Duration) error {
	allowed, err := s.deps.Limiter.Allow(ctx, key, limit, window)
	if err != nil {
		return ErrUnavailable
	}
	if !allowed {
		return ErrRateLimited
	}
	return nil
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// UsernameValidation is a read-only, bounded advisory result. It does not grant
// proof or reserve a spelling, and never reveals an owner or account status.
type UsernameValidation struct {
	Display   string `json:"username_display"`
	Available bool   `json:"available"`
}

func (s *Service) ValidateUsername(ctx context.Context, input, ip string) (UsernameValidation, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" {
		return UsernameValidation{}, ErrInvalid
	}
	if err := s.allow(ctx, "rate:registration:username:"+ratelimit.Subnet(ip), 30, time.Minute); err != nil {
		return UsernameValidation{}, err
	}
	value, err := s.deps.Usernames.Normalizer().Normalize(input)
	if err != nil {
		return UsernameValidation{}, ErrInvalidUsername
	}
	available, err := s.deps.Usernames.Available(ctx, value)
	if err != nil {
		return UsernameValidation{}, usernameError(err)
	}
	return UsernameValidation{Display: value.Display(), Available: available}, nil
}

func usernameError(err error) error {
	switch {
	case errors.Is(err, username.ErrInvalidUsername):
		return ErrInvalidUsername
	case errors.Is(err, username.ErrReserved), errors.Is(err, username.ErrConflict):
		return ErrUsernameUnavailable
	default:
		return ErrUnavailable
	}
}

func (s *Service) frozenUsername(d Details, authority username.GuardAuthority) (username.Value, error) {
	if d.UsernameDisplay == "" || d.UsernameAuthority != authority.Authority || d.UsernameEpoch != authority.Epoch {
		return username.Value{}, ErrUsernamePolicyChanged
	}
	value, err := s.deps.Usernames.Normalizer().Normalize(d.UsernameDisplay)
	if err != nil || value.Display() != d.UsernameDisplay || value.SecurityName() != d.UsernameSecurity || value.Authority() != d.UsernameAuthority {
		return username.Value{}, ErrUsernamePolicyChanged
	}
	if s.deps.Usernames.Normalizer().IsReserved(value) {
		return username.Value{}, ErrUsernameUnavailable
	}
	return value, nil
}

// ResendEmail replaces the proof without extending the attempt deadline.
func (s *Service) ResendEmail(ctx context.Context, a Authority) error {
	_, err := s.issueEmail(ctx, a, true)
	return err
}
func (s *Service) issueEmail(ctx context.Context, a Authority, charge bool) (Attempt, error) {
	snapshot, err := s.pending(ctx, a)
	if err != nil {
		return Attempt{}, err
	}
	if charge {
		if err := s.allow(ctx, "rate:registration:global:1d", s.deps.GlobalDailyLimit, 24*time.Hour); err != nil {
			return Attempt{}, err
		}
		if err := s.allow(ctx, "rate:registration:email:"+digest(snapshot.Details.Email), s.deps.EmailHourlyLimit, time.Hour); err != nil {
			return Attempt{}, err
		}
	}
	token, err := NewCapability()
	if err != nil {
		return Attempt{}, err
	}
	defer clear(token)
	tx, err := begin(ctx, s.deps.Database)
	if err != nil {
		return Attempt{}, err
	}
	defer rollback(tx)
	attempt, err := s.deps.Store.Lock(ctx, tx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return Attempt{}, err
	}
	if attempt.Record.State != "pending" || attempt.Record.RowRevision != snapshot.Record.RowRevision {
		return Attempt{}, ErrConflict
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	attempt.Record.EmailTokenHash, _ = HashCapability(token)
	attempt.Record.EmailTokenIssuedAt = timestamp(now)
	attempt.Record.EmailTokenExpiresAt = timestamp(minTime(now.Add(EmailLifetime), attempt.Record.ExpiresAt.Time))
	attempt.Record.EmailVerifiedAt = timestamp(time.Time{})
	attempt.Record.EmailVerifiedAt.Valid = false
	attempt.Record.PhoneVerifiedAt.Valid = false
	attempt.Record.SmsVerificationRef = uuid.NullUUID{}
	clearCeremony(&attempt)
	attempt, err = s.deps.Store.Save(ctx, tx, attempt)
	if err != nil {
		return Attempt{}, err
	}
	if tx.Commit(ctx) != nil {
		return Attempt{}, ErrUnavailable
	}
	if err := s.deps.Email.SendProof(ctx, attempt, token); err != nil {
		return attempt, ErrSendFailed
	}
	return attempt, nil
}

// VerifyEmail records ownership using the independent token and original JKT.
func (s *Service) VerifyEmail(ctx context.Context, id uuid.UUID, token []byte, jkt string) error {
	tx, err := begin(ctx, s.deps.Database)
	if err != nil {
		return err
	}
	defer rollback(tx)
	a, err := s.deps.Store.LockEmailProof(ctx, tx, id, token, jkt)
	if err != nil {
		return err
	}
	a.Record.EmailTokenHash = nil
	a.Record.EmailVerifiedAt = timestamp(s.now())
	if _, err = s.deps.Store.Save(ctx, tx, a); err != nil {
		return err
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) pending(ctx context.Context, a Authority) (Attempt, error) {
	attempt, err := s.deps.Store.Get(ctx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return Attempt{}, err
	}
	if attempt.Record.State != "pending" {
		return Attempt{}, ErrConflict
	}
	return attempt, nil
}
func (s *Service) requireEmail(a Attempt) error {
	if !a.Record.EmailVerifiedAt.Valid {
		return ErrProofRequired
	}
	if !a.Record.EmailTokenExpiresAt.Valid || !s.now().Before(a.Record.EmailTokenExpiresAt.Time) {
		return ErrExpired
	}
	return nil
}

func verificationReference(id string) (uuid.UUID, error) {
	// The SMS capability is never persisted; retain only a one-way reference.
	if _, err := decodeSecret(id); err != nil {
		return uuid.Nil, ErrInvalid
	}
	hash := sha256.Sum256([]byte("registration:sms:v1:" + id))
	return uuid.FromBytes(hash[:16])
}

func decodeSecret(encoded string) ([]byte, error) {
	value, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(value) != 32 || base64.RawURLEncoding.EncodeToString(value) != encoded {
		return nil, ErrUnauthorized
	}
	return value, nil
}

// SendPhone issues a frozen-phone challenge after verifying email authority.
func (s *Service) SendPhone(ctx context.Context, a Authority, ip string) (string, error) {
	snapshot, err := s.pending(ctx, a)
	if err != nil {
		return "", err
	}
	if err = s.requireEmail(snapshot); err != nil {
		return "", err
	}
	id, err := s.deps.Phone.SendSignupCode(ctx, a.AttemptID, a.JKT, snapshot.Details.Phone, ip, minTime(snapshot.Record.ExpiresAt.Time, snapshot.Record.EmailTokenExpiresAt.Time))
	if err != nil {
		return "", phoneError(err)
	}
	ref, err := verificationReference(id)
	if err != nil {
		return "", ErrUnavailable
	}
	tx, err := begin(ctx, s.deps.Database)
	if err != nil {
		return "", err
	}
	defer rollback(tx)
	attempt, err := s.deps.Store.Lock(ctx, tx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return "", err
	}
	if attempt.Record.State != "pending" || attempt.Record.RowRevision != snapshot.Record.RowRevision {
		return "", ErrConflict
	}
	if err = s.requireEmail(attempt); err != nil {
		return "", err
	}
	attempt.Record.SmsVerificationRef = uuid.NullUUID{UUID: ref, Valid: true}
	attempt.Record.PhoneVerifiedAt.Valid = false
	attempt.Record.ChallengeRevision++
	clearCeremony(&attempt)
	if _, err = s.deps.Store.Save(ctx, tx, attempt); err != nil {
		return "", err
	}
	if tx.Commit(ctx) != nil {
		return "", ErrRestartRequired
	}
	return id, nil
}

// VerifyPhone consumes the bound OTP and records proof or requires a restart.
func (s *Service) VerifyPhone(ctx context.Context, a Authority, id, code string) error {
	ref, err := verificationReference(id)
	if err != nil {
		return err
	}
	tx, err := begin(ctx, s.deps.Database)
	if err != nil {
		return err
	}
	defer rollback(tx)
	attempt, err := s.deps.Store.Lock(ctx, tx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return err
	}
	if attempt.Record.State != "pending" {
		return ErrConflict
	}
	if err = s.requireEmail(attempt); err != nil {
		return err
	}
	if !attempt.Record.SmsVerificationRef.Valid || attempt.Record.SmsVerificationRef.UUID != ref {
		return ErrUnauthorized
	}
	if attempt.Record.PhoneVerifiedAt.Valid {
		return ErrConflict
	}
	if err = s.deps.Phone.ConsumeSignupCode(ctx, a.AttemptID, a.JKT, attempt.Details.Phone, id, code); err != nil {
		return phoneError(err)
	}
	attempt.Record.PhoneVerifiedAt = timestamp(s.now())
	if _, err = s.deps.Store.Save(ctx, tx, attempt); err != nil {
		rollback(tx)
		return s.consumedPhoneOutcome(ctx, a, ref)
	}
	if tx.Commit(ctx) != nil {
		rollback(tx)
		return s.consumedPhoneOutcome(ctx, a, ref)
	}
	return nil
}
func (s *Service) consumedPhoneOutcome(ctx context.Context, a Authority, ref uuid.UUID) error {
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	stored, err := s.deps.Store.Get(check, a.AttemptID, a.Capability, a.JKT)
	if err == nil && stored.Record.State == "pending" && stored.Record.PhoneVerifiedAt.Valid && stored.Record.SmsVerificationRef.Valid && stored.Record.SmsVerificationRef.UUID == ref {
		return nil
	}
	return ErrRestartRequired
}
func phoneError(err error) error {
	switch {
	case errors.Is(err, smsotp.ErrRateLimited), errors.Is(err, smsotp.ErrLockedOut):
		return ErrRateLimited
	case errors.Is(err, smsotp.ErrInvalidCode), errors.Is(err, smsotp.ErrNoActiveCode):
		return ErrProofRequired
	case errors.Is(err, smsotp.ErrSendFailed):
		return ErrSendFailed
	default:
		return ErrUnavailable
	}
}

// PasskeyOptions freezes a resident-UV ceremony only after both contact proofs.
func (s *Service) PasskeyOptions(ctx context.Context, a Authority) (*protocol.CredentialCreation, error) {
	snapshot, err := s.pending(ctx, a)
	if err != nil {
		return nil, err
	}
	if err = s.requireEmail(snapshot); err != nil {
		return nil, err
	}
	if !snapshot.Record.PhoneVerifiedAt.Valid {
		return nil, ErrProofRequired
	}
	expires := minTime(s.now().Add(PasskeyLifetime), minTime(snapshot.Record.ExpiresAt.Time, snapshot.Record.EmailTokenExpiresAt.Time))
	tx, err := begin(ctx, s.deps.Database)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	authority, err := s.deps.Usernames.GuardAuthority(ctx, tx)
	if err != nil {
		return nil, ErrUnavailable
	}
	attempt, err := s.deps.Store.Lock(ctx, tx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return nil, err
	}
	if attempt.Record.State != "pending" || attempt.Record.RowRevision != snapshot.Record.RowRevision {
		return nil, ErrConflict
	}
	if err = s.requireEmail(attempt); err != nil {
		return nil, err
	}
	if !attempt.Record.PhoneVerifiedAt.Valid {
		return nil, ErrProofRequired
	}
	if _, err := s.frozenUsername(attempt.Details, authority); err != nil {
		return nil, err
	}
	options, ceremony, err := s.deps.WebAuthn.BeginSignup(ctx, attempt.Details.Email, attempt.Details.UserHandle, a.JKT, expires)
	if err != nil {
		return nil, ErrInvalid
	}
	attempt.Record.ChallengeRevision++
	attempt.Record.PasskeyCreatedAt = timestamp(s.now())
	attempt.Record.PasskeyExpiresAt = timestamp(expires)
	attempt.Details.Ceremony = ceremony
	attempt.Details.CeremonyRevision = attempt.Record.ChallengeRevision
	if _, err = s.deps.Store.Save(ctx, tx, attempt); err != nil {
		return nil, err
	}
	if tx.Commit(ctx) != nil {
		return nil, ErrUnavailable
	}
	return options, nil
}

func completionFingerprint(body []byte) ([]byte, error) {
	var value map[string]json.RawMessage
	if len(body) == 0 || len(body) > 64<<10 || json.Unmarshal(body, &value) != nil || value == nil {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalid
	}
	hash := sha256.Sum256(append([]byte("registration:completion:v1:"), canonical...))
	return hash[:], nil
}

// Complete verifies the frozen ceremony and atomically creates one account receipt.
func (s *Service) Complete(ctx context.Context, a Authority, body []byte) (Outcome, error) {
	fingerprint, err := completionFingerprint(body)
	if err != nil {
		return Outcome{}, err
	}
	snapshot, err := s.deps.Store.Get(ctx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return Outcome{}, err
	}
	if _, replay, err := CheckReplay(snapshot, fingerprint); err != nil {
		return Outcome{}, err
	} else if replay {
		return outcome(snapshot), nil
	}
	if snapshot.Record.State != "pending" {
		return Outcome{}, ErrConflict
	}
	if snapshot.Details.UsernameDisplay == "" || snapshot.Details.UsernameAuthority != s.deps.Usernames.Normalizer().Authority() {
		return Outcome{}, ErrUsernamePolicyChanged
	}
	if err = s.requireEmail(snapshot); err != nil {
		return Outcome{}, err
	}
	if !snapshot.Record.PhoneVerifiedAt.Valid || !snapshot.Record.PasskeyExpiresAt.Valid || !s.now().Before(snapshot.Record.PasskeyExpiresAt.Time) || len(snapshot.Details.Ceremony) == 0 {
		return Outcome{}, ErrProofRequired
	}
	tx, err := begin(ctx, s.deps.Database)
	if err != nil {
		return Outcome{}, err
	}
	defer rollback(tx)
	authority, err := s.deps.Usernames.GuardAuthority(ctx, tx)
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	attempt, err := s.deps.Store.Lock(ctx, tx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return Outcome{}, err
	}
	if _, replay, err := CheckReplay(attempt, fingerprint); err != nil {
		return Outcome{}, err
	} else if replay {
		return outcome(attempt), nil
	}
	if attempt.Record.State != "pending" || attempt.Record.RowRevision != snapshot.Record.RowRevision || attempt.Record.ChallengeRevision != snapshot.Record.ChallengeRevision || !sameIdentity(attempt.Details, snapshot.Details) || !bytes.Equal(attempt.Details.Ceremony, snapshot.Details.Ceremony) {
		return Outcome{}, ErrConflict
	}
	if err = s.requireEmail(attempt); err != nil {
		return Outcome{}, err
	}
	if !attempt.Record.PhoneVerifiedAt.Valid || !attempt.Record.PasskeyExpiresAt.Valid || !s.now().Before(attempt.Record.PasskeyExpiresAt.Time) {
		return Outcome{}, ErrExpired
	}
	chosen, err := s.frozenUsername(attempt.Details, authority)
	if err != nil {
		return Outcome{}, err
	}
	credential, err := s.deps.WebAuthn.VerifySignup(ctx, attempt.Details.Email, attempt.Details.UserHandle, a.JKT, attempt.Details.Ceremony, body)
	if err != nil || !credential.UserVerified || !credential.UserPresent || len(credential.ID) == 0 || len(credential.PublicKey) == 0 || credential.UserID != uuid.Nil {
		return Outcome{}, ErrInvalid
	}
	phone, err := s.deps.Encryptor.Encrypt(ctx, []byte(attempt.Details.Phone))
	if err != nil {
		return Outcome{}, ErrUnavailable
	}
	defer clear(phone)
	index := s.deps.Indexer.Compute(attempt.Details.Phone)
	indexBytes, indexErr := hex.DecodeString(index)
	if indexErr != nil || len(indexBytes) != 32 || hex.EncodeToString(indexBytes) != index {
		return Outcome{}, ErrUnavailable
	}
	fresh, err := s.deps.Store.Lock(ctx, tx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return Outcome{}, err
	}
	if fresh.Record.State != "pending" || fresh.Record.RowRevision != attempt.Record.RowRevision || !sameIdentity(fresh.Details, attempt.Details) || fresh.Record.ChallengeRevision != attempt.Record.ChallengeRevision || !bytes.Equal(fresh.Details.Ceremony, attempt.Details.Ceremony) {
		return Outcome{}, ErrConflict
	}
	if err := s.requireEmail(fresh); err != nil {
		return Outcome{}, err
	}
	if !s.now().Before(fresh.Record.PasskeyExpiresAt.Time) {
		return Outcome{}, ErrExpired
	}
	q := db.New(tx)
	user, err := lifecycle.CreateUser(ctx, tx, db.CreateUserParams{Email: attempt.Details.Email, Status: "active"})
	if err != nil {
		if errors.Is(err, lifecycle.ErrIdentityConflict) {
			return Outcome{}, ErrConflict
		}
		return Outcome{}, ErrUnavailable
	}
	if err := s.deps.Usernames.Assign(ctx, tx, user.ID, user.AuthVersion, chosen); err != nil {
		return Outcome{}, usernameError(err)
	}
	affected, err := q.SetWebauthnUserHandle(ctx, db.SetWebauthnUserHandleParams{ID: user.ID, WebauthnUserHandle: attempt.Details.UserHandle})
	if err != nil || affected != 1 {
		if uniqueConflict(err) {
			rollback(tx)
			s.failCollision(ctx, a)
			return Outcome{}, ErrNewCeremony
		}
		return Outcome{}, ErrUnavailable
	}
	credential.UserID = user.ID
	if _, err = q.CreateWebauthnCredential(ctx, credential); err != nil {
		return Outcome{}, writeError(err)
	}
	if affected, err = q.SetUserPhone(ctx, db.SetUserPhoneParams{ID: user.ID, PhoneEncrypted: phone, PhoneBlindIndex: &index}); err != nil || affected != 1 {
		return Outcome{}, writeError(err)
	}
	completed, err := s.deps.Store.Complete(ctx, tx, attempt, user.ID, fingerprint)
	if err != nil {
		return Outcome{}, err
	}
	if tx.Commit(ctx) != nil {
		return Outcome{}, ErrOutcomeUnknown
	}
	return outcome(completed), nil
}

func uniqueConflict(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
func writeError(err error) error {
	if uniqueConflict(err) {
		return ErrConflict
	}
	return ErrUnavailable
}
func (s *Service) failCollision(ctx context.Context, a Authority) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	tx, err := begin(ctx, s.deps.Database)
	if err != nil {
		return
	}
	defer rollback(tx)
	attempt, err := s.deps.Store.Lock(ctx, tx, a.AttemptID, a.Capability, a.JKT)
	if err != nil || attempt.Record.State != "pending" {
		return
	}
	if _, err = s.deps.Store.Fail(ctx, tx, attempt); err == nil {
		_ = tx.Commit(ctx)
	}
}

// Result reads the authorized durable outcome without creating or authenticating an account.
func (s *Service) Result(ctx context.Context, a Authority) (Outcome, error) {
	attempt, err := s.deps.Store.Get(ctx, a.AttemptID, a.Capability, a.JKT)
	if err != nil {
		return Outcome{}, err
	}
	return outcome(attempt), nil
}
func outcome(a Attempt) Outcome {
	result := Outcome{State: a.Record.State, EmailVerified: a.Record.EmailVerifiedAt.Valid, PhoneVerified: a.Record.PhoneVerifiedAt.Valid}
	if a.Record.State == "pending" {
		expires := a.Record.ExpiresAt.Time
		result.ExpiresAt = &expires
	} else {
		expires := a.Record.ReceiptExpiresAt.Time
		result.ReceiptExpiresAt = &expires
	}
	if a.Record.State == "completed" {
		result.Next = "login"
	}
	return result
}
func clearCeremony(a *Attempt) {
	a.Details.Ceremony = nil
	a.Details.CeremonyRevision = 0
	a.Record.PasskeyCreatedAt.Valid = false
	a.Record.PasskeyExpiresAt.Valid = false
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
