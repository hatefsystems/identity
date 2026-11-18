// Package contactproof authenticates evidence for one exact current contact.
package contactproof

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
)

// Channels and methods are fixed proof categories, never bearer capabilities.
const (
	Email     = "email"
	Phone     = "phone"
	EmailLink = "email_link"
	SMSOTP    = "sms_otp"
	purpose   = "contact_verification_evidence:v1"
)

// ErrInvalid never includes private material or underlying crypto diagnostics.
var ErrInvalid = errors.New("contactproof: invalid evidence or binding")

var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

// Encryptor uses the existing authenticated envelope implementation.
type Encryptor interface {
	Encrypt(context.Context, []byte) ([]byte, error)
}

// Cipher authenticates envelopes before returning any evidence.
type Cipher interface {
	Encryptor
	Decrypt(context.Context, []byte) ([]byte, error)
}

// Evidence contains only proof binding and original server-recorded time.
type Evidence struct {
	Purpose     string    `json:"purpose"`
	AccountID   uuid.UUID `json:"account_id"`
	Channel     string    `json:"channel"`
	Destination string    `json:"destination"`
	Method      string    `json:"method"`
	VerifiedAt  time.Time `json:"verified_at"`
}

func valid(e Evidence) bool {
	if e.Purpose != purpose || e.AccountID == uuid.Nil || e.VerifiedAt.IsZero() || e.VerifiedAt.Year() < 1 || e.VerifiedAt.Year() > 9999 || !e.VerifiedAt.Equal(e.VerifiedAt.UTC().Truncate(time.Microsecond)) {
		return false
	}
	return e.Channel == Email && e.Method == EmailLink && emailaddress.ValidCanonicalMailbox(e.Destination) ||
		e.Channel == Phone && e.Method == SMSOTP && phonePattern.MatchString(e.Destination)
}

// Seal binds account/channel/exact canonical destination/method/time inside AEAD.
// There is deliberately no OTP, link token, or reusable proof identifier.
func Seal(ctx context.Context, cipher Encryptor, id uuid.UUID, channel, destination, method string, verifiedAt time.Time) ([]byte, error) {
	e := Evidence{purpose, id, channel, destination, method, verifiedAt.UTC().Truncate(time.Microsecond)}
	if cipher == nil || !valid(e) {
		return nil, ErrInvalid
	}
	plain, err := json.Marshal(e)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(plain)
	blob, err := cipher.Encrypt(ctx, plain)
	if err != nil || len(blob) < 90 || len(blob) > 4096 {
		return nil, ErrInvalid
	}
	return blob, nil
}

// Open distinguishes absence from unreadable or substituted evidence. A valid
// envelope for another account, purpose, channel or destination never verifies.
func Open(ctx context.Context, cipher Cipher, blob []byte, id uuid.UUID, channel, destination string) (*Evidence, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	if cipher == nil || len(blob) < 90 || len(blob) > 4096 {
		return nil, ErrInvalid
	}
	plain, err := cipher.Decrypt(ctx, blob)
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > 4007 {
		return nil, ErrInvalid
	}
	var e Evidence
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&e) != nil || decoder.Decode(new(any)) != io.EOF || !valid(e) || e.AccountID != id || e.Channel != channel || e.Destination != destination || e.VerifiedAt.After(time.Now()) {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(plain, canonical) {
		return nil, ErrInvalid
	}
	return &e, nil
}

// Read checks the protected proof against the contact in the same SQL snapshot.
func Read(ctx context.Context, q *db.Queries, cipher Cipher, id uuid.UUID, channel string) (*Evidence, error) {
	if q == nil || id == uuid.Nil || channel != Email && channel != Phone {
		return nil, ErrInvalid
	}
	row, err := q.GetCurrentContactEvidence(ctx, db.GetCurrentContactEvidenceParams{UserID: id, Channel: channel})
	if err != nil || row.ID != id {
		return nil, ErrInvalid
	}
	if len(row.EvidenceEncrypted) == 0 {
		return nil, nil
	}
	destination := ""
	if channel == Email && row.Email != nil {
		destination = *row.Email
	}
	if channel == Phone && len(row.PhoneEncrypted) != 0 {
		if cipher == nil {
			return nil, ErrInvalid
		}
		plain, err := cipher.Decrypt(ctx, row.PhoneEncrypted)
		if err != nil {
			return nil, ErrInvalid
		}
		destination = string(plain)
		clear(plain)
	}
	return Open(ctx, cipher, row.EvidenceEncrypted, id, channel, destination)
}
