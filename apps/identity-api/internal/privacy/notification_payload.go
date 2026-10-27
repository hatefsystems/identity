package privacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
)

const notificationPayloadVersion = 1
const maxNotificationCiphertext = 16384

type notificationPayload struct {
	Version       int       `json:"version"`
	UserID        uuid.UUID `json:"user_id"`
	RequestID     uuid.UUID `json:"request_id"`
	DeliveryID    uuid.UUID `json:"delivery_id"`
	RecipientRole string    `json:"recipient_role"`
	Recipient     string    `json:"recipient"`
	Token         string    `json:"token"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type notificationRecipient struct {
	role    string
	address string
}

func validNotificationAddress(value string) bool {
	return emailaddress.ValidMailbox(value)
}

func (s *Service) deletionRecipients(ctx context.Context, user db.User) ([]notificationRecipient, error) {
	if !validNotificationAddress(user.Email) {
		return nil, errors.New("privacy: invalid primary notification address")
	}
	recipients := []notificationRecipient{{role: "primary", address: user.Email}}
	if len(user.BackupEmailEncrypted) == 0 {
		if user.BackupEmailBlindIndex != nil {
			return nil, errors.New("privacy: backup notification address unavailable")
		}
		return recipients, nil
	}
	plaintext, err := s.cipher.Decrypt(ctx, user.BackupEmailEncrypted)
	if err != nil {
		// Crypto/provider errors are not safe diagnostics: they may contain PII.
		return nil, errors.New("privacy: backup notification address unavailable")
	}
	defer clear(plaintext)
	backup := string(plaintext)
	if !validNotificationAddress(backup) {
		return nil, errors.New("privacy: invalid backup notification address")
	}
	primaryLocal, primaryDomain, _ := strings.Cut(user.Email, "@")
	backupLocal, backupDomain, _ := strings.Cut(backup, "@")
	if primaryLocal != backupLocal || !strings.EqualFold(primaryDomain, backupDomain) {
		recipients = append(recipients, notificationRecipient{role: "backup", address: backup})
	}
	return recipients, nil
}

func (s *Service) enqueueNotices(ctx context.Context, store Store, request db.DeletionRequest, token string, recipients []notificationRecipient) error {
	for _, recipient := range recipients {
		payload := notificationPayload{
			Version: notificationPayloadVersion, UserID: request.UserID, RequestID: request.ID,
			DeliveryID: uuid.New(), RecipientRole: recipient.role, Recipient: recipient.address,
			Token: token, ExpiresAt: request.ExpiresAt.Time.UTC(),
		}
		plaintext, err := json.Marshal(payload)
		if err != nil {
			return errors.New("privacy: encode notification payload")
		}
		ciphertext, err := s.cipher.Encrypt(ctx, plaintext)
		clear(plaintext)
		if err != nil || len(ciphertext) == 0 || len(ciphertext) > maxNotificationCiphertext {
			return errors.New("privacy: encrypt notification payload")
		}
		if _, err := store.CreateDeletionNotification(ctx, db.CreateDeletionNotificationParams{
			ID: payload.DeliveryID, UserID: request.UserID, RequestID: request.ID,
			RecipientRole: recipient.role, PayloadEncrypted: ciphertext, ExpiresAt: request.ExpiresAt,
		}); err != nil {
			return errors.New("privacy: persist notification intent")
		}
	}
	return nil
}

// Every routing/bearer attribute is authenticated inside the envelope and checked
// against the claimed row and live request. Valid ciphertext is not enough:
// swapping envelopes between rows must never reroute a token to another mailbox.
func decodeNotificationPayload(plaintext []byte, row db.DeletionNotification, request db.DeletionRequest) (DeletionNotice, error) {
	invalid := errors.New("privacy: notification payload binding invalid")
	if len(plaintext) == 0 || len(plaintext) > 4096 {
		return DeletionNotice{}, invalid
	}
	var payload notificationPayload
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return DeletionNotice{}, invalid
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return DeletionNotice{}, invalid
	}
	if payload.Version != notificationPayloadVersion || payload.UserID != row.UserID ||
		payload.UserID != request.UserID || payload.RequestID != row.RequestID || payload.RequestID != request.ID ||
		payload.DeliveryID == uuid.Nil || payload.DeliveryID != row.ID || payload.RecipientRole != row.RecipientRole ||
		(payload.RecipientRole != "primary" && payload.RecipientRole != "backup") ||
		!row.ExpiresAt.Valid || !request.ExpiresAt.Valid || !payload.ExpiresAt.Equal(row.ExpiresAt.Time) ||
		!payload.ExpiresAt.Equal(request.ExpiresAt.Time) || !validReclaimToken(payload.Token) ||
		HashReclaimToken(payload.Token) != request.TokenHash || !validNotificationAddress(payload.Recipient) {
		return DeletionNotice{}, invalid
	}
	return DeletionNotice{DeliveryID: row.ID, PrimaryEmail: payload.Recipient, ReclaimToken: payload.Token, ExpiresAt: payload.ExpiresAt}, nil
}
