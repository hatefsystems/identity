package privacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
	"github.com/hatefsystems/identity/apps/identity-api/internal/notification"
)

const notificationPayloadVersion = 2
const maxNotificationCiphertext = 16384

type notificationPayload struct {
	Version         int                          `json:"version"`
	UserID          uuid.UUID                    `json:"user_id"`
	RequestID       uuid.UUID                    `json:"request_id"`
	DeliveryID      uuid.UUID                    `json:"delivery_id"`
	RecipientRole   string                       `json:"recipient_role"`
	Recipient       string                       `json:"recipient"`
	Token           string                       `json:"token"`
	ExpiresAt       time.Time                    `json:"expires_at"`
	Locale          notification.Locale          `json:"locale,omitempty"`
	TemplateVersion notification.TemplateVersion `json:"template_version,omitempty"`
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

func (s *Service) enqueueNotices(ctx context.Context, store Store, request db.DeletionRequest, token string, recipients []notificationRecipient, locale notification.Locale) error {
	for _, recipient := range recipients {
		payload := notificationPayload{
			Version: notificationPayloadVersion, UserID: request.UserID, RequestID: request.ID,
			DeliveryID: uuid.New(), RecipientRole: recipient.role, Recipient: recipient.address,
			Token: token, ExpiresAt: request.ExpiresAt.Time.UTC(),
			Locale: locale, TemplateVersion: notification.CurrentVersion,
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
	if len(plaintext) == 0 || len(plaintext) > 4096 || !utf8.Valid(plaintext) {
		return DeletionNotice{}, invalid
	}
	// Reject duplicate, case-aliased, missing and null fields rather than letting
	// encoding/json silently choose one interpretation of authenticated intent.
	fields := make(map[string]bool, 10)
	keys := json.NewDecoder(bytes.NewReader(plaintext))
	if start, err := keys.Token(); err != nil || start != json.Delim('{') {
		return DeletionNotice{}, invalid
	}
	for keys.More() {
		key, err := keys.Token()
		if err != nil {
			return DeletionNotice{}, invalid
		}
		name, ok := key.(string)
		if !ok || fields[name] {
			return DeletionNotice{}, invalid
		}
		switch name {
		case "version", "user_id", "request_id", "delivery_id", "recipient_role", "recipient", "token", "expires_at", "locale", "template_version":
		default:
			return DeletionNotice{}, invalid
		}
		var value json.RawMessage
		if err := keys.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return DeletionNotice{}, invalid
		}
		fields[name] = true
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
	switch payload.Version {
	case 1:
		if len(fields) != 8 || fields["locale"] || fields["template_version"] {
			return DeletionNotice{}, invalid
		}
		payload.Locale, payload.TemplateVersion = notification.English, notification.Version1
	case notificationPayloadVersion:
		if len(fields) != 10 {
			return DeletionNotice{}, invalid
		}
	default:
		return DeletionNotice{}, invalid
	}
	if _, ok := notification.Catalog(payload.Locale, payload.TemplateVersion); !ok {
		return DeletionNotice{}, invalid
	}
	if payload.UserID == uuid.Nil || payload.RequestID == uuid.Nil || payload.UserID != row.UserID ||
		payload.UserID != request.UserID || payload.RequestID != row.RequestID || payload.RequestID != request.ID ||
		payload.DeliveryID == uuid.Nil || payload.DeliveryID != row.ID || payload.RecipientRole != row.RecipientRole ||
		(payload.RecipientRole != "primary" && payload.RecipientRole != "backup") ||
		!row.ExpiresAt.Valid || !request.ExpiresAt.Valid || !payload.ExpiresAt.Equal(row.ExpiresAt.Time) ||
		!payload.ExpiresAt.Equal(request.ExpiresAt.Time) || !validReclaimToken(payload.Token) ||
		HashReclaimToken(payload.Token) != request.TokenHash || !validNotificationAddress(payload.Recipient) {
		return DeletionNotice{}, invalid
	}
	return DeletionNotice{DeliveryID: row.ID, PrimaryEmail: payload.Recipient, ReclaimToken: payload.Token, ExpiresAt: payload.ExpiresAt,
		Locale: payload.Locale, TemplateVersion: payload.TemplateVersion}, nil
}
