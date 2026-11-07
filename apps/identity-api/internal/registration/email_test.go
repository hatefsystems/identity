package registration

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

type recordingMail struct {
	recipient string
	message   []byte
	calls     int
	deadline  time.Time
	err       error
	before    func()
}

func (m *recordingMail) Send(ctx context.Context, recipient string, message []byte) error {
	if m.before != nil {
		m.before()
	}
	m.calls++
	m.recipient = recipient
	m.message = bytes.Clone(message)
	m.deadline, _ = ctx.Deadline()
	return m.err
}
func TestSignupEmailFragmentBindingAndExpiry(t *testing.T) {
	store, attempt, _ := pendingFixture(t)
	attempt.Details.Email = "\u062d\u0633\u0627\u0628@example.com"
	attempt.Record.EmailTokenExpiresAt = timestamp(store.now().Add(time.Minute))
	mail := &recordingMail{}
	email, err := NewEmail(EmailConfig{From: "identity@example.com", PublicOrigin: "https://identity.example.com"}, mail)
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{4}, 32)
	attempt.Record.EmailTokenHash, _ = HashCapability(token)
	if err = email.SendProof(t.Context(), attempt, token); err != nil {
		t.Fatal(err)
	}
	want := "https://identity.example.com/register/verify-email#attempt_id=" + attempt.Record.ID.String() + "&token=" + base64.RawURLEncoding.EncodeToString(token)
	if mail.recipient != attempt.Details.Email || !strings.Contains(string(mail.message), want) || !strings.Contains(string(mail.message), "To: <"+mail.recipient+">") || !mail.deadline.Equal(attempt.Record.EmailTokenExpiresAt.Time) || strings.Contains(string(mail.message), "?token=") {
		t.Fatal("mail identity/fragment/deadline drift")
	}
	mail.err = errors.New("private relay secret token")
	if err = email.SendProof(t.Context(), attempt, token); !errors.Is(err, ErrSendFailed) || strings.Contains(err.Error(), "private") {
		t.Fatal("raw relay diagnostic escaped")
	}
}
func TestSignupEmailRejectsUnsafeOriginSenderAndToken(t *testing.T) {
	for _, origin := range []string{"https://identity.example.com/", "https://identity.example.com?", "https://identity.example.com#", "http://identity.example.com", "https://user@identity.example.com"} {
		if _, err := NewEmail(EmailConfig{From: "identity@example.com", PublicOrigin: origin}, &recordingMail{}); err == nil {
			t.Fatalf("unsafe origin accepted %s", origin)
		}
	}
	if _, err := NewEmail(EmailConfig{From: "\u062d@example.com", PublicOrigin: "https://identity.example.com"}, &recordingMail{}); err == nil {
		t.Fatal("Unicode system sender accepted")
	}
	_, attempt, _ := pendingFixture(t)
	mail := &recordingMail{}
	email, _ := NewEmail(EmailConfig{From: "identity@example.com", PublicOrigin: "https://identity.example.com"}, mail)
	if err := email.SendProof(t.Context(), attempt, make([]byte, 31)); err == nil || mail.calls != 0 {
		t.Fatal("invalid token sent")
	}
}
