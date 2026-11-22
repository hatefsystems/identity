package contactcode

import (
	"context"
	"strings"
	"testing"
	"time"
)

type captureMail struct {
	calls     int
	recipient string
	message   []byte
	deadline  time.Time
	err       error
}

func (m *captureMail) Send(ctx context.Context, recipient string, message []byte) error {
	m.calls++
	m.recipient, m.message = recipient, append([]byte(nil), message...)
	m.deadline, _ = ctx.Deadline()
	return m.err
}

func TestEmailReusesTransportAndExactRecipientWithoutSignupCapability(t *testing.T) {
	transport := &captureMail{}
	email, err := NewEmail("security@example.test", transport)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)
	destination := "\u0645\u0627\u0644\u06a9@example.test"
	if err := email.SendCode(context.Background(), destination, "000042", expires); err != nil {
		t.Fatal(err)
	}
	message := string(transport.message)
	if transport.calls != 1 || transport.recipient != destination || !transport.deadline.Equal(expires) || !strings.Contains(message, "000042\r\n") || !strings.Contains(message, expires.Format(time.RFC3339Nano)) || strings.Contains(message, "#token=") || strings.Contains(message, "https://") || strings.Contains(message, "attempt_id=") {
		t.Fatal("transport adapter changed canonical destination, expiry or signup purpose")
	}
	transport.err = errPrivate
	if err := email.SendCode(context.Background(), destination, "000042", expires); err != ErrOutcomeUnknown || transport.calls != 2 {
		t.Fatal("ambiguous SMTP acceptance retried or became definite failure")
	}
}

func TestEmailValidationDoesNotSubmit(t *testing.T) {
	transport := &captureMail{}
	for _, from := range []string{"", "bad", "security@example.test\r\nBcc: owner@example.test", "\u0645\u0627\u0644\u06a9@example.test"} {
		if _, err := NewEmail(from, transport); err != ErrInvalid {
			t.Fatal("unsafe system sender accepted")
		}
	}
	if _, err := NewEmail("security@example.test", nil); err != ErrInvalid {
		t.Fatal("missing SMTP transport accepted")
	}
	email, _ := NewEmail("security@example.test", transport)
	for _, code := range []string{"", "12345", "1234567", "12 456", "\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6"} {
		if err := email.SendCode(context.Background(), "owner@example.test", code, time.Now().Add(time.Minute)); err != ErrInvalid {
			t.Fatal("invalid code submitted to SMTP")
		}
	}
	if transport.calls != 0 {
		t.Fatal("invalid input sent email")
	}
}

func TestDeletionEmailCopyIsExplicitAndPreservesExactDelivery(t *testing.T) {
	transport := &captureMail{}
	email, err := NewDeletionEmail("security@example.test", transport)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)
	destination := "\u0645\u0627\u0644\u06a9@example.test"
	if err := email.SendCode(context.Background(), destination, "000042", expires); err != nil {
		t.Fatal(err)
	}
	message := string(transport.message)
	if transport.calls != 1 || transport.recipient != destination || !transport.deadline.Equal(expires) || !strings.Contains(message, "Subject: Your account-deletion request code\r\n") || !strings.Contains(message, "authorizes one account-deletion request") || !strings.Contains(message, "000042\r\n") || !strings.Contains(message, expires.Format(time.RFC3339Nano)) || strings.Contains(message, "Your account sign-in code") || strings.Contains(message, "started signing in") || strings.Contains(message, "#token=") || strings.Contains(message, "https://") {
		t.Fatal("deletion copy reused login or changed exact delivery bytes/deadline")
	}
	transport.err = errPrivate
	if err := email.SendCode(context.Background(), destination, "000042", expires); err != ErrOutcomeUnknown || transport.calls != 2 {
		t.Fatal("deletion SMTP unknown acceptance was retried or hidden")
	}
	for _, code := range []string{"12345", "1234567", "\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6"} {
		if err := email.SendCode(context.Background(), destination, code, expires); err != ErrInvalid {
			t.Fatal("invalid deletion code sent")
		}
	}
	if transport.calls != 2 {
		t.Fatal("invalid deletion delivery invoked SMTP")
	}
	if _, err := NewDeletionEmail("security@example.test\r\nBcc: private@example.test", transport); err != ErrInvalid {
		t.Fatal("deletion accepted unsafe system sender")
	}
	if _, err := NewDeletionEmail("security@example.test", nil); err != ErrInvalid {
		t.Fatal("deletion accepted missing transport")
	}
}

func TestPasswordChangeEmailCopyAndOriginalDeadline(t *testing.T) {
	transport := &captureMail{}
	email, err := NewPasswordChangeEmail("security@example.test", transport)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)
	if err := email.SendCode(t.Context(), "owner@example.test", "000042", expires); err != nil {
		t.Fatal(err)
	}
	message := string(transport.message)
	for _, text := range []string{"Subject: Your password-change code\r\n", "authorizes one password change", "cannot sign you in, add or remove a password, delete your account", "000042\r\n", expires.Format(time.RFC3339Nano)} {
		if !strings.Contains(message, text) {
			t.Fatal("password-change copy lost fixed security meaning/deadline")
		}
	}
	if !transport.deadline.Equal(expires) || transport.calls != 1 || strings.Contains(message, "Subject: Your account-deletion") || strings.Contains(message, "#token=") {
		t.Fatal("password change reused deletion copy or changed delivery lifetime")
	}
}

func TestFirstPasskeyEmailDistinctCopyAndExactDeadline(t *testing.T) {
	transport := &captureMail{}
	email, err := NewFirstPasskeyEmail("security@example.test", transport)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)
	if err := email.SendCode(t.Context(), "owner@example.test", "000042", expires); err != nil {
		t.Fatal(err)
	}
	message := string(transport.message)
	for _, text := range []string{"Subject: Your first-passkey enrollment code\r\n", "authorizes one first-passkey enrollment start", "cannot sign you in, change your password, delete your account", "000042\r\n", expires.Format(time.RFC3339Nano)} {
		if !strings.Contains(message, text) {
			t.Fatal("first-passkey copy lost security meaning/deadline")
		}
	}
	if !transport.deadline.Equal(expires) || transport.calls != 1 || strings.Contains(message, "Subject: Your password-change") || strings.Contains(message, "Subject: Your account-deletion") || strings.Contains(message, "#token=") {
		t.Fatal("first passkey reused another purpose or changed lifetime")
	}
	transport.err = errPrivate
	if err := email.SendCode(t.Context(), "owner@example.test", "000042", expires); err != ErrOutcomeUnknown || transport.calls != 2 {
		t.Fatal("first-passkey SMTP uncertainty retried or hid outcome")
	}
}
