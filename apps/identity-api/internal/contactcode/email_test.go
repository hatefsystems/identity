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
