// Package smsir implements only the SMS.ir VERIFY POST contract.
package smsir

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Endpoint is the fixed HTTPS SMS.ir verification delivery endpoint.
const Endpoint = "https://api.sms.ir/v1/send/verify"
const responseLimit = 32 << 10

// Reason is a fixed, secret-free delivery failure classification.
type Reason string

const (
	// Credentials identifies missing or invalid provider authentication.
	Credentials Reason = "credentials"
	// Account identifies provider account or sender-line restrictions.
	Account Reason = "account"
	// Egress identifies an unauthorized source IP.
	Egress Reason = "egress"
	// Template identifies an invalid line or verification template.
	Template Reason = "template"
	// Parameters identifies invalid delivery parameters.
	Parameters Reason = "parameters"
	// Credit identifies insufficient provider credit.
	Credit Reason = "credit"
	// Throttle identifies provider-side request or message limits.
	Throttle Reason = "throttle"
	// Recipient identifies an invalid or undeliverable recipient.
	Recipient Reason = "recipient"
	// Unavailable identifies transport or provider availability failures.
	Unavailable Reason = "unavailable"
	// Rejected identifies an unknown rejection or invalid provider response.
	Rejected Reason = "rejected"
)

// Error contains no provider text, destination, code, credential or transport error.
type Error struct{ Reason Reason }

func (e *Error) Error() string { return "smsir: " + string(e.Reason) }

// DeliveryReason returns only the fixed classification, never provider diagnostics.
func (e *Error) DeliveryReason() string { return string(e.Reason) }

// Config contains the explicit credential, template ID, and exact code parameter.
type Config struct {
	APIKey        string
	TemplateID    int64
	CodeParameter string
}

// Sender implements bounded, nonretrying SMS.ir verification delivery.
type Sender struct {
	cfg    Config
	client *http.Client
}

var mobilePattern = regexp.MustCompile(`^\+989[0-9]{9}$`)
var codePattern = regexp.MustCompile(`^[0-9]{6}$`)
var parameterPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,49}$`)

// ValidParameter validates the bounded, exact parameter name without hash delimiters.
func ValidParameter(s string) bool { return parameterPattern.MatchString(s) }

// ValidAPIKey validates bounded printable-ASCII credentials without whitespace.
func ValidAPIKey(s string) bool {
	if len(s) == 0 || len(s) > 512 || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// New has no configurable URL or retry policy. Tests replace the private transport.
func New(cfg Config) (*Sender, error) {
	if !ValidAPIKey(cfg.APIKey) || cfg.TemplateID <= 0 || cfg.TemplateID > math.MaxInt32 || !ValidParameter(cfg.CodeParameter) {
		return nil, errors.New("smsir: invalid configuration")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &Sender{cfg: cfg, client: &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// SendCode posts a six-digit code for an Iranian E.164 mobile without retries.
func (s *Sender) SendCode(ctx context.Context, phone, code string) error {
	if !mobilePattern.MatchString(phone) {
		return &Error{Recipient}
	}
	if !codePattern.MatchString(code) {
		return &Error{Parameters}
	}
	payload := struct {
		Mobile     string `json:"mobile"`
		TemplateID int64  `json:"templateId"`
		Parameters []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"parameters"`
	}{Mobile: phone[3:], TemplateID: s.cfg.TemplateID}
	payload.Parameters = append(payload.Parameters, struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}{s.cfg.CodeParameter, code})
	body, err := json.Marshal(payload)
	if err != nil {
		return &Error{Rejected}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Endpoint, bytes.NewReader(body))
	if err != nil {
		return &Error{Unavailable}
	}
	// Disable the standard transport's zero-bytes-written body replay as well.
	req.GetBody = nil
	req.Header.Set("x-api-key", s.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return &Error{Unavailable}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil || len(raw) > responseLimit {
		return &Error{Unavailable}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return &Error{Throttle}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return &Error{Credentials}
	}
	if resp.StatusCode >= 500 {
		return &Error{Unavailable}
	}
	fields, err := responseObject(raw)
	if err != nil {
		return &Error{Rejected}
	}
	if data, ok := fields["data"]; ok && string(data) != "null" {
		if _, err := responseObject(data); err != nil {
			return &Error{Rejected}
		}
	}
	var result struct {
		Status *int64 `json:"status"`
		Data   *struct {
			MessageID *int64   `json:"messageId"`
			Cost      *float64 `json:"cost"`
		} `json:"data"`
	}
	// Unmarshal rejects trailing data and nonnumeric or fractional integer fields.
	if err := json.Unmarshal(raw, &result); err != nil || result.Status == nil {
		return &Error{Rejected}
	}
	if resp.StatusCode != http.StatusOK {
		if *result.Status != 1 {
			return &Error{classify(*result.Status)}
		}
		return &Error{Rejected}
	}
	if *result.Status != 1 {
		return &Error{classify(*result.Status)}
	}
	if result.Data == nil || result.Data.MessageID == nil || *result.Data.MessageID <= 0 || result.Data.Cost == nil || *result.Data.Cost < 0 || math.IsNaN(*result.Data.Cost) || math.IsInf(*result.Data.Cost, 0) {
		return &Error{Rejected}
	}
	return nil
}

func classify(status int64) Reason {
	switch status {
	case 0:
		return Unavailable
	case 10, 11:
		return Credentials
	case 12:
		return Egress
	case 13, 14, 119, 123:
		return Account
	case 20, 118:
		return Throttle
	case 101, 113:
		return Template
	case 102:
		return Credit
	case 104, 107, 115:
		return Recipient
	case 103, 105, 106, 108, 109, 110, 114, 116:
		return Parameters
	default:
		return Rejected
	}
}

// Reject ambiguous duplicate JSON keys instead of accepting last-wins metadata.
func responseObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid response")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid response")
		}
		folded := strings.ToLower(key)
		if _, exists := fields[folded]; exists {
			return nil, errors.New("duplicate response field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[folded] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing response")
	}
	return fields, nil
}
