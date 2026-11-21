package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type compositionRedisPreloads struct {
	preloads   atomic.Int32
	unexpected atomic.Int32
}

func (h *compositionRedisPreloads) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *compositionRedisPreloads) ProcessHook(_ redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		if cmd.Name() == "script" && len(args) == 3 && args[1] == "load" {
			h.preloads.Add(1)
		} else {
			h.unexpected.Add(1)
		}
		return errors.New("composition fixture rejects optional Redis preload before transport")
	}
}

func (h *compositionRedisPreloads) ProcessPipelineHook(_ redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(context.Context, []redis.Cmder) error {
		h.unexpected.Add(1)
		return errors.New("composition fixture forbids Redis pipelines")
	}
}

func enabledActionProofCompositionEnvironment(t *testing.T) {
	t.Helper()
	productionStartupEnvironment(t)
	for name, value := range map[string]string{
		"LOGIN_ENABLED":                       "false",
		"LOGIN_EMAIL_ENABLED":                 "false",
		"SMS_ENABLED":                         "true",
		"SMS_PROVIDER":                        "smsir",
		"SMS_IR_KEY_MODE":                     "live",
		"SMS_GATEWAY_API_KEY":                 "isolated-composition-fixture-not-a-provider-credential",
		"SMS_IR_TEMPLATE_ID":                  "123",
		"SMS_IR_CODE_PARAMETER":               "CODE",
		"SMS_OTP_HASH_PEPPER":                 base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x45}, 32)),
		"SMS_OTP_CODE_TTL":                    "90s",
		"SMS_OTP_MAX_ATTEMPTS":                "2",
		"SMS_OTP_LOCKOUT_TTL":                 "30m",
		"SMS_OTP_PER_PHONE_PER_MINUTE":        "1",
		"SMS_OTP_PER_PHONE_PER_HOUR":          "3",
		"SMS_OTP_PER_SUBNET_PER_HOUR":         "6",
		"SMS_OTP_GLOBAL_PER_DAY":              "10",
		"SMS_OTP_MAX_PENDING_SIGNUP":          "2",
		"LOGIN_CODE_HMAC_KEY":                 base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x46}, 32)),
		"PASSWORD_CHANGE_PROOFS_BINDING_KEY":  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x47}, 32)),
		"ACCOUNT_DELETION_PROOFS_BINDING_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x48}, 32)),
		"PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID":  "125",
		"ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID": "124",
		"LOGIN_SMTP_HOST":                     "smtp.composition.invalid",
		"LOGIN_SMTP_PORT":                     "465",
		"LOGIN_SMTP_TLS_MODE":                 "implicit",
		"LOGIN_SMTP_USERNAME":                 "composition-fixture-user",
		"LOGIN_SMTP_PASSWORD":                 "composition-fixture-password",
		"LOGIN_SMTP_FROM":                     "security@composition.invalid",
		"LOGIN_SMTP_CA_BUNDLE":                "",
	} {
		t.Setenv(name, value)
	}
}

func TestEnabledActionProofSMSCompositionKeepsPurposeChannelsIndependent(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		passwordSMS, passwordEmail bool
		deletionSMS, deletionEmail bool
	}{
		{name: "no-purpose"},
		{name: "password-sms-only", passwordSMS: true},
		{name: "deletion-sms-only", deletionSMS: true},
		{name: "both-sms", passwordSMS: true, deletionSMS: true},
		{name: "password-sms-deletion-email", passwordSMS: true, deletionEmail: true},
		{name: "password-email-deletion-sms", passwordEmail: true, deletionSMS: true},
		{name: "both-email", passwordEmail: true, deletionEmail: true},
		{name: "both-mixed", passwordSMS: true, passwordEmail: true, deletionSMS: true, deletionEmail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabledActionProofCompositionEnvironment(t)
			for name, enabled := range map[string]bool{
				"PASSWORD_CHANGE_PROOFS_ENABLED":        tc.passwordSMS || tc.passwordEmail,
				"PASSWORD_CHANGE_PROOFS_SMS_ENABLED":    tc.passwordSMS,
				"PASSWORD_CHANGE_PROOFS_EMAIL_ENABLED":  tc.passwordEmail,
				"ACCOUNT_DELETION_PROOFS_ENABLED":       tc.deletionSMS || tc.deletionEmail,
				"ACCOUNT_DELETION_PROOFS_SMS_ENABLED":   tc.deletionSMS,
				"ACCOUNT_DELETION_PROOFS_EMAIL_ENABLED": tc.deletionEmail,
			} {
				t.Setenv(name, strconv.FormatBool(enabled))
			}
			if !tc.deletionSMS && !tc.deletionEmail {
				t.Setenv("ACCOUNT_DELETION_PROOFS_BINDING_KEY", "")
				t.Setenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "")
			}
			if !tc.passwordSMS && !tc.passwordEmail {
				t.Setenv("PASSWORD_CHANGE_PROOFS_BINDING_KEY", "")
				t.Setenv("PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", "")
			}
			login, err := config.LoadLogin("production")
			if err != nil || login.Enabled || login.EmailEnabled {
				t.Fatal("composition fixture enabled login")
			}

			// A zero-value pool cannot execute a query. Reject the rate limiter's
			// optional SCRIPT LOAD before transport, and guard every physical dial.
			pool := &pgxpool.Pool{}
			var dials atomic.Int32
			preloads := &compositionRedisPreloads{}
			expectedPreloads := int32(1)
			if tc.passwordSMS && !tc.passwordEmail {
				expectedPreloads++
			}
			if tc.deletionSMS && !tc.deletionEmail {
				expectedPreloads++
			}
			client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1,
				Dialer: func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("composition fixture forbids Redis I/O")
				},
			})
			client.AddHook(preloads)
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Error("composition Redis client cleanup failed")
				}
				if dials.Load() != 0 {
					t.Error("startup composition attempted Redis I/O")
				}
				if preloads.unexpected.Load() != 0 || preloads.preloads.Load() != expectedPreloads {
					t.Error("composition executed Redis work beyond expected optional script preloads")
				}
			})
			sms, err := buildSMSOTPService("production", pool, client, slog.New(slog.DiscardHandler))
			if err != nil || sms == nil || !sms.DeliveryEnabled() {
				t.Fatal("actual enabled SMS construction failed", err)
			}
			if sms.PasswordChangeDeliveryEnabled() != tc.passwordSMS || sms.DeletionDeliveryEnabled() != tc.deletionSMS {
				t.Fatal("composition coupled password-change and deletion SMS channels")
			}
			if tc.passwordSMS {
				policy, err := sms.ContactPasswordChangePolicy("+989123456789", "203.0.113.8")
				if err != nil || policy.CodeTTL != 90*time.Second || policy.MaxAttempts != 2 || policy.LockoutTTL != 30*time.Minute {
					t.Fatal("composition lost configured password-change SMS policy")
				}
				if tc.deletionSMS {
					deletion, err := sms.ContactDeletionPolicy("+989123456789", "203.0.113.8")
					if err != nil || !reflect.DeepEqual(policy, deletion) {
						t.Fatal("composed purposes do not share exact SMS quotas and lockout")
					}
				}
			}

			store, err := session.NewRedisStore(client)
			if err != nil {
				t.Fatal(err)
			}
			cookie, err := session.NewCookieCodec(session.CookieConfig{Name: session.DefaultCookieName, Secure: true, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			sessions, err := session.NewManager(store, cookie, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: session.NewDBAccountState(pool)})
			if err != nil {
				t.Fatal(err)
			}
			// Email-enabled builders deliberately perform SMTP capability checks.
			// This zero-I/O test composes only SMS-only or disabled proof builders.
			if !tc.passwordEmail {
				proofs, err := buildPasswordChangeProofs("production", pool, client, sessions, sms)
				if err != nil || (proofs != nil) != tc.passwordSMS {
					t.Fatal("password-change proof builder depends on deletion/login enablement", err)
				}
			}
			if !tc.deletionEmail {
				proofs, err := buildAccountDeletionProofs("production", pool, client, sessions, sms)
				if err != nil || (proofs != nil) != tc.deletionSMS {
					t.Fatal("deletion proof builder depends on password-change enablement", err)
				}
			}
		})
	}
}
