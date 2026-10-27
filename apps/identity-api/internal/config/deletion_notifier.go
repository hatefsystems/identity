package config

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
)

// SMTP settings are independent of new-deletion enablement: pending notices must
// remain deliverable while the API's deletion switch is off.
const (
	EnvDeletionSMTPHost         = "DELETION_SMTP_HOST"
	EnvDeletionSMTPPort         = "DELETION_SMTP_PORT"
	EnvDeletionSMTPTLSMode      = "DELETION_SMTP_TLS_MODE"
	EnvDeletionSMTPUsername     = "DELETION_SMTP_USERNAME"
	EnvDeletionSMTPPassword     = "DELETION_SMTP_PASSWORD" //nolint:gosec // Environment variable name, not a credential.
	EnvDeletionSMTPFrom         = "DELETION_SMTP_FROM"
	EnvDeletionSMTPPublicOrigin = "DELETION_SMTP_PUBLIC_ORIGIN"
	EnvDeletionSMTPTimeout      = "DELETION_SMTP_TIMEOUT"
	EnvDeletionSMTPCABundle     = "DELETION_SMTP_CA_BUNDLE"

	EnvDeletionNotifierDatabaseURL    = "DELETION_NOTIFIER_DATABASE_URL"
	EnvDeletionNotifierBatchSize      = "DELETION_NOTIFIER_BATCH_SIZE"
	EnvDeletionNotifierConcurrency    = "DELETION_NOTIFIER_CONCURRENCY"
	EnvDeletionNotifierLeaseDuration  = "DELETION_NOTIFIER_LEASE_DURATION"
	EnvDeletionNotifierRetryBase      = "DELETION_NOTIFIER_RETRY_BASE"
	EnvDeletionNotifierRetryMax       = "DELETION_NOTIFIER_RETRY_MAX"
	EnvDeletionNotifierPollInterval   = "DELETION_NOTIFIER_POLL_INTERVAL"
	EnvDeletionNotifierStartupTimeout = "DELETION_NOTIFIER_STARTUP_TIMEOUT"

	DeletionSMTPStartTLS = "starttls"
	DeletionSMTPImplicit = "implicit"
)

// DeletionSMTPConfig intentionally has no plaintext or skip-verification option.
// Credentials and addresses must never be logged, including the whole config.
type DeletionSMTPConfig struct {
	Host         string
	Port         int
	TLSMode      string
	Username     string
	Password     string
	From         string
	PublicOrigin string
	Timeout      time.Duration
	// CABundlePath selects an explicit PEM trust store instead of system roots.
	CABundlePath string
}

// DeletionNotifierConfig uses a dedicated database identity, not API credentials.
// The command maps these primitive settings to privacy.NotificationConfig; this
// package must not import privacy or its SMTP child package.
type DeletionNotifierConfig struct {
	DatabaseURL        string
	SMTP               DeletionSMTPConfig
	BatchSize          int
	Concurrency        int
	LeaseDuration      time.Duration
	RetryBase          time.Duration
	RetryMax           time.Duration
	PollInterval       time.Duration
	StartupTimeout     time.Duration
	GracePeriod        time.Duration
	ReclaimMaxAttempts int
}

// LoadDeletionSMTP loads a verified, authenticated relay configuration. Errors
// identify settings, never their supplied values, parser errors, or credentials.
func LoadDeletionSMTP() (DeletionSMTPConfig, error) {
	cfg := DeletionSMTPConfig{
		Host:         os.Getenv(EnvDeletionSMTPHost),
		TLSMode:      getEnv(EnvDeletionSMTPTLSMode, DeletionSMTPStartTLS),
		Username:     os.Getenv(EnvDeletionSMTPUsername),
		Password:     os.Getenv(EnvDeletionSMTPPassword),
		From:         os.Getenv(EnvDeletionSMTPFrom),
		PublicOrigin: os.Getenv(EnvDeletionSMTPPublicOrigin),
		CABundlePath: os.Getenv(EnvDeletionSMTPCABundle),
	}
	portDefault := int64(587)
	if cfg.TLSMode == DeletionSMTPImplicit {
		portDefault = 465
	}
	port, err := lifecycleInt(EnvDeletionSMTPPort, portDefault, 1, 65535)
	if err != nil {
		return DeletionSMTPConfig{}, err
	}
	cfg.Port = int(port)
	if cfg.Timeout, err = lifecycleDuration(EnvDeletionSMTPTimeout, 15*time.Second, time.Millisecond, time.Minute); err != nil {
		return DeletionSMTPConfig{}, err
	}
	if err := cfg.Validate(); err != nil {
		return DeletionSMTPConfig{}, err
	}
	return cfg, nil
}

// Validate also protects direct construction by a command or test.
func (c DeletionSMTPConfig) Validate() error {
	if !deletionSMTPHost(c.Host) {
		return fmt.Errorf("config: %s requires a canonical DNS name or IP address", EnvDeletionSMTPHost)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("config: %s must be in 1..65535", EnvDeletionSMTPPort)
	}
	if c.TLSMode != DeletionSMTPStartTLS && c.TLSMode != DeletionSMTPImplicit {
		return fmt.Errorf("config: %s must be starttls or implicit", EnvDeletionSMTPTLSMode)
	}
	if !deletionSMTPASCII(c.Username, 1, 256, false) {
		return fmt.Errorf("config: %s requires bounded nonempty ASCII credentials", EnvDeletionSMTPUsername)
	}
	if !deletionSMTPASCII(c.Password, 1, 1024, true) || strings.TrimSpace(c.Password) == "" {
		return fmt.Errorf("config: %s requires bounded nonempty ASCII credentials", EnvDeletionSMTPPassword)
	}
	if err := ValidateDeletionSMTPAddress(c.From); err != nil {
		return fmt.Errorf("config: %s requires a single bare ASCII mailbox", EnvDeletionSMTPFrom)
	}
	if len(c.PublicOrigin) > 512 {
		return fmt.Errorf("config: %s requires a canonical HTTPS origin", EnvDeletionSMTPPublicOrigin)
	}
	if _, err := canonicalPortalOrigin(c.PublicOrigin, "production"); err != nil {
		return fmt.Errorf("config: %s requires a canonical HTTPS origin", EnvDeletionSMTPPublicOrigin)
	}
	if c.Timeout < time.Millisecond || c.Timeout > time.Minute {
		return fmt.Errorf("config: %s must be in 1ms..1m", EnvDeletionSMTPTimeout)
	}
	if c.CABundlePath != "" && (!deletionSMTPASCII(c.CABundlePath, 1, 4096, true) || strings.TrimSpace(c.CABundlePath) != c.CABundlePath) {
		return fmt.Errorf("config: %s requires a bounded file path", EnvDeletionSMTPCABundle)
	}
	return nil
}

// ValidateDeletionSMTPAddress accepts exactly one ASCII dot-atom mailbox. The
// transport shares this validator for recipients; display names, quoted local
// parts, address lists, literals and SMTPUTF8 are intentionally unsupported.
func ValidateDeletionSMTPAddress(address string) error {
	if !emailaddress.ValidMailbox(address) {
		return errors.New("deletion smtp: invalid mailbox")
	}
	return nil
}

func deletionSMTPASCII(value string, minimum, maximum int, spaces bool) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if value[i] < 33 && (!spaces || value[i] != ' ') || value[i] > 126 {
			return false
		}
	}
	return true
}

func deletionSMTPHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == host
	}
	if len(host) == 0 || len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// LoadDeletionNotifier loads delivery bounds without reading the API feature
// switch. SMTP's end-to-end timeout also bounds each core worker send.
func LoadDeletionNotifier() (DeletionNotifierConfig, error) {
	cfg := DeletionNotifierConfig{DatabaseURL: os.Getenv(EnvDeletionNotifierDatabaseURL)}
	if strings.TrimSpace(cfg.DatabaseURL) == "" || strings.TrimSpace(cfg.DatabaseURL) != cfg.DatabaseURL ||
		len(cfg.DatabaseURL) > 8192 || strings.ContainsAny(cfg.DatabaseURL, "\x00\r\n") {
		return DeletionNotifierConfig{}, fmt.Errorf("config: %s requires an explicit bounded database DSN; DATABASE_URL is not a fallback", EnvDeletionNotifierDatabaseURL)
	}
	var err error
	if cfg.SMTP, err = LoadDeletionSMTP(); err != nil {
		return DeletionNotifierConfig{}, err
	}
	batch, err := lifecycleInt(EnvDeletionNotifierBatchSize, 50, 1, 200)
	if err != nil {
		return DeletionNotifierConfig{}, err
	}
	cfg.BatchSize = int(batch)
	concurrency, err := lifecycleInt(EnvDeletionNotifierConcurrency, 4, 1, 16)
	if err != nil {
		return DeletionNotifierConfig{}, err
	}
	cfg.Concurrency = int(concurrency)
	for _, field := range []struct {
		key          string
		destination  *time.Duration
		fallback     time.Duration
		minimum, max time.Duration
	}{
		{EnvDeletionNotifierLeaseDuration, &cfg.LeaseDuration, time.Minute, time.Second, 5 * time.Minute},
		{EnvDeletionNotifierRetryBase, &cfg.RetryBase, 30 * time.Second, time.Second, time.Hour},
		{EnvDeletionNotifierRetryMax, &cfg.RetryMax, time.Hour, time.Second, 24 * time.Hour},
		{EnvDeletionNotifierPollInterval, &cfg.PollInterval, 5 * time.Second, 10 * time.Millisecond, time.Minute},
		{EnvDeletionNotifierStartupTimeout, &cfg.StartupTimeout, 15 * time.Second, time.Millisecond, time.Minute},
	} {
		if *field.destination, err = lifecycleDuration(field.key, field.fallback, field.minimum, field.max); err != nil {
			return DeletionNotifierConfig{}, err
		}
	}
	if cfg.LeaseDuration < cfg.SMTP.Timeout+5*time.Second {
		return DeletionNotifierConfig{}, errors.New("config: deletion notifier lease must exceed SMTP timeout by at least 5s")
	}
	if cfg.RetryMax < cfg.RetryBase {
		return DeletionNotifierConfig{}, errors.New("config: deletion notifier retry maximum must not be below retry base")
	}
	// Read only shared recovery policy, not API enablement, rate limits or purge
	// settings. Disabling new deletion requests must not strand accepted notices.
	if cfg.GracePeriod, err = lifecycleDuration(EnvGDPRGracePeriod, defaultGDPRGracePeriod, MinGDPRGracePeriod, math.MaxInt64); err != nil {
		return DeletionNotifierConfig{}, err
	}
	if environment := os.Getenv("APP_ENV"); environment != "development" && environment != "test" && cfg.GracePeriod != defaultGDPRGracePeriod {
		return DeletionNotifierConfig{}, fmt.Errorf("config: %s must be 720h outside development/test", EnvGDPRGracePeriod)
	}
	attempts, err := lifecycleInt(EnvGDPRReclaimMaxAttempts, defaultGDPRReclaimMaxAttempts, 1, math.MaxInt32)
	if err != nil {
		return DeletionNotifierConfig{}, err
	}
	cfg.ReclaimMaxAttempts = int(attempts)
	return cfg, nil
}
