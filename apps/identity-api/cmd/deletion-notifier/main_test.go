package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy/smtp"
)

var errPrivate = errors.New("private-recipient@example.test private-token postgres://private-user:private-password@host/db private-relay-reply")

type testDatabase struct {
	db.DBTX
	ping                 func(context.Context) error
	pings, closes, reads int
}

func (d *testDatabase) Ping(ctx context.Context) error {
	d.pings++
	if d.ping != nil {
		return d.ping(ctx)
	}
	return nil
}

func (d *testDatabase) Close() { d.closes++ }

func (*testDatabase) Begin(context.Context) (pgx.Tx, error) { return nil, errPrivate }

func (d *testDatabase) Query(context.Context, string, ...any) (pgx.Rows, error) {
	d.reads++
	return emptyRows{}, nil
}

type emptyRows struct{ pgx.Rows }

func (emptyRows) Next() bool { return false }
func (emptyRows) Err() error { return nil }
func (emptyRows) Close()     {}

type testWorker struct {
	run     func(context.Context) (privacy.NotificationStats, error)
	passes  int
	bounded bool
}

func (w *testWorker) RunOnce(ctx context.Context) (privacy.NotificationStats, error) {
	w.passes++
	deadline, ok := ctx.Deadline()
	w.bounded = ok && time.Until(deadline) > 0 && time.Until(deadline) <= maxPassDuration
	if w.run != nil {
		return w.run(ctx)
	}
	return privacy.NotificationStats{Considered: 3, Claimed: 2, Accepted: 1, Retried: 1, Failed: 1, Cleaned: 2, SkippedLegalHold: 1}, nil
}

type commandState struct {
	database                 testDatabase
	worker                   testWorker
	opens, builds            int
	dsn                      string
	startupBounded           bool
	workerConfig             privacy.NotificationConfig
	cipher                   privacy.Cipher
	notifier                 privacy.Notifier
	openErr, buildErr        error
	nilDatabase, partialOpen bool
	nilWorker                bool
}

func (s *commandState) dependencies() commandDependencies {
	return commandDependencies{
		openDatabase: func(ctx context.Context, dsn string) (workerDatabase, error) {
			s.opens++
			s.dsn = dsn
			deadline, ok := ctx.Deadline()
			s.startupBounded = ok && time.Until(deadline) > 0 && time.Until(deadline) <= 15*time.Second
			if s.nilDatabase || s.openErr != nil && !s.partialOpen {
				return nil, s.openErr
			}
			return &s.database, s.openErr
		},
		newWorker: func(cfg privacy.NotificationConfig, _ workerDatabase, cipher privacy.Cipher, notifier privacy.Notifier, _ *slog.Logger) (notificationWorker, error) {
			s.builds++
			s.workerConfig, s.cipher, s.notifier = cfg, cipher, notifier
			if s.buildErr != nil || s.nilWorker {
				return nil, s.buildErr
			}
			return &s.worker, nil
		},
	}
}

func commandEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		config.EnvDeletionSMTPHost, config.EnvDeletionSMTPPort, config.EnvDeletionSMTPTLSMode,
		config.EnvDeletionSMTPUsername, config.EnvDeletionSMTPPassword, config.EnvDeletionSMTPFrom,
		config.EnvDeletionSMTPPublicOrigin, config.EnvDeletionSMTPTimeout, config.EnvDeletionSMTPCABundle,
		config.EnvDeletionNotifierDatabaseURL, config.EnvDeletionNotifierBatchSize, config.EnvDeletionNotifierConcurrency,
		config.EnvDeletionNotifierLeaseDuration, config.EnvDeletionNotifierRetryBase, config.EnvDeletionNotifierRetryMax,
		config.EnvDeletionNotifierPollInterval, config.EnvDeletionNotifierStartupTimeout,
		config.EnvMasterKEK, config.EnvMasterKEKVersion, config.EnvBlindIndexPepper,
		config.EnvGDPRGracePeriod, config.EnvGDPRReclaimMaxAttempts,
	} {
		t.Setenv(key, "")
	}
	t.Setenv("APP_ENV", "production")
	t.Setenv("DATABASE_URL", "postgres://unrelated:private-password@api/identity")
	t.Setenv("GDPR_DELETION_ENABLED", "false")
	t.Setenv(config.EnvDeletionNotifierDatabaseURL, "postgres://notifier:private-password@worker/identity")
	t.Setenv(config.EnvDeletionSMTPHost, "relay.example.test")
	t.Setenv(config.EnvDeletionSMTPUsername, "private-user")
	t.Setenv(config.EnvDeletionSMTPPassword, "private-password")
	t.Setenv(config.EnvDeletionSMTPFrom, "accounts@example.test")
	t.Setenv(config.EnvDeletionSMTPPublicOrigin, "https://identity.example.test")
	t.Setenv(config.EnvMasterKEK, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32)))
	t.Setenv(config.EnvMasterKEKVersion, "7")
}

func assertCommandRedacted(t *testing.T, logs string, err error) {
	t.Helper()
	if strings.Contains(logs+fmt.Sprintf("%v %+v %#v", err, err, err), "private") {
		t.Fatal("command error/log retained credentials, recipient, token, or raw dependency error")
	}
}

func TestCommandOnceWiresIsolatedRealTransportAndCipher(t *testing.T) {
	commandEnvironment(t)
	t.Setenv(config.EnvBlindIndexPepper, "unrelated private invalid pepper")
	t.Setenv("GDPR_DELETION_ENABLED", "unrelated malformed API switch")
	t.Setenv(config.EnvGDPRPurgeBatchSize, "unrelated malformed purge setting")
	state := &commandState{}
	var logs bytes.Buffer
	err := runWithDependencies(context.Background(), slog.New(slog.NewJSONHandler(&logs, nil)), []string{"once"}, state.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	if state.opens != 1 || state.database.pings != 1 || state.database.closes != 1 || state.builds != 1 || state.worker.passes != 1 ||
		!state.startupBounded || !state.worker.bounded || state.dsn != os.Getenv(config.EnvDeletionNotifierDatabaseURL) {
		t.Fatal("command did not use one bounded pass, dedicated credentials and dependency cleanup")
	}
	want := privacy.NotificationConfig{
		BatchSize: 50, Concurrency: 4, LeaseDuration: time.Minute, SendTimeout: 15 * time.Second,
		RetryBase: 30 * time.Second, RetryMax: time.Hour, GracePeriod: 720 * time.Hour, ReclaimMaxAttempts: 5,
	}
	if state.workerConfig != want {
		t.Fatal("command changed worker limits or recovery policy")
	}
	if _, ok := state.notifier.(*smtp.Notifier); !ok || state.notifier.IsDevelopmentOnly() {
		t.Fatal("command installed a log-only notifier")
	}
	blob, err := state.cipher.Encrypt(context.Background(), []byte("private-token"))
	if err != nil || blob[0] != 7 {
		t.Fatal("command did not wire the configured KEK version")
	}
	plaintext, err := state.cipher.Decrypt(context.Background(), blob)
	if err != nil || string(plaintext) != "private-token" {
		t.Fatal("command did not wire the real envelope cipher")
	}
	for _, field := range []string{"\"relay_accepted\":1", "\"retried\":1", "\"failed\":1", "\"payloads_cleaned\":2", "\"skipped_legal_hold\":1", "\"level\":\"WARN\""} {
		if !strings.Contains(logs.String(), field) {
			t.Fatal("command omitted aggregate delivery/failure diagnostics")
		}
	}
	assertCommandRedacted(t, logs.String(), err)
}

func TestCommandProductionFactoryRunsCoreWorkerWithoutDatabaseReset(t *testing.T) {
	commandEnvironment(t)
	state := &commandState{}
	deps := state.dependencies()
	deps.newWorker = newWorker
	if err := runWithDependencies(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), []string{"once"}, deps); err != nil {
		t.Fatal(err)
	}
	if state.database.reads != 2 || state.database.closes != 1 {
		t.Fatal("real core worker did not list delivery and cleanup work or release database")
	}
}

func TestCommandHelpAndInvalidModesDoNotOpenDependencies(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"private-token"}, {"once", "private-token"}} {
		t.Run(fmt.Sprint(len(args), args[0] == "-h"), func(t *testing.T) {
			state := &commandState{}
			var logs bytes.Buffer
			err := runWithDependencies(context.Background(), slog.New(slog.NewJSONHandler(&logs, nil)), args, state.dependencies())
			valid := len(args) == 1 && (args[0] == "--help" || args[0] == "-h")
			if (err == nil) != valid || state.opens != 0 || state.builds != 0 {
				t.Fatal("help or invalid argument handling opened dependencies")
			}
			if valid && !strings.Contains(logs.String(), "usage: deletion-notifier [run|once]") {
				t.Fatal("help did not advertise modes")
			}
			assertCommandRedacted(t, logs.String(), err)
		})
	}
}

func TestCommandInvalidConfigurationFailsBeforeConnections(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{config.EnvDeletionNotifierDatabaseURL, ""},
		{config.EnvDeletionSMTPHost, ""}, {config.EnvDeletionSMTPPassword, ""},
		{config.EnvDeletionSMTPTLSMode, "plaintext"},
		{config.EnvDeletionSMTPFrom, "a@example.test\r\nBcc: private-recipient@example.test"},
		{config.EnvDeletionSMTPPublicOrigin, "https://identity.example.test?token=private-token"},
		{config.EnvDeletionSMTPCABundle, "/private-missing-ca.pem"},
		{config.EnvDeletionNotifierLeaseDuration, "1s"},
		{config.EnvMasterKEK, ""}, {config.EnvMasterKEK, "private-token"},
		{config.EnvMasterKEKVersion, "private-token"},
		{config.EnvGDPRGracePeriod, "719h"}, {config.EnvGDPRGracePeriod, "721h"},
		{config.EnvGDPRReclaimMaxAttempts, "2147483648"},
	} {
		t.Run(tc.key+"/"+fmt.Sprint(len(tc.value)), func(t *testing.T) {
			commandEnvironment(t)
			t.Setenv(tc.key, tc.value)
			state := &commandState{}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			err := runWithDependencies(context.Background(), logger, []string{"once"}, state.dependencies())
			if !errors.Is(err, errConfiguration) || state.opens != 0 || state.builds != 0 {
				t.Fatal("unsafe command configuration contacted dependencies")
			}
			logFailure(logger, err)
			assertCommandRedacted(t, logs.String(), err)
		})
	}
}

func TestCommandFailuresAreSanitizedAndReleaseResources(t *testing.T) {
	for _, failure := range []string{"open", "partial open", "nil database", "ping", "build", "nil worker", "pass"} {
		t.Run(failure, func(t *testing.T) {
			commandEnvironment(t)
			state := &commandState{}
			want := errDatabase
			switch failure {
			case "open":
				state.openErr = errPrivate
			case "partial open":
				state.openErr, state.partialOpen = errPrivate, true
			case "nil database":
				state.nilDatabase = true
			case "ping":
				state.database.ping = func(context.Context) error { return errPrivate }
			case "build":
				state.buildErr, want = errPrivate, errWorker
			case "nil worker":
				state.nilWorker, want = true, errWorker
			case "pass":
				state.worker.run = func(context.Context) (privacy.NotificationStats, error) {
					return privacy.NotificationStats{}, errPrivate
				}
				want = errPass
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			err := runWithDependencies(context.Background(), logger, []string{"once"}, state.dependencies())
			if !errors.Is(err, want) || failure != "open" && failure != "nil database" && state.database.closes != 1 {
				t.Fatal("dependency failure was swallowed or resources leaked")
			}
			logFailure(logger, err)
			assertCommandRedacted(t, logs.String(), err)
		})
	}
}

func TestCommandCancellationAndStartupTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, nil, nil); err != nil {
		t.Fatal("pre-canceled command did not stop gracefully")
	}
	for _, phase := range []string{"open", "ping", "pass", "poll", "startup timeout"} {
		t.Run(phase, func(t *testing.T) {
			commandEnvironment(t)
			t.Setenv(config.EnvDeletionNotifierPollInterval, "1m")
			t.Setenv(config.EnvDeletionNotifierStartupTimeout, "50ms")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state := &commandState{}
			deps := state.dependencies()
			reached := make(chan struct{})
			switch phase {
			case "open":
				deps.openDatabase = func(ctx context.Context, _ string) (workerDatabase, error) {
					close(reached)
					<-ctx.Done()
					return nil, errPrivate
				}
			case "ping", "startup timeout":
				state.database.ping = func(ctx context.Context) error { close(reached); <-ctx.Done(); return errPrivate }
			case "pass":
				state.worker.run = func(ctx context.Context) (privacy.NotificationStats, error) {
					close(reached)
					<-ctx.Done()
					return privacy.NotificationStats{}, errPrivate
				}
			case "poll":
				state.worker.run = func(context.Context) (privacy.NotificationStats, error) {
					close(reached)
					return privacy.NotificationStats{}, nil
				}
			}
			var logs bytes.Buffer
			result := make(chan error, 1)
			go func() { result <- runWithDependencies(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), nil, deps) }()
			select {
			case <-reached:
			case <-time.After(time.Second):
				t.Fatal("command did not reach cancellation boundary")
			}
			if phase != "startup timeout" {
				cancel()
			}
			select {
			case err := <-result:
				if phase == "startup timeout" && !errors.Is(err, errDatabase) || phase != "startup timeout" && err != nil {
					t.Fatal("startup timeout or signal cancellation misclassified")
				}
				assertCommandRedacted(t, logs.String(), err)
			case <-time.After(time.Second):
				t.Fatal("command ignored cancellation or startup timeout")
			}
			if phase != "open" && state.database.closes != 1 {
				t.Fatal("command leaked its database on cancellation")
			}
		})
	}
}

func TestCommandRunRetriesFailedPassWithoutExposingItsError(t *testing.T) {
	for _, args := range [][]string{nil, {"run"}} {
		commandEnvironment(t)
		t.Setenv(config.EnvDeletionNotifierPollInterval, "10ms")
		ctx, cancel := context.WithCancel(context.Background())
		state := &commandState{}
		state.worker.run = func(context.Context) (privacy.NotificationStats, error) {
			if state.worker.passes == 1 {
				return privacy.NotificationStats{}, errPrivate
			}
			cancel()
			return privacy.NotificationStats{Accepted: 1}, nil
		}
		var logs bytes.Buffer
		err := runWithDependencies(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), args, state.dependencies())
		cancel()
		if err != nil || state.worker.passes != 2 || state.database.closes != 1 || !strings.Contains(logs.String(), "pass incomplete") {
			t.Fatal("run mode exited on a transient pass failure or did not drain after retry")
		}
		assertCommandRedacted(t, logs.String(), err)
	}
}

func TestCommandFatalLogsContainOnlyKnownReasons(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	for _, err := range []error{errPrivate, errConfiguration, errDatabase, errWorker, errPass} {
		logFailure(logger, err)
	}
	for _, reason := range []string{"dependency_or_configuration_failure", "invalid_configuration", "database_unavailable", "worker_initialization_failed", "pass_incomplete"} {
		if !strings.Contains(logs.String(), reason) {
			t.Fatal("fatal log omitted its sanitized reason")
		}
	}
	assertCommandRedacted(t, logs.String(), nil)
}
