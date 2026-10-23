package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
)

var errCLIPrivate = errors.New("private-user:private-password@host private-body private-account-id")

type cliLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *cliLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *cliLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type cliTx struct {
	pgx.Tx
	batch           int32
	rollbackBounded bool
}

func (*cliTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("SET"), nil
}
func (tx *cliTx) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	tx.batch = args[1].(int32)
	return cliRows{}, nil
}
func (tx *cliTx) Rollback(ctx context.Context) error {
	d, ok := ctx.Deadline()
	tx.rollbackBounded = ok && ctx.Err() == nil && time.Until(d) <= 5*time.Second
	return nil
}

type cliRows struct{ pgx.Rows }

func (cliRows) Next() bool { return false }
func (cliRows) Err() error { return nil }
func (cliRows) Close()     {}

type cliDatabase struct {
	tx      cliTx
	pingErr error
	pings   int
	begins  int
	closed  int
}

func (d *cliDatabase) Begin(context.Context) (pgx.Tx, error) { d.begins++; return &d.tx, nil }
func (d *cliDatabase) Ping(context.Context) error            { d.pings++; return d.pingErr }
func (d *cliDatabase) Close()                                { d.closed++ }

type cliStream struct {
	jetstream.Stream
	info   jetstream.StreamInfo
	err    error
	onInfo func()
}

func (s *cliStream) Info(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	if s.onInfo != nil {
		s.onInfo()
	}
	return &s.info, s.err
}

type cliJetStream struct {
	jetstream.JetStream
	stream  cliStream
	openErr error
	creates int
	opens   int
}

func (js *cliJetStream) CreateStream(_ context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error) {
	js.creates++
	js.stream.info.Config = cfg
	return &js.stream, nil
}
func (js *cliJetStream) Stream(context.Context, string) (jetstream.Stream, error) {
	js.opens++
	return &js.stream, js.openErr
}

type cliState struct {
	database                  cliDatabase
	js                        cliJetStream
	databaseURL, natsURL      string
	databaseOpens, connects   int
	connectionCloses          int
	openErr, connectErr       error
	startupDeadlineWasBounded bool
}

func (s *cliState) dependencies() commandDependencies {
	s.js.stream.info.Config = jetstream.StreamConfig{
		Name: "IDENTITY_USERS", Subjects: []string{lifecycle.SubjectCreated, lifecycle.SubjectUpdated, lifecycle.SubjectSuspended, lifecycle.SubjectDeleted},
		MaxAge: 168 * time.Hour, MaxBytes: 128 << 20, Duplicates: lifecycle.DuplicateWindow,
		MaxMsgSize: lifecycle.MaxMessageBytes, Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy,
		Discard: jetstream.DiscardNew, Replicas: 1,
	}
	return commandDependencies{
		openDatabase: func(ctx context.Context, url string) (workerDatabase, error) {
			s.databaseOpens++
			s.databaseURL = url
			d, ok := ctx.Deadline()
			s.startupDeadlineWasBounded = ok && time.Until(d) <= 15*time.Second
			if s.openErr != nil {
				return nil, s.openErr
			}
			return &s.database, nil
		},
		connect: func(ctx context.Context, url string, _ *slog.Logger) (jetstream.JetStream, func(), error) {
			s.connects++
			s.natsURL = url
			d, ok := ctx.Deadline()
			s.startupDeadlineWasBounded = ok && time.Until(d) <= 15*time.Second
			if s.connectErr != nil {
				return nil, nil, s.connectErr
			}
			return &s.js, func() { s.connectionCloses++ }, nil
		},
	}
}

func cliEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"APP_ENV", "DATABASE_URL", "NATS_URL", config.EnvLifecycleCleanupDatabaseURL,
		config.EnvLifecycleStreamName, config.EnvLifecycleStreamMaxBytes, config.EnvLifecycleStreamMaxAge,
		config.EnvLifecycleOutboxRetention, config.EnvLifecycleBatchSize, config.EnvLifecyclePublishTimeout,
		config.EnvLifecycleBatchTimeout, config.EnvLifecyclePollInterval, config.EnvLifecycleStartupTimeout,
		config.EnvLifecycleCleanupBatchSize,
	} {
		t.Setenv(key, "")
	}
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://publisher:private-password@localhost/db")
	t.Setenv("NATS_URL", "nats://publisher:private-password@localhost:4222")
	t.Setenv(config.EnvLifecycleCleanupDatabaseURL, "postgres://maintenance:private-password@localhost/db")
}

func TestCLIModesKeepProvisionAndCleanupSeparate(t *testing.T) {
	for _, mode := range []string{"", "publish", "provision", "cleanup-published", "--help"} {
		t.Run(mode, func(t *testing.T) {
			cliEnvironment(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state := &cliState{}
			deps := state.dependencies()
			if mode == "" || mode == "publish" {
				state.js.stream.onInfo = cancel
			}
			if mode == "provision" {
				t.Setenv("APP_ENV", "production")
				t.Setenv(config.EnvLifecycleStreamMaxAge, "168h")
				t.Setenv(config.EnvLifecycleOutboxRetention, "invalid unrelated retention")
				t.Setenv(config.EnvLifecyclePublishTimeout, "invalid unrelated timeout")
				t.Setenv("DATABASE_URL", "not a database URL")
			}
			if mode == "cleanup-published" {
				t.Setenv("NATS_URL", "invalid broker credentials")
				t.Setenv(config.EnvLifecycleStreamMaxAge, "invalid")
				t.Setenv(config.EnvLifecycleCleanupBatchSize, "17")
			}
			var args []string
			if mode != "" {
				args = []string{mode}
			}
			var logs cliLogBuffer
			if err := runWithDependencies(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), args, deps); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "provision":
				if state.databaseOpens != 0 || state.js.creates != 1 || state.js.opens != 1 || state.connects != 1 || state.connectionCloses != 1 {
					t.Fatal("provision used database or did not explicitly create and validate")
				}
			case "cleanup-published":
				if state.connects != 0 || state.databaseOpens != 1 || state.database.begins != 1 || state.database.tx.batch != 17 ||
					state.databaseURL != os.Getenv(config.EnvLifecycleCleanupDatabaseURL) || state.database.closed != 1 || !state.database.tx.rollbackBounded {
					t.Fatal("cleanup used wrong credentials/dependencies or ignored its bound")
				}
			case "--help":
				if state.databaseOpens != 0 || state.connects != 0 || !strings.Contains(logs.String(), "usage:") {
					t.Fatal("help contacted a dependency")
				}
			default:
				if state.js.creates != 0 || state.js.opens != 1 || state.databaseOpens != 1 || state.database.pings != 1 ||
					state.connectionCloses != 1 || state.database.closed != 1 || state.database.begins != 0 {
					t.Fatal("normal publish provisioned or did not close dependencies on cancellation")
				}
			}
			if mode != "--help" && !state.startupDeadlineWasBounded {
				t.Fatal("startup deadline absent")
			}
			if strings.Contains(logs.String(), "private-password") {
				t.Fatal("CLI disclosed connection credentials")
			}
		})
	}
}

func TestCLIConfigurationFailurePrecedesConnections(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		args             []string
	}{
		{"database missing", "DATABASE_URL", "", nil},
		{"broker missing", "NATS_URL", "", nil},
		{"cleanup identity missing", config.EnvLifecycleCleanupDatabaseURL, "", []string{"cleanup-published"}},
		{"production retention missing", "APP_ENV", "production", []string{"provision"}},
		{"unknown mode", "", "", []string{"private-account-id"}},
		{"extra argument", "", "", []string{"publish", "private-password"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cliEnvironment(t)
			if tc.key != "" {
				t.Setenv(tc.key, tc.value)
			}
			state := &cliState{}
			var logs cliLogBuffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			err := runWithDependencies(context.Background(), logger, tc.args, state.dependencies())
			if err == nil || state.databaseOpens != 0 || state.connects != 0 {
				t.Fatalf("bad configuration attempted dependency access: %v", err)
			}
			logFailure(logger, err)
			if strings.Contains(logs.String()+err.Error(), "private") {
				t.Fatal("configuration failure disclosed a supplied value")
			}
		})
	}
}

func TestCLIStartupErrorsAreSanitizedAndReleaseDependencies(t *testing.T) {
	for _, failure := range []string{"open", "ping", "connect", "missing stream", "wrong topology", "stream info"} {
		t.Run(failure, func(t *testing.T) {
			cliEnvironment(t)
			state := &cliState{}
			deps := state.dependencies()
			switch failure {
			case "open":
				state.openErr = errCLIPrivate
			case "ping":
				state.database.pingErr = errCLIPrivate
			case "connect":
				state.connectErr = errCLIPrivate
			case "missing stream":
				state.js.openErr = jetstream.ErrStreamNotFound
			case "wrong topology":
				state.js.stream.info.Config.Retention = jetstream.WorkQueuePolicy
			case "stream info":
				state.js.stream.err = errCLIPrivate
			}
			var logs cliLogBuffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			err := runWithDependencies(context.Background(), logger, nil, deps)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatalf("failure lost or leaked: %v", err)
			}
			logFailure(logger, err)
			if strings.Contains(logs.String(), "private") || state.js.creates != 0 {
				t.Fatal("startup disclosed details or automatically provisioned")
			}
			if failure != "open" && state.database.closed != 1 {
				t.Fatal("database not closed after startup failure")
			}
			if state.js.opens == 1 && state.connectionCloses != 1 {
				t.Fatal("broker not closed after topology failure")
			}
		})
	}
}

func TestCLIStartupCancellationIsBounded(t *testing.T) {
	cliEnvironment(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, nil, nil); err != nil {
		t.Fatal("already canceled startup was not graceful")
	}
	if _, _, err := connectNATS(ctx, "private invalid URL", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled NATS startup tried to dial")
	}
	for _, signal := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "signal"}[signal], func(t *testing.T) {
			t.Setenv(config.EnvLifecycleStartupTimeout, "1ms")
			state := &cliState{}
			deps := state.dependencies()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			deps.connect = func(ctx context.Context, _ string, _ *slog.Logger) (jetstream.JetStream, func(), error) {
				if signal {
					cancel()
				}
				<-ctx.Done()
				return nil, nil, ctx.Err()
			}
			start := time.Now()
			err := runWithDependencies(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, deps)
			if signal && err != nil || !signal && err == nil || time.Since(start) > time.Second || state.database.closed != 1 {
				t.Fatalf("startup did not stop and close within its bound: %v", err)
			}
		})
	}
}

func cliNATSStub(t *testing.T, handshake <-chan struct{}) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		close(accepted)
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if handshake != nil {
			select {
			case <-handshake:
			case <-time.After(3 * time.Second):
				return
			}
		}
		_, _ = io.WriteString(conn, "INFO {\"server_id\":\"unit\",\"version\":\"2.10.0\",\"proto\":1,\"headers\":true,\"max_payload\":1048576}\r\n")
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			if scanner.Text() == "PING" {
				_, _ = io.WriteString(conn, "PONG\r\n")
			}
		}
	}()
	return listener.Addr().String(), accepted, finished
}

func TestWorkerNATSCallbacksDoNotExposeTransportInputs(t *testing.T) {
	// A protocol stub, not an external broker or integration service. Connecting
	// through the real shared constructor also exercises its actual callbacks.
	address, _, finished := cliNATSStub(t, nil)
	var logs cliLogBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	js, closeConnection, err := connectNATS(ctx, "nats://private-user:private-password@"+address, logger)
	if err != nil {
		t.Fatal("protocol stub connection failed")
	}
	defer closeConnection()
	nc := js.Conn()
	nc.Opts.DisconnectedErrCB(nc, errCLIPrivate)
	nc.Opts.ReconnectedCB(nc)
	nc.Opts.AsyncErrorCB(nc, &nats.Subscription{Subject: "private-account-id"}, errCLIPrivate)
	nc.Opts.ClosedCB(nc)
	closeConnection()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("protocol stub did not close")
	}
	if strings.Contains(logs.String(), "private") || strings.Contains(logs.String(), address) ||
		!strings.Contains(logs.String(), "asynchronous NATS error") || !strings.Contains(logs.String(), "reconnected to NATS") {
		t.Fatal("connection callbacks disclosed identifiers, URL, or raw errors")
	}
}

func TestNATSStartupCancellationClosesLateConnection(t *testing.T) {
	handshake := make(chan struct{})
	address, accepted, finished := cliNATSStub(t, handshake)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, closeConnection, err := connectNATS(ctx, "nats://"+address, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if closeConnection != nil {
			closeConnection()
		}
		result <- err
	}()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("stub connection was not attempted")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("startup cancellation was lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup waited for a stalled NATS handshake")
	}
	// Finish the dial only after its caller has returned. The abandoned result
	// must close its own connection, not leak it into an unread channel.
	close(handshake)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("late NATS connection remained open")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if js, closeConnection, err := connectNATS(ctx, "nats://[private-password", nil); !errors.Is(err, lifecycle.ErrUnavailable) || js != nil || closeConnection != nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("dial failure was not sanitized: %v", err)
	}
}

func TestLogFailureEmitsOnlyKnownReasonCodes(t *testing.T) {
	var logs cliLogBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	for _, err := range []error{errCLIPrivate, lifecycle.ErrStreamMissing, lifecycle.ErrStreamMismatch, lifecycle.ErrInvalidEvent} {
		logFailure(logger, err)
	}
	for _, reason := range []string{"dependency_or_configuration_failure", "stream_missing", "stream_topology_mismatch", "invalid_envelope"} {
		if !strings.Contains(logs.String(), reason) {
			t.Fatalf("reason code missing: %s", reason)
		}
	}
	if strings.Contains(logs.String(), "private") {
		t.Fatal("fatal logging leaked raw error")
	}
}
