package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type runtimeStream struct {
	jetstream.Stream
	info  *jetstream.StreamInfo
	err   error
	calls int
}

func (s *runtimeStream) Info(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	s.calls++
	return s.info, s.err
}

type runtimeStreams struct {
	stream              *runtimeStream
	createErr, openErr  error
	created             []jetstream.StreamConfig
	opened              []string
	createDeadlineBound bool
}

func (s *runtimeStreams) CreateStream(ctx context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error) {
	s.created = append(s.created, cfg)
	deadline, ok := ctx.Deadline()
	s.createDeadlineBound = ok && time.Until(deadline) <= 15*time.Second
	return s.stream, s.createErr
}

func (s *runtimeStreams) Stream(_ context.Context, name string) (jetstream.Stream, error) {
	s.opened = append(s.opened, name)
	if s.stream == nil {
		return nil, s.openErr
	}
	return s.stream, s.openErr
}

func runtimeStreamOptions() StreamOptions {
	return StreamOptions{Name: "IDENTITY_USERS", MaxBytes: 128 << 20, MaxAge: 168 * time.Hour}
}

func TestStreamProvisionIsCreateOnlyAndOpenIsReadOnly(t *testing.T) {
	opts := runtimeStreamOptions()
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			stream := &runtimeStream{info: &jetstream.StreamInfo{Config: streamConfig(opts)}}
			js := &runtimeStreams{stream: stream}
			if existing {
				js.createErr = jetstream.ErrStreamNameAlreadyInUse
			}
			got, err := ProvisionStream(context.Background(), js, opts)
			if err != nil || got != stream || len(js.created) != 1 || !reflect.DeepEqual(js.created[0], streamConfig(opts)) ||
				!js.createDeadlineBound || len(js.opened) != 1 || stream.calls != 1 {
				t.Fatalf("provision did not create then validate: %v", err)
			}
			if _, err := OpenStream(context.Background(), js, opts); err != nil || len(js.created) != 1 || len(js.opened) != 2 || stream.calls != 2 {
				t.Fatalf("normal open changed topology or did not validate: %v", err)
			}
		})
	}
}

func TestStreamRejectsIncompatibleTopology(t *testing.T) {
	mutations := map[string]func(*jetstream.StreamConfig){
		"name":             func(c *jetstream.StreamConfig) { c.Name = "OTHER" },
		"wildcard":         func(c *jetstream.StreamConfig) { c.Subjects[0] = "identity.user.>" },
		"audit subject":    func(c *jetstream.StreamConfig) { c.Subjects[0] = "identity.audit.logs" },
		"missing subject":  func(c *jetstream.StreamConfig) { c.Subjects = c.Subjects[:3] },
		"extra subject":    func(c *jetstream.StreamConfig) { c.Subjects = append(c.Subjects, "extra") },
		"duplicate":        func(c *jetstream.StreamConfig) { c.Subjects[0] = c.Subjects[1] },
		"workqueue":        func(c *jetstream.StreamConfig) { c.Retention = jetstream.WorkQueuePolicy },
		"interest":         func(c *jetstream.StreamConfig) { c.Retention = jetstream.InterestPolicy },
		"memory":           func(c *jetstream.StreamConfig) { c.Storage = jetstream.MemoryStorage },
		"discard old":      func(c *jetstream.StreamConfig) { c.Discard = jetstream.DiscardOld },
		"max bytes":        func(c *jetstream.StreamConfig) { c.MaxBytes++ },
		"max age":          func(c *jetstream.StreamConfig) { c.MaxAge++ },
		"duplicate window": func(c *jetstream.StreamConfig) { c.Duplicates++ },
		"max message":      func(c *jetstream.StreamConfig) { c.MaxMsgSize++ },
		"replicas":         func(c *jetstream.StreamConfig) { c.Replicas = 3 },
		"max messages":     func(c *jetstream.StreamConfig) { c.MaxMsgs = 100 },
		"per subject":      func(c *jetstream.StreamConfig) { c.MaxMsgsPerSubject = 1 },
		"one consumer":     func(c *jetstream.StreamConfig) { c.MaxConsumers = 1 },
		"no ack":           func(c *jetstream.StreamConfig) { c.NoAck = true },
		"sealed":           func(c *jetstream.StreamConfig) { c.Sealed = true },
		"subject discard":  func(c *jetstream.StreamConfig) { c.DiscardNewPerSubject = true },
		"rollup":           func(c *jetstream.StreamConfig) { c.AllowRollup = true },
		"mirror":           func(c *jetstream.StreamConfig) { c.Mirror = &jetstream.StreamSource{Name: "PRIVATE"} },
		"sources":          func(c *jetstream.StreamConfig) { c.Sources = []*jetstream.StreamSource{{Name: "PRIVATE"}} },
		"transform":        func(c *jetstream.StreamConfig) { c.SubjectTransform = &jetstream.SubjectTransformConfig{} },
		"republish":        func(c *jetstream.StreamConfig) { c.RePublish = &jetstream.RePublish{} },
		"template":         func(c *jetstream.StreamConfig) { c.Template = "PRIVATE" },
		"message ttl":      func(c *jetstream.StreamConfig) { c.AllowMsgTTL = true },
		"delete markers":   func(c *jetstream.StreamConfig) { c.SubjectDeleteMarkerTTL = time.Minute },
		"counter":          func(c *jetstream.StreamConfig) { c.AllowMsgCounter = true },
		"schedules":        func(c *jetstream.StreamConfig) { c.AllowMsgSchedules = true },
		"atomic publish":   func(c *jetstream.StreamConfig) { c.AllowAtomicPublish = true },
		"batch publish":    func(c *jetstream.StreamConfig) { c.AllowBatchPublish = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			opts := runtimeStreamOptions()
			cfg := streamConfig(opts)
			mutate(&cfg)
			js := &runtimeStreams{stream: &runtimeStream{info: &jetstream.StreamInfo{Config: cfg}}, createErr: jetstream.ErrStreamNameAlreadyInUse}
			for _, open := range []func(context.Context, StreamOptions) (jetstream.Stream, error){
				func(ctx context.Context, opts StreamOptions) (jetstream.Stream, error) {
					return OpenStream(ctx, js, opts)
				},
				func(ctx context.Context, opts StreamOptions) (jetstream.Stream, error) {
					return ProvisionStream(ctx, js, opts)
				},
			} {
				if _, err := open(context.Background(), opts); !errors.Is(err, ErrStreamMismatch) {
					t.Fatalf("accepted incompatible topology: %v", err)
				}
			}
		})
	}
}

func TestStreamCompatibleSubjectsAreOrderIndependent(t *testing.T) {
	opts := runtimeStreamOptions()
	cfg := streamConfig(opts)
	cfg.Subjects = []string{SubjectDeleted, SubjectSuspended, SubjectUpdated, SubjectCreated}
	cfg.Description = "operator description"
	cfg.Metadata = map[string]string{"owner": "operations"}
	if !compatibleStream(cfg, opts) {
		t.Fatal("harmless subject order or annotations rejected")
	}
	// The server normalizes omitted unlimited limits to -1.
	cfg.MaxMsgs, cfg.MaxMsgsPerSubject, cfg.MaxConsumers = 0, 0, 0
	if !compatibleStream(cfg, opts) {
		t.Fatal("equivalent unlimited defaults rejected")
	}
}

func TestStreamErrorsCancellationAndConfigurationAreSafe(t *testing.T) {
	opts := runtimeStreamOptions()
	secret := errors.New("nats://user:private-password@host private-body")
	for _, tc := range []struct {
		name string
		js   *runtimeStreams
		want error
	}{
		{"missing", &runtimeStreams{openErr: jetstream.ErrStreamNotFound}, ErrStreamMissing},
		{"open failure", &runtimeStreams{openErr: secret}, ErrUnavailable},
		{"nil stream", &runtimeStreams{}, ErrUnavailable},
		{"info failure", &runtimeStreams{stream: &runtimeStream{err: secret}}, ErrUnavailable},
		{"nil info", &runtimeStreams{stream: &runtimeStream{}}, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := OpenStream(context.Background(), tc.js, opts); !errors.Is(err, tc.want) || strings.Contains(err.Error(), "private") || len(tc.js.created) != 0 {
				t.Fatalf("unsafe open behavior: %v", err)
			}
		})
	}
	js := &runtimeStreams{createErr: secret}
	if _, err := ProvisionStream(context.Background(), js, opts); !errors.Is(err, ErrUnavailable) || len(js.opened) != 0 {
		t.Fatalf("creation failure fell through or leaked: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	js = &runtimeStreams{}
	if _, err := ProvisionStream(ctx, js, opts); !errors.Is(err, context.Canceled) || len(js.created) != 0 {
		t.Fatal("provision ignored cancellation")
	}
	if _, err := OpenStream(ctx, js, opts); !errors.Is(err, context.Canceled) || len(js.opened) != 0 {
		t.Fatal("open ignored cancellation")
	}
	if _, err := OpenStream(context.Background(), nil, opts); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := ProvisionStream(context.Background(), nil, opts); err == nil {
		t.Fatal("nil provisioner accepted")
	}
	for _, name := range []string{"", "a.b", "a>b", "a*b", "a/b", `a\b`, "a b", "a\x00b", "a\nb", "\u00e9", strings.Repeat("a", 101)} {
		invalid := opts
		invalid.Name = name
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid stream name accepted: %q", name)
		}
	}
	for _, invalid := range []StreamOptions{
		{Name: opts.Name, MaxBytes: MaxMessageBytes - 1, MaxAge: opts.MaxAge},
		{Name: opts.Name, MaxBytes: opts.MaxBytes, MaxAge: 0},
		{Name: opts.Name, MaxBytes: opts.MaxBytes, MaxAge: -time.Hour},
		{Name: opts.Name, MaxBytes: opts.MaxBytes, MaxAge: DuplicateWindow},
	} {
		if _, err := ProvisionStream(context.Background(), js, invalid); err == nil {
			t.Fatal("invalid stream options accepted")
		}
	}
	if err := (StreamOptions{Name: "users_1-v1", MaxBytes: MaxMessageBytes, MaxAge: DuplicateWindow + time.Nanosecond}).Validate(); err != nil {
		t.Fatal(err)
	}
}
