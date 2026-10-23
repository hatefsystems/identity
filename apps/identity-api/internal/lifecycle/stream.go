package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// DuplicateWindow bounds broker deduplication; consumers need durable protection.
const DuplicateWindow = 2 * time.Minute

// Stream errors never disclose broker responses or credential-bearing URLs.
var (
	ErrStreamMissing  = errors.New("lifecycle: stream missing; explicit provisioning required")
	ErrStreamMismatch = errors.New("lifecycle: incompatible stream topology")
)

// StreamOptions is the explicitly approved retention and capacity policy.
type StreamOptions struct {
	Name     string
	MaxBytes int64
	MaxAge   time.Duration
}

// Validate does not supply retention defaults or include configured values in errors.
func (o StreamOptions) Validate() error {
	if !validStreamName(o.Name) || o.MaxBytes < MaxMessageBytes || o.MaxAge <= DuplicateWindow {
		return errors.New("lifecycle: valid stream name, capacity >= 16 KiB and max age > 2m required")
	}
	return nil
}

func validStreamName(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}
	for _, c := range name {
		if c != '-' && c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// StreamReader deliberately cannot create or update topology.
type StreamReader interface {
	Stream(context.Context, string) (jetstream.Stream, error)
}

// StreamProvisioner only adds create-only access, never an update operation.
type StreamProvisioner interface {
	StreamReader
	CreateStream(context.Context, jetstream.StreamConfig) (jetstream.Stream, error)
}

func streamConfig(o StreamOptions) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:      o.Name,
		Subjects:  []string{SubjectCreated, SubjectUpdated, SubjectSuspended, SubjectDeleted},
		Retention: jetstream.LimitsPolicy, Storage: jetstream.FileStorage, Discard: jetstream.DiscardNew,
		MaxBytes: o.MaxBytes, MaxAge: o.MaxAge, Duplicates: DuplicateWindow,
		MaxMsgSize: MaxMessageBytes, Replicas: 1,
		MaxMsgs: -1, MaxMsgsPerSubject: -1, MaxConsumers: -1,
	}
}

// ProvisionStream is explicit and create-only. An existing stream must already
// match; a timeout or permission error never triggers an update or replacement.
func ProvisionStream(ctx context.Context, js StreamProvisioner, opts StreamOptions) (jetstream.Stream, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if js == nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if _, err := js.CreateStream(ctx, streamConfig(opts)); err != nil && !errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
		return nil, dependencyError(ctx)
	}
	return OpenStream(ctx, js, opts)
}

// OpenStream never creates or changes a stream, including when it is missing.
func OpenStream(ctx context.Context, js StreamReader, opts StreamOptions) (jetstream.Stream, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if js == nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	stream, err := js.Stream(ctx, opts.Name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil, ErrStreamMissing
	}
	if err != nil || stream == nil {
		return nil, dependencyError(ctx)
	}
	info, err := stream.Info(ctx)
	if err != nil || info == nil {
		return nil, dependencyError(ctx)
	}
	if !compatibleStream(info.Config, opts) {
		return nil, ErrStreamMismatch
	}
	return stream, nil
}

func compatibleStream(c jetstream.StreamConfig, o StreamOptions) bool {
	if c.Name != o.Name || len(c.Subjects) != 4 || c.Retention != jetstream.LimitsPolicy ||
		c.Storage != jetstream.FileStorage || c.Discard != jetstream.DiscardNew ||
		c.MaxBytes != o.MaxBytes || c.MaxAge != o.MaxAge || c.Duplicates != DuplicateWindow ||
		c.MaxMsgSize != MaxMessageBytes || c.Replicas != 1 {
		return false
	}
	seen := make(map[string]bool, 4)
	for _, subject := range c.Subjects {
		switch subject {
		case SubjectCreated, SubjectUpdated, SubjectSuspended, SubjectDeleted:
			if seen[subject] {
				return false
			}
			seen[subject] = true
		default:
			return false
		}
	}
	// Other limits or message-rewriting features could silently truncate replay,
	// change subjects, bypass acknowledgements or introduce non-contract traffic.
	return c.MaxMsgs >= -1 && c.MaxMsgs <= 0 && c.MaxMsgsPerSubject >= -1 && c.MaxMsgsPerSubject <= 0 &&
		c.MaxConsumers >= -1 && c.MaxConsumers <= 0 && !c.NoAck && !c.Sealed && !c.DiscardNewPerSubject &&
		!c.AllowRollup && c.Mirror == nil && len(c.Sources) == 0 && c.SubjectTransform == nil && c.RePublish == nil &&
		c.Template == "" && !c.AllowMsgTTL && c.SubjectDeleteMarkerTTL == 0 && !c.AllowMsgCounter &&
		!c.AllowMsgSchedules && !c.AllowAtomicPublish && !c.AllowBatchPublish
}
