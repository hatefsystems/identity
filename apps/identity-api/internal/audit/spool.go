package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Spool is the durable last-resort sink for envelopes the transport could not
// publish.
//
// # Why a file and not the container log
//
// The log line still happens, and it remains the alerting signal. But a log line
// is not a recovery procedure. Reconstructing a hash chain by hand from stdout
// requires an operator to locate the right lines across rotation, strip the
// surrounding structured-logging envelope, reassemble JSON that may have been
// truncated by a collector's line limit, and replay it in the original order —
// under incident conditions, against a compliance deadline. In practice that does
// not happen, which means the "durable" fallback was durable only in principle.
//
// A spool file makes recovery a command: the operator replays the file into
// JetStream and the signer's existing idempotency filter absorbs anything that
// already landed. The format is therefore newline-delimited JSON envelopes, which
// is exactly what a publisher reads back.
//
// # Why not the transactional outbox
//
// event_outbox would be the obvious home, and for events produced inside a
// business transaction it would be better. It does not fit here: this path exists
// precisely because the process could not reach its dependencies, and the
// envelopes arriving here were produced by handlers whose transactions have
// already committed. Requiring a database write to record "we could not reach the
// database or the broker" reintroduces the dependency the fallback exists to
// survive.
//
// # Ordering and completeness
//
// A spool is append-only and fsynced per record, so a crash loses at most the
// record being written. It is not a queue: nothing drains it automatically,
// because automatic replay would race the signer's chain position and could
// reorder events relative to live traffic. Draining is an operator action.
type Spool struct {
	mu   sync.Mutex
	file *os.File
	// path is retained for the operator-facing log line that names the file.
	path string
	// limit bounds the file so a long outage cannot fill the volume and take the
	// service down with it. Reaching the limit is itself reported.
	limit int64
	size  int64
	full  bool
}

// ErrSpoolFull reports that the spool reached its configured size limit.
var ErrSpoolFull = errors.New("audit: spool is full")

// DefaultSpoolLimit caps the spool at 64 MiB, which is roughly a million
// envelopes — far longer than any outage that should go unnoticed.
const DefaultSpoolLimit = 64 << 20

// OpenSpool opens or creates the spool at path.
//
// The directory must already exist and be writable: creating it here would mask a
// misconfigured deployment until the first outage, which is the worst possible
// moment to discover that the fallback never worked.
func OpenSpool(path string, limit int64) (*Spool, error) {
	if path == "" {
		return nil, errors.New("audit: spool path is required")
	}
	if limit <= 0 {
		limit = DefaultSpoolLimit
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("audit: spool directory is not usable: %w", err)
	}
	defer func() { _ = root.Close() }()
	// Constrain resolution to the configured directory, including symlink targets.
	// 0600: the spool contains full envelopes, including payload values.
	file, err := root.OpenFile(filepath.Base(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open spool: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("audit: stat spool: %w", err)
	}
	return &Spool{file: file, path: path, limit: limit, size: info.Size()}, nil
}

// Path reports the spool's location so a failure log line can name it.
func (s *Spool) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Append writes one envelope as a single JSON line and fsyncs it.
//
// fsync per record is deliberate. This path is already the exceptional one, so
// its throughput does not matter, and the entire purpose of the spool is to
// survive the process dying moments later — which is exactly when an unflushed
// buffer would lose the events that mattered most.
func (s *Spool) Append(env Envelope) error {
	if s == nil {
		return errors.New("audit: spool is not configured")
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("audit: serialize envelope for spool: %w", err)
	}
	encoded = append(encoded, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return errors.New("audit: spool is closed")
	}
	if s.full || s.size+int64(len(encoded)) > s.limit {
		// Latch, so one log line reports the limit rather than one per event for
		// the remainder of the outage.
		wasFull := s.full
		s.full = true
		if wasFull {
			return ErrSpoolFull
		}
		return fmt.Errorf("%w at %d bytes", ErrSpoolFull, s.size)
	}
	n, err := s.file.Write(encoded)
	s.size += int64(n)
	if err != nil {
		return fmt.Errorf("audit: write spool: %w", err)
	}
	if n != len(encoded) {
		return fmt.Errorf("audit: short spool write: %d of %d bytes", n, len(encoded))
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("audit: fsync spool: %w", err)
	}
	return nil
}

// Close flushes and releases the spool.
func (s *Spool) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	if err != nil {
		return fmt.Errorf("audit: close spool: %w", err)
	}
	return nil
}
