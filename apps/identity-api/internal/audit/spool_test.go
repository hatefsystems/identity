package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The spool exists because a log line is an alerting signal, not a recovery
// procedure. These tests therefore assert the properties that make it a recovery
// procedure: the file is replayable as-is, a crash loses at most the record being
// written, and a long outage cannot fill the volume.

func spoolEnvelope(t *testing.T, eventType string) Envelope {
	t.Helper()
	env, err := NewEnvelope(Event{
		EventType:     eventType,
		ActionStatus:  StatusSuccess,
		ActorSPIFFEID: APIActorSPIFFEID,
		Payload:       map[string]any{"k": "v"},
	}, uuid.New(), time.Date(2026, 4, 5, 6, 7, 8, 9000, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestSpoolAppendProducesReplayableJSONLines(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.spool")
	spool, err := OpenSpool(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })

	want := []Envelope{
		spoolEnvelope(t, EventLoginSucceeded),
		spoolEnvelope(t, EventRTRBreach),
		spoolEnvelope(t, EventLoginFailed),
	}
	for _, env := range want {
		if err := spool.Append(env); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	var got []Envelope
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var env Envelope
		if err := json.Unmarshal(scanner.Bytes(), &env); err != nil {
			t.Fatalf("spool line is not a decodable envelope: %v", err)
		}
		got = append(got, env)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("spool holds %d envelopes, want %d", len(got), len(want))
	}
	// Order must be preserved: the signer chains in the order it consumes, so a
	// replay that reordered events would produce a different chain.
	for i := range want {
		if got[i].EventID != want[i].EventID || got[i].EventType != want[i].EventType {
			t.Errorf("line %d = %s/%s, want %s/%s", i,
				got[i].EventID, got[i].EventType, want[i].EventID, want[i].EventType)
		}
		if got[i].SchemaVersion != EnvelopeSchemaVersion {
			t.Errorf("line %d schema version = %d, want %d", i, got[i].SchemaVersion, EnvelopeSchemaVersion)
		}
	}
}

// TestSpoolSurvivesReopen covers the restart case: a new process must append to
// the existing file rather than truncating the records it is meant to preserve.
func TestSpoolSurvivesReopen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.spool")

	first, err := OpenSpool(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Append(spoolEnvelope(t, EventLoginSucceeded)); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := OpenSpool(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if err := second.Append(spoolEnvelope(t, EventRTRBreach)); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(data), "\n"); lines != 2 {
		t.Errorf("spool holds %d lines after reopen, want 2; a restart truncated preserved events", lines)
	}
}

// TestSpoolIsBounded keeps a sustained outage from filling the volume and taking
// the service down with it — which would convert a degraded audit transport into
// an availability incident.
func TestSpoolIsBounded(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.spool")
	// Small enough that the second or third record crosses it.
	spool, err := OpenSpool(path, 400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })

	var firstFull error
	accepted := 0
	for range 50 {
		err := spool.Append(spoolEnvelope(t, EventLoginSucceeded))
		if err == nil {
			accepted++
			continue
		}
		if !errors.Is(err, ErrSpoolFull) {
			t.Fatalf("Append error = %v, want ErrSpoolFull", err)
		}
		if firstFull == nil {
			firstFull = err
		}
	}
	if accepted == 0 {
		t.Fatal("the spool accepted nothing; the limit is not usable")
	}
	if firstFull == nil {
		t.Fatal("the spool never reported ErrSpoolFull despite a 400-byte limit")
	}
	// The first refusal names the size so an operator can see how much was kept;
	// later ones are latched to avoid one line per event for the rest of an outage.
	if !strings.Contains(firstFull.Error(), "bytes") {
		t.Errorf("first full error = %q, want it to report the size", firstFull)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 400 {
		t.Errorf("spool grew to %d bytes past its 400-byte limit", info.Size())
	}
}

func TestOpenSpoolRejectsUnusableConfiguration(t *testing.T) {
	t.Parallel()
	if _, err := OpenSpool("", 0); err == nil {
		t.Error("an empty spool path was accepted")
	}
	// A missing directory must fail at startup, not on the first outage: that is
	// the worst possible moment to discover the fallback never worked.
	missing := filepath.Join(t.TempDir(), "absent", "audit.spool")
	if _, err := OpenSpool(missing, 0); err == nil {
		t.Error("a spool in a nonexistent directory was accepted")
	}
}

func TestSpoolFilePermissionsAreRestrictive(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.spool")
	spool, err := OpenSpool(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	if err := spool.Append(spoolEnvelope(t, EventLoginSucceeded)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The spool carries whole envelopes, including payload values.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("spool mode = %o, want 600", perm)
	}
}

// TestSpoolNilAndClosedAreSafe matters because the fallback path must never panic:
// it runs when everything else has already failed.
func TestSpoolNilAndClosedAreSafe(t *testing.T) {
	t.Parallel()
	var nilSpool *Spool
	if nilSpool.Path() != "" {
		t.Error("a nil spool reported a path")
	}
	if err := nilSpool.Append(spoolEnvelope(t, EventLoginSucceeded)); err == nil {
		t.Error("a nil spool accepted an append")
	}
	if err := nilSpool.Close(); err != nil {
		t.Errorf("closing a nil spool: %v", err)
	}

	path := filepath.Join(t.TempDir(), "audit.spool")
	spool, err := OpenSpool(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Errorf("double close: %v", err)
	}
	if err := spool.Append(spoolEnvelope(t, EventLoginSucceeded)); err == nil {
		t.Error("a closed spool accepted an append")
	}
}
