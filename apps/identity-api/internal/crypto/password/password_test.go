package password

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestParameterConstants(t *testing.T) {
	if Memory != 64*1024 {
		t.Errorf("Memory = %d KiB, want %d (64MB)", Memory, 64*1024)
	}
	if Iterations != 3 {
		t.Errorf("Iterations = %d, want 3", Iterations)
	}
	if Parallelism != 4 {
		t.Errorf("Parallelism = %d, want 4", Parallelism)
	}
	if SaltLength != 16 {
		t.Errorf("SaltLength = %d, want 16", SaltLength)
	}
	if KeyLength != 32 {
		t.Errorf("KeyLength = %d, want 32", KeyLength)
	}
}

func TestSupportedHashMatchesVerifierAdmission(t *testing.T) {
	const valid = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for encoded, want := range map[string]bool{
		valid: true,
		strings.Replace(valid, "m=65536,t=3,p=4", "m=32,t=1,p=1", 1): true,
		strings.Replace(valid, "m=65536", "m=8", 1):                  false,
		"":                false,
		"legacy-password": false,
		strings.Replace(valid, "argon2id", "argon2i", 1): false,
		strings.Replace(valid, "v=19", "v=16", 1):        false,
		strings.Replace(valid, "m=65536", "m=999999", 1): false,
		valid + "$extra": false,
	} {
		if SupportedHash(encoded) != want {
			t.Fatal("primary credential admission differs from supported verifier formats")
		}
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	cases := map[string]string{
		"ascii":      "correct horse battery compass",
		"unicode":    "گذرواژهٔ محرمانه",
		"long":       strings.Repeat("A", 1024),
		"symbols":    "p@$$w0rd!#%&*()_+",
		"whitespace": "  leading and trailing  ",
	}
	for name, pw := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := Hash(pw)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			ok, err := Verify(pw, encoded)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Error("Verify returned false for correct password")
			}
		})
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	encoded, err := Hash("the real password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := Verify("not the password", encoded)
	if err != nil {
		t.Fatalf("Verify returned error for mismatch: %v", err)
	}
	if ok {
		t.Error("Verify returned true for wrong password")
	}
}

// TestHashUniqueSalt ensures each Hash call uses a fresh salt, so identical
// passwords produce different encoded strings.
func TestHashUniqueSalt(t *testing.T) {
	pw := "same-password-long"
	h1, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash #1: %v", err)
	}
	h2, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash #2: %v", err)
	}
	if h1 == h2 {
		t.Error("two hashes of same password are identical; salt not unique")
	}
	// Both must still verify.
	for i, h := range []string{h1, h2} {
		ok, err := Verify(pw, h)
		if err != nil || !ok {
			t.Errorf("hash #%d failed to verify (ok=%v, err=%v)", i+1, ok, err)
		}
	}
}

func TestHashEncodingFormat(t *testing.T) {
	encoded, err := Hash("value-long-enough")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	wantPrefix := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$", argon2.Version, Memory, Iterations, Parallelism)
	if !strings.HasPrefix(encoded, wantPrefix) {
		t.Errorf("encoded = %q, want prefix %q", encoded, wantPrefix)
	}
	// Must fit in the password_hash VARCHAR(255) column.
	if len(encoded) > 255 {
		t.Errorf("encoded length = %d, exceeds VARCHAR(255)", len(encoded))
	}
	// Exactly 6 '$'-delimited segments (leading empty + 5).
	if got := len(strings.Split(encoded, "$")); got != 6 {
		t.Errorf("segments = %d, want 6", got)
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	validSalt := base64.RawStdEncoding.EncodeToString(make([]byte, SaltLength))
	validKey := base64.RawStdEncoding.EncodeToString(make([]byte, KeyLength))

	cases := map[string]struct {
		hash    string
		wantErr error
	}{
		"empty":            {"", ErrInvalidHash},
		"not-phc":          {"plaintext", ErrInvalidHash},
		"too-few-fields":   {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt, ErrInvalidHash},
		"wrong-variant":    {"$argon2i$v=19$m=65536,t=3,p=4$" + validSalt + "$" + validKey, ErrIncompatibleVariant},
		"bad-version":      {"$argon2id$v=99$m=65536,t=3,p=4$" + validSalt + "$" + validKey, ErrIncompatibleVersion},
		"unparseable-vers": {"$argon2id$vX$m=65536,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"bad-params":       {"$argon2id$v=19$m=abc,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"zero-params":      {"$argon2id$v=19$m=0,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"bad-salt-b64":     {"$argon2id$v=19$m=65536,t=3,p=4$!!!not-base64!!!$" + validKey, ErrInvalidHash},
		"bad-key-b64":      {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "$!!!bad!!!", ErrInvalidHash},
		"empty-salt":       {"$argon2id$v=19$m=65536,t=3,p=4$$" + validKey, ErrInvalidHash},
		"empty-key":        {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "$", ErrInvalidHash},
		"high-memory":      {"$argon2id$v=19$m=65537,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"memory-overflow":  {"$argon2id$v=19$m=4294967296,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"high-iterations":  {"$argon2id$v=19$m=65536,t=4,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"high-parallelism": {"$argon2id$v=19$m=65536,t=3,p=5$" + validSalt + "$" + validKey, ErrInvalidHash},
		"lane-overflow":    {"$argon2id$v=19$m=65536,t=3,p=256$" + validSalt + "$" + validKey, ErrInvalidHash},
		"zero-iterations":  {"$argon2id$v=19$m=65536,t=0,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"zero-parallelism": {"$argon2id$v=19$m=65536,t=3,p=0$" + validSalt + "$" + validKey, ErrInvalidHash},
		"memory-rounding":  {"$argon2id$v=19$m=31,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"version-suffix":   {"$argon2id$v=19junk$m=65536,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"parameter-suffix": {"$argon2id$v=19$m=65536,t=3,p=4junk$" + validSalt + "$" + validKey, ErrInvalidHash},
		"extra-parameter":  {"$argon2id$v=19$m=65536,t=3,p=4,x=1$" + validSalt + "$" + validKey, ErrInvalidHash},
		"signed-parameter": {"$argon2id$v=19$m=+65536,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"salt-newline":     {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "\n$" + validKey, ErrInvalidHash},
		"salt-padding":     {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "==$" + validKey, ErrInvalidHash},
		"salt-pad-bits":    {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt[:len(validSalt)-1] + "B$" + validKey, ErrInvalidHash},
		"oversized-salt":   {"$argon2id$v=19$m=65536,t=3,p=4$" + base64.RawStdEncoding.EncodeToString(make([]byte, MaxSaltLength+1)) + "$" + validKey, ErrInvalidHash},
		"oversized-key":    {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, MaxKeyLength+1)), ErrInvalidHash},
		"oversized-text":   {strings.Repeat("$", MaxEncodedHashBytes+1), ErrInvalidHash},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := Verify("pw", tc.hash)
			if ok {
				t.Error("Verify returned true for malformed hash")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	current, err := Hash("value-long-enough")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if NeedsRehash(current) {
		t.Error("NeedsRehash = true for current-parameter hash, want false")
	}

	salt := base64.RawStdEncoding.EncodeToString(make([]byte, SaltLength))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, KeyLength))

	weaker := map[string]string{
		"low-memory":      fmt.Sprintf("$argon2id$v=19$m=%d,t=3,p=4$%s$%s", Memory/2, salt, key),
		"low-iterations":  fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=4$%s$%s", Memory, salt, key),
		"low-parallelism": fmt.Sprintf("$argon2id$v=19$m=%d,t=3,p=1$%s$%s", Memory, salt, key),
		"malformed":       "garbage",
	}
	for name, h := range weaker {
		t.Run(name, func(t *testing.T) {
			if !NeedsRehash(h) {
				t.Error("NeedsRehash = false, want true for weaker/invalid params")
			}
		})
	}
}

// TestCrossPasswordVerifyFails guards against any accidental salt reuse or
// truncation making distinct passwords collide.
func TestCrossPasswordVerifyFails(t *testing.T) {
	h1, err := Hash("password-one-long")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := Verify("password-two-long", h1)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("password-two verified against password-one hash")
	}
}

func TestCreationValidation(t *testing.T) {
	cases := map[string]struct {
		password string
		wantErr  error
	}{
		"empty":            {"", ErrTooShort},
		"14-codepoints":    {strings.Repeat("a", 14), ErrTooShort},
		"15-codepoints":    {strings.Repeat("a", 15), nil},
		"persian-14":       {strings.Repeat("\u0628", 14), ErrTooShort},
		"persian-15":       {strings.Repeat("\u0628", 15), nil},
		"combining-marks":  {"a" + strings.Repeat("\u0301", 14), nil},
		"replacement-rune": {strings.Repeat("a", 14) + "\ufffd", nil},
		"1024-bytes":       {strings.Repeat("a", 1024), nil},
		"1025-bytes":       {strings.Repeat("a", 1025), ErrTooLong},
		"persian-1024":     {strings.Repeat("\u0628", 512), nil},
		"persian-1025":     {strings.Repeat("\u0628", 512) + "a", ErrTooLong},
		"spaces-count":     {strings.Repeat("a", 13) + "  ", nil},
		"only-spaces":      {strings.Repeat(" ", 15), nil},
		"invalid-utf8":     {strings.Repeat("a", 14) + "\xff", ErrInvalidUTF8},
		"compromised":      {"password123456789", ErrCompromisedPassword},
		"published":        {"correct horse battery staple", ErrCompromisedPassword},
		"numeric":          {"123456789012345", ErrCompromisedPassword},
		"keyboard":         {"qwertyuiopasdfgh", ErrCompromisedPassword},
		"no-trimming":      {" password123456789 ", nil},
		"no-case-folding":  {"Password123456789", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Validate(tc.password); !errors.Is(err, tc.wantErr) {
				t.Errorf("Validate error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				encoded, err := HashContext(context.Background(), tc.password)
				if encoded != "" || !errors.Is(err, tc.wantErr) {
					t.Errorf("HashContext = (%q, %v), want empty hash and %v", encoded, err, tc.wantErr)
				}
			}
		})
	}
	if CompromisedListVersion == "" {
		t.Fatal("compromised list must have a version")
	}
}

func TestHashExactBytes(t *testing.T) {
	cases := []struct {
		name, password, altered string
	}{
		{"spaces", "  exact password bytes  ", "exact password bytes"},
		{"normalization", strings.Repeat("x", 14) + "\u00e9", strings.Repeat("x", 14) + "e\u0301"},
		{"persian", strings.Repeat("\u0628", 15) + " ", strings.Repeat("\u0628", 15)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := HashContext(context.Background(), tc.password)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := VerifyContext(context.Background(), tc.password, encoded); err != nil || !ok {
				t.Fatalf("exact bytes failed verification: ok=%v err=%v", ok, err)
			}
			if ok, err := VerifyContext(context.Background(), tc.altered, encoded); err != nil || ok {
				t.Fatalf("altered bytes verification: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestExistingPasswordsBypassCreationRules(t *testing.T) {
	for name, password := range map[string]string{
		"empty": "", "short": "old", "invalid-utf8": "old\xff",
		"over-1024": strings.Repeat("x", 1025), "compromised": "password123456789",
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(password); err == nil {
				t.Fatal("fixture must fail creation rules")
			}
			salt := []byte("old-password-salt")
			key := argon2.IDKey([]byte(password), salt, 1, 8, 1, KeyLength)
			encoded := fmt.Sprintf("$argon2id$v=19$m=8,t=1,p=1$%s$%s",
				base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
			if ok, err := Verify(password, encoded); err != nil || !ok {
				t.Fatalf("old credential rejected: ok=%v err=%v", ok, err)
			}
			rehashed, err := RehashContext(context.Background(), password)
			if err != nil {
				t.Fatal(err)
			}
			if NeedsRehash(rehashed) {
				t.Error("rehash did not use current parameters")
			}
			if ok, err := VerifyContext(context.Background(), password, rehashed); err != nil || !ok {
				t.Fatalf("rehashed credential rejected: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestDecodeBounds(t *testing.T) {
	b64 := base64.RawStdEncoding
	maxHash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", Memory, Iterations, Parallelism,
		b64.EncodeToString(make([]byte, MaxSaltLength)), b64.EncodeToString(make([]byte, MaxKeyLength)))
	textBoundary := strings.Replace(maxHash, "m=", "m="+strings.Repeat("0", MaxEncodedHashBytes-len(maxHash)), 1)
	for name, encoded := range map[string]string{
		"max-cost-salt-key": maxHash,
		"max-text":          textBoundary,
		"min-cost-salt-key": "$argon2id$v=19$m=8,t=1,p=1$AA$AA",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decode(encoded); err != nil {
				t.Fatalf("within bounds: %v", err)
			}
		})
	}
	if len(textBoundary) != MaxEncodedHashBytes {
		t.Fatal("incorrect text boundary fixture")
	}
	if _, _, _, err := decode(strings.Replace(textBoundary, "m=", "m=0", 1)); !errors.Is(err, ErrInvalidHash) {
		t.Errorf("oversized PHC text error = %v", err)
	}
}

func TestContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HashContext(ctx, "new-password-long"); !errors.Is(err, context.Canceled) {
		t.Errorf("HashContext error = %v", err)
	}
	if _, err := RehashContext(ctx, "old"); !errors.Is(err, context.Canceled) {
		t.Errorf("RehashContext error = %v", err)
	}
	if _, err := VerifyContext(ctx, "old", "invalid"); !errors.Is(err, context.Canceled) {
		t.Errorf("VerifyContext error = %v", err)
	}
	if err := DummyVerifyContext(ctx, "old"); !errors.Is(err, context.Canceled) {
		t.Errorf("DummyVerifyContext error = %v", err)
	}
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	if err := DummyVerifyContext(deadline, "old"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expired context error = %v", err)
	}
	if len(computations) != 0 {
		t.Fatal("canceled contexts admitted computation")
	}
}

func TestDecodeRejectsOversizedTextBeforeAllocating(t *testing.T) {
	encoded := strings.Repeat("$", 1<<20)
	allocations := testing.AllocsPerRun(10, func() {
		if _, _, _, err := decode(encoded); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("oversized PHC error = %v", err)
		}
	})
	if allocations != 0 {
		t.Errorf("oversized PHC parsing allocated %v times, want zero", allocations)
	}
}

func TestDummyVerifyContext(t *testing.T) {
	if err := DummyVerifyContext(context.Background(), "not-an-existing-password"); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledComputationKeepsSharedSlot(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		waitForEmptyGate(t)
	})
	started := make(chan struct{}, MaxComputations)
	results := make(chan error, MaxComputations)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range MaxComputations {
		go func() {
			_, err := computeKey(ctx, func() []byte {
				started <- struct{}{}
				<-release
				return []byte("key")
			})
			results <- err
		}()
	}
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for range MaxComputations {
		select {
		case <-started:
		case <-timeout.C:
			t.Fatal("computations did not start")
		}
	}
	cancel()
	for range MaxComputations {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("active cancellation error = %v", err)
			}
		case <-timeout.C:
			t.Fatal("canceled caller kept waiting for computation")
		}
	}
	if len(computations) != MaxComputations {
		t.Fatalf("canceled active work holds %d slots, want %d", len(computations), MaxComputations)
	}
	const encoded = "$argon2id$v=19$m=8,t=1,p=1$AA$AA"
	apis := map[string]func() error{
		"hash":           func() error { _, err := HashContext(context.Background(), "new-password-long"); return err },
		"hash-wrapper":   func() error { _, err := Hash("new-password-long"); return err },
		"verify":         func() error { _, err := VerifyContext(context.Background(), "old", encoded); return err },
		"verify-wrapper": func() error { _, err := Verify("old", encoded); return err },
		"rehash":         func() error { _, err := RehashContext(context.Background(), "old"); return err },
		"dummy":          func() error { return DummyVerifyContext(context.Background(), "old") },
	}
	for name, call := range apis {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrBusy) {
				t.Fatalf("shared gate error = %v, want ErrBusy", err)
			}
		})
	}
	releaseOnce.Do(func() { close(release) })
	waitForEmptyGate(t)
	key, err := computeKey(context.Background(), func() []byte { return []byte("available") })
	if err != nil || string(key) != "available" {
		t.Fatalf("finished computation did not free capacity: key=%q err=%v", key, err)
	}
}

func TestConcurrentAdmissionIsBounded(t *testing.T) {
	const callers = 24
	start := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		waitForEmptyGate(t)
	})
	results := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			_, err := computeKey(context.Background(), func() []byte {
				<-release
				return []byte("key")
			})
			results <- err
		}()
	}
	close(start)
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for range callers - MaxComputations {
		select {
		case err := <-results:
			if !errors.Is(err, ErrBusy) {
				t.Fatalf("excess admission error = %v, want ErrBusy", err)
			}
		case <-timeout.C:
			t.Fatal("excess callers queued instead of being rejected")
		}
	}
	if len(computations) != MaxComputations {
		t.Fatalf("admitted %d computations, want %d", len(computations), MaxComputations)
	}
	releaseOnce.Do(func() { close(release) })
	for range MaxComputations {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("admitted computation failed: %v", err)
			}
		case <-timeout.C:
			t.Fatal("admitted computation did not finish")
		}
	}
}

func waitForEmptyGate(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(computations) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("computation slots did not drain")
		}
		runtime.Gosched()
	}
}
