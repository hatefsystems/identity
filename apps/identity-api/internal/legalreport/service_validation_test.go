package legalreport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func TestReportRowRejectsPrivateFieldsEvenWithMatchingDigest(t *testing.T) {
	payload, err := sanitize(2025, time.Time{}, Totals{})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		strings.Replace(string(payload), `"year":2025`, `"year":2025,"case_id":"private"`, 1),
		strings.Replace(string(payload), `"status":"no_coverage"`, `"status":"private narrative"`, 1),
		strings.Replace(string(payload), `"year":2025`, `"year":2024`, 1),
	} {
		hash := sha256.Sum256([]byte(body))
		_, err := fromRow(db.LegalTransparencyReport{Year: 2025, SchemaVersion: SchemaVersion, Payload: []byte(body), Digest: hex.EncodeToString(hash[:])})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unsafe stored report accepted: %v", err)
		}
	}
}
