package privacy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/notification"
)

func TestNotificationPayloadVersionsAndFrozenLocale(t *testing.T) {
	for _, locale := range []notification.Locale{"en", "fa-IR", "unknown", ""} {
		t.Run(string(locale), func(t *testing.T) {
			h := newHarness(t, Config{})
			u := h.store.addActiveUser("locale@example.test")
			if _, err := h.svc.RequestDeletion(t.Context(), u.ID, 0, "", locale); err != nil {
				t.Fatal(err)
			}
			before := h.queuedNotice(t)
			want := notification.RequestLocale([]string{string(locale)})
			if before.Locale != want || before.TemplateVersion != notification.CurrentVersion {
				t.Fatal("writer did not freeze locale and template")
			}
			row := h.store.notifications[before.DeliveryID]
			plaintext, err := h.cipher.Decrypt(t.Context(), row.PayloadEncrypted)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plaintext)
			var payload notificationPayload
			if err := json.Unmarshal(plaintext, &payload); err != nil || payload.Version != 2 {
				t.Fatal("writer did not emit payload v2")
			}
			if bytes.Contains(row.PayloadEncrypted, []byte(before.ReclaimToken)) || bytes.Contains(row.PayloadEncrypted, []byte(u.Email)) {
				t.Fatal("queue contains plaintext delivery material")
			}
			// An already admitted duplicate cannot rewrite the original language.
			if _, err := h.svc.RequestDeletion(t.Context(), u.ID, 0, "", "en"); err != nil || h.queuedNotice(t) != before || len(h.store.notificationIDs) != 1 {
				t.Fatal("coalesced request changed frozen intent")
			}
			// Simulate an existing v1 envelope, which never carried locale fields.
			payload.Version, payload.Locale, payload.TemplateVersion = 1, "", 0
			legacy, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(legacy)
			notice, err := decodeNotificationPayload(legacy, row, h.store.requests[0])
			before.Locale, before.TemplateVersion = notification.English, notification.Version1
			if err != nil || notice != before {
				t.Fatal("v1 did not decode to original English delivery")
			}
		})
	}
}

func TestNotificationPayloadRejectsAmbiguousPresentation(t *testing.T) {
	h := newHarness(t, Config{})
	requestDeletionAndToken(t, h, "payload-validation@example.test")
	row := h.store.notifications[h.store.notificationIDs[0]]
	request := h.store.requests[0]
	plaintext, err := h.cipher.Decrypt(t.Context(), row.PayloadEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	for _, tc := range []struct{ name, old, replacement string }{
		{"unknown locale", `"locale":"en"`, `"locale":"ar"`},
		{"locale alias", `"locale":"en"`, `"locale":"fa"`},
		{"empty locale", `"locale":"en"`, `"locale":""`},
		{"null locale", `"locale":"en"`, `"locale":null`},
		{"locale type", `"locale":"en"`, `"locale":2`},
		{"missing locale", `,"locale":"en"`, ``},
		{"locale injection", `"locale":"en"`, `"locale":"fa-IR\r\nBcc: private@example.test"`},
		{"unknown template", `"template_version":1`, `"template_version":2`},
		{"zero template", `"template_version":1`, `"template_version":0`},
		{"negative template", `"template_version":1`, `"template_version":-1`},
		{"null template", `"template_version":1`, `"template_version":null`},
		{"template type", `"template_version":1`, `"template_version":"1"`},
		{"missing template", `,"template_version":1`, ``},
		{"v1 unexpected presentation", `"version":2`, `"version":1`},
		{"unknown payload", `"version":2`, `"version":3`},
		{"duplicate locale", `"locale":"en"`, `"locale":"fa-IR","locale":"en"`},
		{"duplicate template", `"template_version":1`, `"template_version":2,"template_version":1`},
		{"duplicate version", `"version":2`, `"version":1,"version":2`},
		{"case alias", `"locale":"en"`, `"Locale":"en"`},
		{"escaped duplicate", `"locale":"en"`, `"lo\u0063ale":"en","locale":"en"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(string(plaintext), tc.old, tc.replacement, 1)
			if input == string(plaintext) {
				t.Fatal("fixture mutation did not apply")
			}
			if got, err := decodeNotificationPayload([]byte(input), row, request); err == nil || got != (DeletionNotice{}) || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid presentation accepted or leaked")
			}
		})
	}
	for _, input := range [][]byte{nil, []byte("null"), []byte("[]"), bytes.Repeat([]byte(" "), 4097), append(bytes.Clone(plaintext), []byte("{}")...), append(bytes.Clone(plaintext), 0xff)} {
		if _, err := decodeNotificationPayload(input, row, request); err == nil {
			t.Fatal("unbounded or malformed payload accepted")
		}
	}
}
