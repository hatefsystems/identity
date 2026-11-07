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

func TestUnicodeNotificationIntentsPreserveBoundRecipient(t *testing.T) {
	for _, tc := range []struct {
		primary, backup string
		count           int
	}{
		{"\u0639\u0644\u06cc@xn--mgbh0fb.xn--mgba3a4f16a", "\u0639\u0644\u06cc@XN--MGBH0FB.XN--MGBA3A4F16A", 1},
		{"\u0639\u0644\u06cc@example.test", "\u0639\u0644\u064a@example.test", 2},
		{"\u06a9@example.test", "\u0643@example.test", 2},
		{"user@example.test", "\uff55ser@example.test", 2},
		{"\u00c9@EXAMPLE.test", "\u00e9@example.test", 2},
	} {
		t.Run(tc.primary, func(t *testing.T) {
			h := newHarness(t, Config{})
			u := h.store.addActiveUser(tc.primary)
			var err error
			u.BackupEmailEncrypted, err = h.cipher.Encrypt(t.Context(), []byte(tc.backup))
			if err != nil {
				t.Fatal(err)
			}
			h.store.users[u.ID] = u
			if _, err := h.svc.RequestDeletion(t.Context(), u.ID, u.AuthVersion, "", notification.English); err != nil || len(h.store.notifications) != tc.count {
				t.Fatal("Unicode recipient intent creation failed", err)
			}
			request := h.store.requests[0]
			for _, row := range h.store.notifications {
				plain, err := h.cipher.Decrypt(t.Context(), row.PayloadEncrypted)
				if err != nil {
					t.Fatal(err)
				}
				notice, err := decodeNotificationPayload(plain, row, request)
				clear(plain)
				want := tc.primary
				if row.RecipientRole == "backup" {
					want = tc.backup
				}
				if err != nil || notice.PrimaryEmail != want {
					t.Fatal("authenticated Unicode recipient was rerouted", err)
				}
			}
		})
	}
}

func TestNotificationPayloadRejectsMalformedUnicodeAndNonNFCBindings(t *testing.T) {
	h := newHarness(t, Config{})
	requestDeletionAndToken(t, h, "bound@example.test")
	row := h.store.notifications[h.store.notificationIDs[0]]
	request := h.store.requests[0]
	plain, err := h.cipher.Decrypt(t.Context(), row.PayloadEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	for _, replacement := range []string{
		"ae\u0301@example.test", "a\u200cb@example.test", "a\u200fb@example.test", "a\ufffdb@example.test",
		"a\\ud800b@example.test", "a\\udc00b@example.test", "a\\ud800\\ud800b@example.test",
		"a\xFFb@example.test", "a\xED\xA0\x80b@example.test",
	} {
		// Replace the encoded recipient to exercise raw JSON decoding, including
		// the standard decoder's replacement of lone UTF-16 surrogate escapes.
		mutated := bytes.Replace(plain, []byte("bound@example.test"), []byte(replacement), 1)
		if _, err := decodeNotificationPayload(mutated, row, request); err == nil || strings.Contains(err.Error(), replacement) {
			t.Fatal("malformed Unicode recipient accepted or disclosed")
		}
	}
	var payload notificationPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatal(err)
	}
	payload.Recipient = "\u00c9@EXAMPLE.test"
	bound, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	notice, err := decodeNotificationPayload(bound, row, request)
	if err != nil || notice.PrimaryEmail != payload.Recipient {
		t.Fatal("valid stored binding was silently normalized")
	}
}
