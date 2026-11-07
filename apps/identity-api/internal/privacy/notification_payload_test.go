package privacy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

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
			if _, err := h.svc.RequestDeletion(t.Context(), u.ID, u.AuthVersion, ""); err != nil || len(h.store.notifications) != tc.count {
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
