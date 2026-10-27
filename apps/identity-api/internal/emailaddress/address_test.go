package emailaddress

import (
	"strings"
	"testing"
)

func TestValidMailbox(t *testing.T) {
	for _, address := range []string{
		"user@example.test", "UPPER+tag@EXAMPLE.Test", "o'hara@example.test", "a!#$%&'*+-/=?^_`{|}~b@example.test",
		"user@xn--bcher-kva.example", strings.Repeat("a", 64) + "@example.test",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
	} {
		t.Run(address, func(t *testing.T) {
			if !ValidMailbox(address) {
				t.Fatal("supported mailbox rejected")
			}
		})
	}
}

func TestInvalidMailbox(t *testing.T) {
	for _, address := range []string{
		"", "@example.test", "user@", "user@localhost", "user@127.0.0.1", "user@[127.0.0.1]", "user@[IPv6:::1]",
		"Display <user@example.test>", "<user@example.test>", "\"quoted\"@example.test", "user(comment)@example.test",
		"a@example.test,b@example.test", "a@@example.test", ".user@example.test", "user.@example.test", "u..ser@example.test",
		" user@example.test", "user@example.test ", "user\t@example.test", "user\r\nBcc:other@example.test", "user\x00@example.test",
		"us\xc3\xa9r@example.test", "user@b\xc3\xbccher.example", "user@example.test.", "user@.example.test", "user@example..test",
		"user@-example.test", "user@example-.test", "user@under_score.test", "user@example/test", "user@ex<ample.test",
		strings.Repeat("a", 65) + "@example.test", "user@" + strings.Repeat("b", 64) + ".test",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
	} {
		t.Run(address, func(t *testing.T) {
			if ValidMailbox(address) {
				t.Fatal("unsupported or unsafe mailbox accepted")
			}
		})
	}
}
