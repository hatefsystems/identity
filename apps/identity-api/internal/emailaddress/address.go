// Package emailaddress defines the deliberately restricted mailbox format used
// by encrypted deletion notices and their SMTP transport, not every RFC mailbox.
package emailaddress

import (
	"net/netip"
	"strings"
)

// ValidMailbox accepts one bare ASCII dot-atom mailbox at a DNS domain. It does
// not normalize the address or support display names, lists, quoted local parts,
// domain/IP literals, or SMTPUTF8. DNS names are case-insensitive.
func ValidMailbox(address string) bool {
	if len(address) < 3 || len(address) > 254 || strings.Count(address, "@") != 1 {
		return false
	}
	for i := range len(address) {
		if address[i] < 33 || address[i] > 126 {
			return false
		}
	}
	local, domain, _ := strings.Cut(address, "@")
	if len(local) == 0 || len(local) > 64 || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for _, c := range local {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~.", c) {
			return false
		}
	}
	if len(domain) == 0 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	for _, label := range strings.Split(strings.ToLower(domain), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
