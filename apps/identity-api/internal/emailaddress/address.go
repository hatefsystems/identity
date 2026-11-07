// Package emailaddress defines the supported identity and delivery mailbox
// profile, not every RFC mailbox.
package emailaddress

import (
	"errors"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// MaxRawBytes bounds work before trimming, normalization or IDNA conversion.
const MaxRawBytes = 1024

// ErrInvalid is fixed and never contains a supplied address or IDNA diagnostic.
var ErrInvalid = errors.New("emailaddress: invalid mailbox")

var domainProfile = idna.New(idna.MapForLookup(), idna.Transitional(false),
	idna.StrictDomainName(true), idna.ValidateLabels(true), idna.CheckHyphens(true),
	idna.CheckJoiners(true), idna.VerifyDNSLength(true), idna.BidiRule())

// Canonicalize returns NFC(lowercase(NFC(local))) at a lowercase, strict,
// nontransitional IDNA lookup domain. It never applies NFKC to the local part or
// strips invisible characters. ASCII atom punctuation, Unicode letters, numbers
// and combining marks are supported; quoted forms, lists and literals are not.
func Canonicalize(address string) (string, error) {
	if len(address) > MaxRawBytes || !utf8.ValidString(address) {
		return "", ErrInvalid
	}
	// Reject unsafe characters before lookup mapping can remove them. Only outer
	// non-control whitespace may be trimmed; CR/LF and other controls never pass.
	for _, c := range address {
		if unsafeRune(c) {
			return "", ErrInvalid
		}
	}
	address = strings.TrimSpace(address)
	if strings.Count(address, "@") != 1 {
		return "", ErrInvalid
	}
	local, domain, _ := strings.Cut(address, "@")
	local = norm.NFC.String(strings.ToLower(norm.NFC.String(local)))
	if !validLocal(local) {
		return "", ErrInvalid
	}
	domain, err := domainProfile.ToASCII(domain)
	if err != nil {
		return "", ErrInvalid
	}
	domain = strings.ToLower(domain)
	result := local + "@" + domain
	if !ValidMailbox(result) {
		return "", ErrInvalid
	}
	return result, nil
}

// ValidCanonicalMailbox admits only exact canonical identities for new stored
// contacts/proofs. Unlike ValidMailbox it rejects case or normalization changes.
func ValidCanonicalMailbox(address string) bool {
	canonical, err := Canonicalize(address)
	return err == nil && canonical == address
}

// ValidMailbox validates an already-bound delivery address without changing its
// local-part identity. It permits case-preserving stored local parts and DNS
// casing, but requires NFC local bytes and an ASCII IDNA domain. Callers must
// send these exact bytes, not silently canonicalize an authenticated recipient.
func ValidMailbox(address string) bool {
	if len(address) < 3 || len(address) > 254 || !utf8.ValidString(address) || strings.Count(address, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(address, "@")
	if !validLocal(local) || !norm.NFC.IsNormalString(local) || !validDomain(domain) {
		return false
	}
	// A syntactically valid xn-- label must also encode a supported IDNA label.
	ascii, err := domainProfile.ToASCII(domain)
	if err != nil || !strings.EqualFold(ascii, domain) {
		return false
	}
	decoded, err := domainProfile.ToUnicode(domain)
	if err != nil {
		return false
	}
	for _, c := range decoded {
		if unsafeRune(c) || unicode.IsSpace(c) {
			return false
		}
	}
	return true
}

func validLocal(local string) bool {
	if len(local) == 0 || len(local) > 64 || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for _, c := range local {
		if unsafeRune(c) || unicode.IsSpace(c) ||
			!strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~.", c) &&
				(c <= unicode.MaxASCII || !unicode.IsLetter(c) && !unicode.IsNumber(c) && !unicode.IsMark(c)) {
			return false
		}
	}
	return true
}

func unsafeRune(c rune) bool {
	return c == utf8.RuneError || unicode.IsControl(c) || unicode.Is(unicode.Cf, c) ||
		unicode.Is(unicode.Bidi_Control, c) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, c) ||
		unicode.Is(unicode.Variation_Selector, c) || unicode.Is(unicode.Noncharacter_Code_Point, c)
}

func validDomain(domain string) bool {
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
