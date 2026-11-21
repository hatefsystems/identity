package password

// CompromisedListVersion identifies the reviewed local denylist snapshot.
// Entries are common numeric/keyboard passwords or widely published examples,
// not private credentials. Changes require reviewing and advancing this version.
const CompromisedListVersion = "2026-11-20.1"

func compromised(password string) bool {
	// Compare exact bytes: no case folding, whitespace trimming or normalization.
	switch password {
	case "password", "password123", "password123456789",
		"123456789012345", "12345678901234567890", "qwertyuiopasdfgh",
		"correct horse battery staple":
		return true
	default:
		return false
	}
}
