package audit

import (
	"strings"
	"testing"
)

// TestAdminAndLegalEventsAreNeverLedgered pins Decision 8 of the Task 5.3 plan:
// administrative and lawful-request events are Class C, audit-only, and must
// never produce a security_event_ledger row.
//
// This is a structural constraint, not a preference.
// security_event_ledger.account_ref is NOT NULL and is defined as the *subject*
// of the event (tasks.md:54). For an admin action the account that matters is
// the actor — the administrator — so a ledger row would file an admin's action
// under whichever user id landed in account_ref, fabricating attribution
// evidence against the wrong person. It would also make that row survive the
// subject's erasure, which is exactly what the ledger's survival property is
// reserved for and exactly what it should not be spent on here.
//
// The test enumerates the constants explicitly rather than only prefix-matching
// so that renaming one to something outside the admin./legal. namespaces does
// not silently remove it from the check.
func TestAdminAndLegalEventsAreNeverLedgered(t *testing.T) {
	classC := []struct {
		name  string
		event string
	}{
		{"EventAdminUserStatusChanged", EventAdminUserStatusChanged},
		{"EventAdminRoleAssigned", EventAdminRoleAssigned},
		{"EventAdminAuditLogsQueried", EventAdminAuditLogsQueried},
		{"EventAdminChainVerified", EventAdminChainVerified},
		{"EventAdminAccessDenied", EventAdminAccessDenied},
		{"EventLegalHoldApplied", EventLegalHoldApplied},
		{"EventLegalHoldReleased", EventLegalHoldReleased},
		{"EventLegalPreservationRecorded", EventLegalPreservationRecorded},
		{"EventLegalInquiryLookup", EventLegalInquiryLookup},
	}

	for _, tc := range classC {
		t.Run(tc.name, func(t *testing.T) {
			if IsLedgerEventType(tc.event) {
				t.Fatalf("%s (%q) is a member of LedgerEventTypes; admin and legal events are "+
					"Class C audit-only. security_event_ledger.account_ref is the event *subject*, "+
					"but the account here is the *actor*, so ledgering this misattributes an "+
					"administrator's action to a user and makes it outlive that user's erasure.",
					tc.name, tc.event)
			}
		})
	}
}

// TestNoAdminOrLegalPrefixInLedgerEventTypes is the catch-all half of the
// guard above: it fails on any future admin.* or legal.* event added to the
// ledger set, including ones this test file does not know about yet.
func TestNoAdminOrLegalPrefixInLedgerEventTypes(t *testing.T) {
	for eventType := range LedgerEventTypes {
		if strings.HasPrefix(eventType, "admin.") || strings.HasPrefix(eventType, "legal.") {
			t.Fatalf("LedgerEventTypes contains %q; admin.* and legal.* events are Class C "+
				"and must stay audit-only (see the Class C block in audit.go)", eventType)
		}
	}
}
