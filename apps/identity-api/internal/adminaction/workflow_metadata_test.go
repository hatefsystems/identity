package adminaction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

func TestWorkflowAuditContainsNoRestrictedFingerprints(t *testing.T) {
	for _, operation := range []string{
		"POST /api/v1/admin/legal-cases", "GET /api/v1/admin/legal-cases/{case_id}",
		"POST /api/v1/admin/legal-holds/{hold_id}/reviews",
		"POST /api/v1/admin/legal-transparency/reports/{report_id}/download",
	} {
		t.Run(operation, func(t *testing.T) {
			event, err := sanitizedEvent(audit.Event{
				EventType: "legal.case.read", ActionStatus: audit.StatusSuccess,
				ActorID: uuid.New(), ClientIP: "192.0.2.1", UserAgent: "sensitive-client",
				Payload: map[string]any{
					"operation": operation, "http_status": 200, "result_count": 1,
					"response_digest": strings.Repeat("a", 64), "record_set_digest": strings.Repeat("b", 64),
					"hold_id": uuid.New().String(), "case_id": uuid.New().String(), "narrative": "secret",
				},
			}, uuid.New())
			if err != nil {
				t.Fatal(err)
			}
			if len(event.Payload) != 4 || event.ClientIP != "" || event.UserAgent != "" || event.SubjectID != nil {
				t.Fatalf("unexpected audit projection: %+v", event)
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"response_digest", "record_set_digest", `"case_id":`, `"hold_id":`, "secret", "sensitive-client"} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("audit contains %q", forbidden)
				}
			}
		})
	}
}

func TestWorkflowOperationUsesExactRouteTemplates(t *testing.T) {
	for _, operation := range []string{
		"GET /api/v1/admin/users", "GET /api/v1/admin/legal-cases/" + uuid.NewString(),
		"POST /api/v1/admin/legal-cases-extra", "POST /api/v1/admin/legal-cases?email=secret",
	} {
		if IsLegalWorkflowOperation(operation) {
			t.Fatalf("unexpected workflow operation %q", operation)
		}
	}
}

func TestWorkflowEarlyDenialUsesRestrictedProjection(t *testing.T) {
	event, err := sanitizedEvent(audit.Event{EventType: "admin.request", ActionStatus: audit.StatusFailure,
		ClientIP: "192.0.2.1", UserAgent: "private-agent", Payload: map[string]any{
			"operation": "POST /api/v1/admin/*", "http_status": 403, "workflow_restricted": true,
			"response_digest": strings.Repeat("a", 64),
		}}, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if event.ClientIP != "" || event.UserAgent != "" || len(event.Payload) != 3 {
		t.Fatalf("early denial projection: %+v", event)
	}
	for _, path := range []string{"/api/v1/admin/legal-cases", "/api/v1/admin/legal-cases/invalid", "/api/v1/admin/legal-holds/invalid/reviews", "/api/v1/admin/legal-transparency/reports/x/download"} {
		if !IsLegalWorkflowPath(path) {
			t.Fatalf("unresolved workflow not protected: %s", path)
		}
	}
	if IsLegalWorkflowPath("/api/v1/admin/legal-cases-other") {
		t.Fatal("matched unrelated path")
	}
}
