//go:build integration

package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminAbsentEmailDirectoryAndDetailIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	old := *f.target.Email
	if _, err := f.pool.Exec(t.Context(), `UPDATE users SET email=NULL WHERE id=$1`, f.target.ID); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"support", "moderator"} {
		for _, path := range []string{"/users", "/users/" + f.target.ID.String()} {
			response := f.request(t, role, http.MethodGet, path, "", "")
			if response.Code != http.StatusOK {
				t.Fatal("absent email broke admin reader")
			}
			var fields map[string]json.RawMessage
			if path == "/users" {
				var page struct {
					Items []map[string]json.RawMessage `json:"items"`
				}
				if json.Unmarshal(response.Body.Bytes(), &page) != nil {
					t.Fatal("invalid admin page")
				}
				for _, candidate := range page.Items {
					if string(candidate["id"]) == `"`+f.target.ID.String()+`"` {
						fields = candidate
					}
				}
			} else if json.Unmarshal(response.Body.Bytes(), &fields) != nil {
				t.Fatal("invalid admin detail")
			}
			if fields == nil {
				t.Fatal("absent email account omitted from directory")
			}
			value, present := fields["email"]
			if role == "support" && present || role == "moderator" && (!present || string(value) != "null") {
				t.Fatal("admin omitted redaction/explicit absence distinction")
			}
		}
	}
	response := f.request(t, "moderator", http.MethodPost, "/users/lookup", `{"email":"`+old+`"}`, "")
	var page struct {
		Total int64             `json:"total"`
		Items []json.RawMessage `json:"items"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatal("removed email remained exact-lookup identity")
	}
}
