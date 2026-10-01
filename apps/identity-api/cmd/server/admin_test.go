package main

import (
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
)

func TestAdminStartupFailsClosedOnMissingDependencies(t *testing.T) {
	deps, err := buildAdminServices(config.AdminConfig{}, "development", nil, nil)
	if err != nil || deps.AdminActions != nil || deps.LegalHold != nil {
		t.Fatalf("disabled admin: %+v %v", deps, err)
	}
	for _, environment := range []string{"development", "production"} {
		if _, err := buildAdminServices(config.AdminConfig{Enabled: true}, environment, nil, nil); err == nil {
			t.Fatalf("%s accepted enabled admin without backing dependencies", environment)
		}
	}
}
