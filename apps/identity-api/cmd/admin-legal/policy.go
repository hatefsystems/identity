package main

import (
	"context"
	"io"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
)

// policyInstall consumes a bounded external approval artifact. Attribution comes
// from the trusted process launcher, never the artifact or an HTTP request.
func policyInstall(ctx context.Context, actions *adminaction.Service, input io.Reader, environment string, operator uuid.UUID, identity string) error {
	if actions == nil {
		return adminaction.ErrNoOperation
	}
	policy, err := legalpolicy.Decode(input)
	if err != nil {
		return err
	}
	if err := policy.Validate(environment); err != nil {
		return err
	}
	op, err := actions.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = op.Rollback(context.WithoutCancel(ctx)) }()
	op.Event = audit.Event{ActorID: operator, ActorSPIFFEID: identity}
	if err := legalpolicy.Install(ctx, op, policy, environment); err != nil {
		return err
	}
	return op.Commit(ctx)
}
