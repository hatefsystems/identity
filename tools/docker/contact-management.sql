-- Explicit operator provisioning only, after migration 00011. Supply the existing
-- restricted runtime role with psql -v runtime_role=...; this creates no role,
-- activates no provider and changes no unrelated table privileges.
\set ON_ERROR_STOP on
BEGIN;
GRANT SELECT, INSERT, DELETE ON public.contact_management_action_proofs,
    public.contact_change_attempts TO :"runtime_role";
REVOKE UPDATE, TRUNCATE, REFERENCES, TRIGGER ON public.contact_management_action_proofs,
    public.contact_change_attempts FROM :"runtime_role";
COMMIT;
