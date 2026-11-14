---
name: task-verification
description: Required completion gate for every code, configuration or test task in this repository. Use before reporting completion or an authorized commit/push, after resolving conflicts, and when preventing recurrence of CI failures.
---

# Task Completion Verification

Use this repository skill for local completion checks. Keep GitHub Actions as
the independent release gate; do not move or disable its checks. This is agent
workflow guidance, not a Git hook or an automatic authorization to commit/push.

## Final Source, One Pass

1. Finish implementation and resolve conflicts before the completion pass.
2. Inspect `git status --short` and the combined staged, unstaged and untracked
   changes. Include newly created files; never review the index alone.
3. Read `.github/workflows/identity-api.yml` and resolve projects with
   `npm exec -- nx show project <name> --json`. Use those current commands and
   toolchain versions, not remembered target names or a newer host toolchain.
4. The integrating agent runs each required gate once on the final source.
   Reuse already observed results only when their relevant source, configuration
   and toolchain remain unchanged. Do not duplicate full suites in every child
   agent or after every small edit.
5. If a failure needs a fix, or external edits/conflict resolution change the
   verified source, rerun the invalidated gates. "Once" never means preserving a
   stale result. Freeze source and Git identity during real browser acceptance.

## Required Regression Gates

Run these four regression classes for every code, configuration or test task,
even if focused unit tests already pass. They cover failures that escaped local
checks in the registration/username delivery. Commands below run from the
repository root; verify them against the workflow before executing.

### Go Lint, Including Integration Tags

```bash
npm exec -- nx run identity-api:lint --skipNxCache
npm exec -- nx run identity-api:lint --skipNxCache --args='--build-tags=integration'
```

Use the CI-pinned Go and golangci-lint versions. Resolve hidden diagnostics after
the first failure; a capped output is not the complete issue inventory. Never
disable linters, add blanket suppressions or remove integration-tag coverage.

### CI Release And Container Policy Tests

```bash
npm exec -- nx exec -p schemas -- node --test "$PWD"/.github/scripts/*.test.mjs
```

This includes Compose interpolation, secret isolation, release provenance,
source identity, browser privacy and acceptance-report contracts. Required
feature environment values must be explicit test fixtures, not production
defaults. Keep worker-only provisioning inactive and provider-free.

### Real Retention Integration

```bash
npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-retention-integration
```

Use the existing allowlisted harness with freshly owned disposable services.
Never run a bare database target against inherited `DATABASE_URL`, migrate a
shared database, bypass a safety trigger or relax zero-skip evidence. Confirm
successful tests, the expected package inventory and complete teardown.
Migration changes also require exact lineage and forward-only recovery tests.

### Real Admin Browser Acceptance

```bash
npm exec -- nx run web:test-admin-browser --skipNxCache
```

Use Chromium and the real API dependency chain, including both `en` and `fa-IR`.
Confirm mobile/desktop keyboard focus, contrast, structural privacy masks,
security assertions, unchanged source identity and complete teardown. Unit
geometry probes supplement this target; they do not replace it. Never relax
viewport assertions, mask private diagnostics incorrectly or silently skip the
second locale after the first locale fails.

## Additional Affected Gates

- Go changes: run the applicable unit tests, race detector and vet. Security,
  database and integration fixture changes also require integration-tag vet and
  the relevant allowlisted integration/race suites from the workflow.
- Web/shared UI changes: run lint, tests and type checking for the affected
  projects. Use `--max-warnings=0` and the workflow's test flags when matching CI.
  Production presentation changes require the corresponding build/browser gate.
- SQL/protobuf changes: run SQL vet, schema lint and generation checks through
  Nx. Keep ignored generated outputs out of commits; preserve reproducibility.
- Registration/container changes: include the existing registration and Compose
  acceptance gates when affected. Missing immutable images/manifests are explicit
  unverified prerequisites, never permission to invent evidence or activate a
  production username policy.
- Documentation-only work: check formatting and referenced paths/commands; report
  the scope as documentation-only instead of claiming runtime gates passed.

Use compiler-enabled Linux/CGO tooling for race checks. Check the workflow for
current Node, npm, Go and linter versions. Do not count an environment failure as
successful verification or change project/global toolchain configuration to hide it.

## Completion Evidence And Git Safety

- Record the final source/commit identity, commands, toolchain, pass/fail status,
  test/package counts where available, skipped tests and teardown result.
- Fix failed gates before marking a task fully verified. If a required gate
  cannot run, report it as not run with the exact prerequisite; request explicit
  acceptance of partial verification before proceeding as if the task were green.
- Preserve user changes and external staging. Stop for conflicting external
  edits unless the user explicitly authorizes conflict resolution.
- Stage only intended files and never secrets. Commit, amend, push or create a
  PR only when explicitly authorized. Do not use stash/autostash to integrate
  concurrent worktrees, bypass hooks or force-push.
- After an authorized push, identify CI runs by the pushed SHA. A local green
  pass is not a claim that GitHub CI passed. For a requested later check, schedule
  a wakeup instead of sleeping or polling; inspect that exact run when it fires.
