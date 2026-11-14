<!-- nx configuration start-->
<!-- Leave the start & end comments to automatically receive updates. -->

# General Guidelines for working with Nx

- For navigating/exploring the workspace, invoke the `nx-workspace` skill first - it has patterns for querying projects, targets, and dependencies
- When running tasks (for example build, lint, test, e2e, etc.), always prefer running the task through `nx` (i.e. `nx run`, `nx run-many`, `nx affected`) instead of using the underlying tooling directly
- Prefix nx commands with the workspace's package manager (e.g., `pnpm nx build`, `npm exec nx test`) - avoids using globally installed CLI
- You have access to the Nx MCP server and its tools, use them to help the user
- For Nx plugin best practices, check `node_modules/@nx/<plugin>/PLUGIN.md`. Not all plugins have this file - proceed without it if unavailable.
- NEVER guess CLI flags - always check nx_docs or `--help` first when unsure

## Scaffolding & Generators

- For scaffolding tasks (creating apps, libs, project structure, setup), ALWAYS invoke the `nx-generate` skill FIRST before exploring or calling MCP tools

## When to use nx_docs

- USE for: advanced config options, unfamiliar flags, migration guides, plugin configuration, edge cases
- DON'T USE for: basic generator syntax (`nx g @nx/react:app`), standard commands, things you already know
- The `nx-generate` skill handles generator discovery internally - don't call nx_docs just to look up generator syntax


<!-- nx configuration end-->

# Task completion verification

- Before completing any code, configuration or test task, load the `task-verification` skill. If the skill is not available in the current session, read `.agents/skills/task-verification/SKILL.md` directly.
- Run its required local CI gates once against the final combined working-tree changes, including staged, unstaged and untracked files. Do not run the entire suite after every edit or separately for each collaborating agent; the integrating agent owns the final verification pass.
- Fix failures before declaring completion. Changes or conflict resolutions after a check invalidate affected evidence; rerun only the invalidated gates. Do not treat skipped tests, cached browser evidence, incomplete teardown or a different source identity as a passing run.
- Keep `.github/workflows/identity-api.yml` and resolved Nx targets as the command/toolchain authority. Report each required gate as passed, failed or not run with a concrete reason; do not weaken CI or security assertions to obtain a green result.

# Localization conventions

- Read `docs/localization.md` before changing presentation, preferences or notification templates.
- Keep `en` as the typed source and `fa-IR` structurally complete; use whole ICU messages/rich slots for owned JSX, ARIA, metadata, validation and feedback. Store message descriptors/status keys rather than translated strings in state. Update the source-prose guard's narrow allowlist only for reviewed technical data.
- Preserve unchanged routes, request-time CSP/SSR, strict authentication cookies, same-origin Server Action protections and stable provider/ceremony identities. Language/calendar/time-zone changes must not replay API work, rebootstrap a session or extend a deadline.
- Prefer logical styles. Isolate technical values LTR and names/narratives with automatic direction without altering wire/clipboard/download bytes. Calendar/time zone affect display only; canonical UTC evidence and decimal string precision remain primary and exact.
- Never add private values to catalogs, diagnostics or browser artifacts. Use structural screenshot masks and explicit expected accessible names for both locales. Keep `libs/ui` locale-agnostic.
- Notification v2 writers require v1/v2 readers first; retain compatible readers during rollback until live v2 work is handled. Never rewrite queued locale/token/deadline to change language. Manual Persian security/legal review and platform/deployed-ingress gates stay explicit until observed.
