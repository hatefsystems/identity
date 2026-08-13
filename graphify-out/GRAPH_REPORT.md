# Graph Report - ldp  (2026-08-12)

## Corpus Check
- 237 files · ~176,214 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2927 nodes · 5718 edges · 224 communities (175 shown, 49 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 424 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `052cc846`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- testing.T
- dpop_test.go
- time.Time
- server/webauthn_test.go
- clientauth_test.go
- compilerOptions
- Client
- context.Context
- New
- Service
- exclude
- time.Duration
- smsotp/service_test.go
- newTokenTestServer
- schemas/project.json
- Common Issues
- MemoryRefreshTokenStore
- Common Issues
- Common Issues
- newTestManager
- .agents/skills/monitor-ci/scripts/ci-poll-decide.mjs
- NewMockProvider
- ParsePublicJWK
- SigningKey
- .github/skills/monitor-ci/scripts/ci-poll-decide.mjs
- .opencode/skills/monitor-ci/scripts/ci-poll-decide.mjs
- Next.js
- Next.js
- Next.js
- Monitor CI Command
- Monitor CI Command
- Monitor CI Command
- include
- Monitor CI Command
- Monitor CI Command
- Service
- devDependencies
- fakeTx
- nx.json
- New
- server/phone_test.go
- include
- Hatef Identity Platform - Compliance & Data Governance
- cn
- Service
- ParseAuthorizationRequest
- dependencies
- compilerOptions
- Nx Workspace Exploration
- NewCookieCodec
- Nx Workspace Exploration
- Nx Workspace Exploration
- Status Handling by Code
- Jest
- Status Handling by Code
- Jest
- Status Handling by Code
- Jest
- newTestService
- NewRequireSession
- Hatef Identity Platform - Architecture Documentation
- Hatef Identity Platform - Data Architecture & Database Schemas
- components.json
- database/sql.DB
- Load
- buildSMSOTPService
- New
- credentials_test.go
- password_test.go
- Verify
- newClientCredentialsServer
- writeJSON
- net/http.HandlerFunc
- Steps
- Service
- 2.2 Constructing the Client JWT Assertion
- Steps
- Steps
- setupMFATestFixture
- dependencies
- 1. External APIs (REST & OIDC)
- Hatef Identity Platform - DevOps & Operational Playbook
- setupTestService
- command
- Hatef Identity Platform - Disaster Recovery & High Availability
- Hatef Identity Platform - Frontend Pages Structure
- 2. STRIDE Threat Analysis Matrix
- newAuthorizeTestServer
- Link Workspace Packages
- LoadOIDC
- sqlc-generate
- Link Workspace Packages
- nx-mcp
- Link Workspace Packages
- package.json
- Hatef Identity Platform (LDP) - Implementation Roadmap
- net/http.Request
- NormalizePhone
- ui/package.json
- Hatef Identity Platform (LDP)
- .agents/skills/monitor-ci/scripts/ci-state-update.mjs
- ESLint
- .agents/skills/nx-import/references/TURBOREPO.md
- Fix Orders
- identity-api/project.json
- identity-api
- Commands
- README.md
- 2. Identity & Security (Privacy-First)
- Commands
- .github/skills/monitor-ci/scripts/ci-state-update.mjs
- ESLint
- .github/skills/nx-import/references/TURBOREPO.md
- Fix Orders
- Commands
- .opencode/skills/monitor-ci/scripts/ci-state-update.mjs
- ESLint
- .opencode/skills/nx-import/references/TURBOREPO.md
- Fix Orders
- .agents/skills/nx-import/references/VITE.md
- Vite
- Vue-Specific
- Subnet
- 1.2 Demonstrating Proof-of-Possession (DPoP - RFC 9449)
- sync.Mutex
- .github/skills/nx-import/references/VITE.md
- Vite
- Vue-Specific
- schemas/package.json
- @hatef/schemas
- .opencode/skills/nx-import/references/VITE.md
- Vite
- Vue-Specific
- TanStack Start (Vite-Based)
- React-Specific
- .agents/skills/nx-run-tasks/SKILL.md
- NewEphemeralES256
- TestVerifyPKCE
- build
- targets
- 1. System Architecture
- TanStack Start (Vite-Based)
- React-Specific
- .github/skills/nx-run-tasks/SKILL.md
- ui/tsconfig.json
- TanStack Start (Vite-Based)
- React-Specific
- .opencode/skills/nx-run-tasks/SKILL.md
- tsconfig.json
- React Router 7 (Vite-Based)
- server/phone.go
- .handlePhoneSendCode
- toWebAuthnCredentialResponse
- web/jest.config.js
- React Router 7 (Vite-Based)
- React Router 7 (Vite-Based)
- General Guidelines for working with Nx
- Mixed React + Vue
- mfa.go
- lint
- test
- Mixed React + Vue
- Mixed React + Vue
- options
- options
- layout.tsx
- page.tsx
- ui
- .agents/skills/nx-import/references/GRADLE.md
- .agents/skills/nx-plugins/SKILL.md
- index.d.ts
- next.config.js
- next-env.d.ts
- postcss.config.js
- tailwind.config.js
- CLAUDE.md
- eslint
- eslint-config-next
- eslint-plugin-import
- eslint-plugin-jsx-a11y
- eslint-plugin-react
- eslint-plugin-react-hooks
- copilot-instructions.md
- .github/skills/nx-import/references/GRADLE.md
- .github/skills/nx-plugins/SKILL.md
- jest-environment-jsdom
- jest-util
- @next/eslint-plugin-next
- @nx/eslint
- @nx/jest
- @nx/js
- @nx/next
- @nx/react
- .opencode/skills/nx-import/references/GRADLE.md
- .opencode/skills/nx-plugins/SKILL.md
- nx
- postcss
- @swc/core
- @swc/helpers
- @swc-node/register
- @testing-library/dom
- @testing-library/react
- ts-jest
- ts-node
- @types/jest
- @types/node
- @types/react
- typescript
- typescript-eslint
- @typescript-eslint/eslint-plugin
- @typescript-eslint/parser
- github.com/hatefsystems/identity/apps/identity-api
- github.com/hatefsystems/identity/libs/schemas

## God Nodes (most connected - your core abstractions)
1. `newFixture()` - 62 edges
2. `newES256Signer()` - 33 edges
3. `Service` - 27 edges
4. `writeJSON()` - 27 edges
5. `challengeOf()` - 27 edges
6. `LoadWebAuthn()` - 26 edges
7. `newHarness()` - 26 edges
8. `newTestValidator()` - 25 edges
9. `newServiceFixture()` - 24 edges
10. `es256Signer()` - 23 edges

## Surprising Connections (you probably didn't know these)
- `LoadClients()` --calls--> `getEnv()`  [INFERRED]
  apps/identity-api/internal/config/clients.go → apps/identity-api/internal/config/config.go
- `loadMockChallengeKey()` --calls--> `getEnv()`  [INFERRED]
  apps/identity-api/internal/config/webauthn.go → apps/identity-api/internal/config/config.go
- `LoadWebAuthn()` --calls--> `getEnv()`  [INFERRED]
  apps/identity-api/internal/config/webauthn.go → apps/identity-api/internal/config/config.go
- `LoadWebAuthn()` --calls--> `getEnvDuration()`  [INFERRED]
  apps/identity-api/internal/config/webauthn.go → apps/identity-api/internal/config/config.go
- `TestEqual()` --calls--> `Equal()`  [INFERRED]
  apps/identity-api/internal/crypto/blindindex/blindindex_test.go → apps/identity-api/internal/crypto/blindindex/blindindex.go

## Import Cycles
- None detected.

## Communities (224 total, 49 thin omitted)

### Community 0 - "testing.T"
Cohesion: 0.05
Nodes (127): LoadCrypto(), randB64(), TestLoadCryptoDefaultVersion(), TestLoadCryptoInvalidBase64(), TestLoadCryptoInvalidVersion(), TestLoadCryptoMissingKEK(), TestLoadCryptoMissingPepper(), TestLoadCryptoShortPepper() (+119 more)

### Community 1 - "dpop_test.go"
Cohesion: 0.06
Nodes (86): buildDPoPValidator(), ProofFromContext(), AccessTokenHash(), canonicalURI(), constantTimeEqual(), Proof, Validator, NewValidator() (+78 more)

### Community 2 - "time.Time"
Cohesion: 0.07
Nodes (39): redis.Client, isNoScript(), NewRedisLimiter(), miniredis.Miniredis, redis.Client, newTestClock(), newTestLimiter(), TestAllowAdmitsUpToLimitThenRejects() (+31 more)

### Community 3 - "server/webauthn_test.go"
Cohesion: 0.08
Nodes (45): addCookies(), Server, issueSession(), newSessionTestServer(), TestListSessionsDoesNotLeakToken(), TestListSessionsWithCookie(), TestListSessionsWithoutCookieUnauthorized(), TestLogoutReturns204() (+37 more)

### Community 4 - "clientauth_test.go"
Cohesion: 0.14
Nodes (44): audienceMatches(), New(), parseAssertion(), stringClaim(), es256Signer(), form(), newHarness(), rs256Signer() (+36 more)

### Community 5 - "compilerOptions"
Cohesion: 0.04
Nodes (47): compilerOptions, allowJs, allowSyntheticDefaultImports, emitDeclarationOnly, esModuleInterop, forceConsistentCasingInFileNames, incremental, jsx (+39 more)

### Community 6 - "Client"
Cohesion: 0.08
Nodes (32): devDefaultClients(), LoadClients(), testJWKJSON(), TestLoadClientsDevDefault(), TestLoadClientsEmptyArray(), TestLoadClientsFromJSON(), TestLoadClientsInvalidJSON(), TestLoadClientsPrivateKeyJWTRequiresJWKS() (+24 more)

### Community 7 - "context.Context"
Cohesion: 0.11
Nodes (12): context.Context, github.com/google/uuid.UUID, github.com/hatefsystems/identity/apps/identity-api/internal/db.CreateWebauthnCredentialParams, github.com/hatefsystems/identity/apps/identity-api/internal/db.SetWebauthnUserHandleParams, github.com/hatefsystems/identity/apps/identity-api/internal/db.UpdateWebauthnSignCountParams, github.com/hatefsystems/identity/apps/identity-api/internal/db.User, github.com/hatefsystems/identity/apps/identity-api/internal/db.WebauthnCredential, fakeUserStore (+4 more)

### Community 8 - "New"
Cohesion: 0.10
Nodes (34): NewMemoryChallengeStore(), newFixedChallengeStore(), newPendingChallenge(), TestMemoryChallengeStoreImplementsInterface(), TestMemoryChallengeStoreIsolatesChallenges(), TestMemoryChallengeStoreSaveTakeRoundTrip(), TestMemoryChallengeStoreTakeExpired(), TestMemoryChallengeStoreTakeIsAtomic() (+26 more)

### Community 9 - "Service"
Cohesion: 0.10
Nodes (18): dbToCredentials(), signCountToUint32(), TestSignCountToUint32(), isDomainError(), deriveMockBytes(), mockCredentials(), mockUserHandle(), newMockUserAdapter() (+10 more)

### Community 10 - "exclude"
Cohesion: 0.05
Nodes (36): compilerOptions, jsx, lib, outDir, rootDir, tsBuildInfoFile, types, exclude (+28 more)

### Community 11 - "time.Duration"
Cohesion: 0.09
Nodes (11): OTPRecord, lockoutKey(), NewRedisOTPStore(), otpKey(), TestNewRedisOTPStoreRejectsNilClient(), time.Duration, redis.Cmdable, phoneFakeLimiter (+3 more)

### Community 12 - "smsotp/service_test.go"
Cohesion: 0.12
Nodes (28): phoneRateKey(), Config, Service, newFakeLimiter(), newFakeOTPStore(), newFakeUserStore(), newServiceFixture(), TestHashCodeBindsPhone() (+20 more)

### Community 13 - "newTokenTestServer"
Cohesion: 0.19
Nodes (28): dpopTokenProof(), ecdsaKeyFrom(), Server, newDPoPTokenTestServer(), postFormDPoP(), TestTokenEndpointDPoPBindsCnfJKT(), TestTokenEndpointDPoPInvalidProofRejected(), TestTokenEndpointDPoPNonceChallenge() (+20 more)

### Community 14 - "schemas/project.json"
Cohesion: 0.08
Nodes (30): executor, options, executor, options, cache, executor, inputs, options (+22 more)

### Community 15 - "Common Issues"
Cohesion: 0.07
Nodes (29): Application vs Library Detection, Common Issues, Dependency Version Conflicts, Directory Conventions, ESLint Config Handling, ESLint Version Pinning (Critical), Explicit Executor Path Fixups, Frontend tsconfig Base Settings (Critical) (+21 more)

### Community 16 - "MemoryRefreshTokenStore"
Cohesion: 0.13
Nodes (18): HashSecret(), NewMemoryCodeStore(), NewMemoryRefreshTokenStore(), NewSecret(), assertStatus(), mustSave(), TestMemoryCodeStoreConsumeConcurrent(), TestMemoryCodeStoreConsumeSingleUse() (+10 more)

### Community 17 - "Common Issues"
Cohesion: 0.07
Nodes (29): Application vs Library Detection, Common Issues, Dependency Version Conflicts, Directory Conventions, ESLint Config Handling, ESLint Version Pinning (Critical), Explicit Executor Path Fixups, Frontend tsconfig Base Settings (Critical) (+21 more)

### Community 18 - "Common Issues"
Cohesion: 0.07
Nodes (29): Application vs Library Detection, Common Issues, Dependency Version Conflicts, Directory Conventions, ESLint Config Handling, ESLint Version Pinning (Critical), Explicit Executor Path Fixups, Frontend tsconfig Base Settings (Critical) (+21 more)

### Community 19 - "newTestManager"
Cohesion: 0.16
Nodes (26): WithProof(), Manager, newTestManager(), requestWithCookies(), TestManagerAuthenticateClampsIdleToAbsolute(), TestManagerAuthenticateExpired(), TestManagerAuthenticateNoCookie(), TestManagerCookieName() (+18 more)

### Community 20 - ".agents/skills/monitor-ci/scripts/ci-poll-decide.mjs"
Cohesion: 0.10
Nodes (25): args, backoff(), buildOutput(), categorizeTasks(), classify(), envRerunCount, expectedSha, formatMessage() (+17 more)

### Community 21 - "NewMockProvider"
Cohesion: 0.15
Nodes (20): New(), newGCM(), TestNewNilProvider(), Provider, newGCM(), NewMockProvider(), newTestDEK(), newTestKEK() (+12 more)

### Community 22 - "ParsePublicJWK"
Cohesion: 0.18
Nodes (25): JWK, newECDSASigningKey(), newRSASigningKey(), Thumbprint(), PublicKey, kidFor(), parseECPublicJWK(), ParsePublicJWK() (+17 more)

### Community 23 - "SigningKey"
Cohesion: 0.14
Nodes (22): SigningKey, ParsePrivateKeyPEM(), ecPEM(), mustEphemeral(), pemEncode(), rsaPEM(), TestJWKNeverContainsPrivateMaterial(), TestManagerConcurrentAccess() (+14 more)

### Community 24 - ".github/skills/monitor-ci/scripts/ci-poll-decide.mjs"
Cohesion: 0.10
Nodes (25): args, backoff(), buildOutput(), categorizeTasks(), classify(), envRerunCount, expectedSha, formatMessage() (+17 more)

### Community 25 - ".opencode/skills/monitor-ci/scripts/ci-poll-decide.mjs"
Cohesion: 0.10
Nodes (25): args, backoff(), buildOutput(), categorizeTasks(), classify(), envRerunCount, expectedSha, formatMessage() (+17 more)

### Community 26 - "Next.js"
Cohesion: 0.07
Nodes (26): ESLint: Self-Contained `eslint-config-next`, Fix Order — Non-Nx Source (create-next-app), Fix Order — Nx Source (Subdirectory Import), Iteration Log, Mixed Next.js + Vite Coexistence, `next.config.js` Lint Warning, `next-env.d.ts`, Next.js (+18 more)

### Community 27 - "Next.js"
Cohesion: 0.07
Nodes (26): ESLint: Self-Contained `eslint-config-next`, Fix Order — Non-Nx Source (create-next-app), Fix Order — Nx Source (Subdirectory Import), Iteration Log, Mixed Next.js + Vite Coexistence, `next.config.js` Lint Warning, `next-env.d.ts`, Next.js (+18 more)

### Community 28 - "Next.js"
Cohesion: 0.07
Nodes (26): ESLint: Self-Contained `eslint-config-next`, Fix Order — Non-Nx Source (create-next-app), Fix Order — Nx Source (Subdirectory Import), Iteration Log, Mixed Next.js + Vite Coexistence, `next.config.js` Lint Warning, `next-env.d.ts`, Next.js (+18 more)

### Community 29 - "Monitor CI Command"
Cohesion: 0.08
Nodes (25): 2a. Spawn subagent (FETCH_STATUS), 2b. Run decision script, 2c. Process script output, Anti-Patterns, Architecture Overview, Configuration Defaults, Context, Default Behaviors by Status (+17 more)

### Community 30 - "Monitor CI Command"
Cohesion: 0.08
Nodes (25): 2a. Spawn subagent (FETCH_STATUS), 2b. Run decision script, 2c. Process script output, Anti-Patterns, Architecture Overview, Configuration Defaults, Context, Default Behaviors by Status (+17 more)

### Community 31 - "Monitor CI Command"
Cohesion: 0.08
Nodes (25): 2a. Spawn subagent (FETCH_STATUS), 2b. Run decision script, 2c. Process script output, Anti-Patterns, Architecture Overview, Configuration Defaults, Context, Default Behaviors by Status (+17 more)

### Community 32 - "include"
Cohesion: 0.08
Nodes (25): compilerOptions, jsx, lib, outDir, types, extends, include, dom (+17 more)

### Community 33 - "Monitor CI Command"
Cohesion: 0.08
Nodes (25): 2a. Spawn subagent (FETCH_STATUS), 2b. Run decision script, 2c. Process script output, Anti-Patterns, Architecture Overview, Configuration Defaults, Context, Default Behaviors by Status (+17 more)

### Community 34 - "Monitor CI Command"
Cohesion: 0.08
Nodes (25): 2a. Spawn subagent (FETCH_STATUS), 2b. Run decision script, 2c. Process script output, Anti-Patterns, Architecture Overview, Configuration Defaults, Context, Default Behaviors by Status (+17 more)

### Community 35 - "Service"
Cohesion: 0.22
Nodes (14): ClientAuthenticator, Response, Service, newError(), NewService(), splitScopes(), TestSplitScopes(), net/url.Values (+6 more)

### Community 36 - "devDependencies"
Cohesion: 0.08
Nodes (25): autoprefixer, @babel/core, babel-jest, @babel/preset-react, eslint-config-prettier, jest, @nx/eslint-plugin, devDependencies (+17 more)

### Community 37 - "fakeTx"
Cohesion: 0.08
Nodes (13): github.com/jackc/pgx/v5/pgconn.CommandTag, github.com/jackc/pgx/v5/pgconn.StatementDescription, pgx.Batch, pgx.BatchResults, pgx.Conn, pgx.CopyFromSource, pgx.Identifier, pgx.LargeObjects (+5 more)

### Community 38 - "nx.json"
Cohesion: 0.08
Nodes (23): analytics, linter, style, cache, generators, @nx/next, @nx/react, unitTestRunner (+15 more)

### Community 39 - "New"
Cohesion: 0.15
Nodes (15): Config, Server, newTestServer(), testConfig(), TestHealthzEndpoint(), TestReadyzEndpoint(), TestUnknownRouteReturns404(), TestOIDCRoutesAbsentWithoutKeyManager() (+7 more)

### Community 40 - "server/phone_test.go"
Cohesion: 0.16
Nodes (14): Server, newPhoneFakeOTPStore(), setupPhoneTestFixture(), TestPhoneRoutesRequireSession(), TestPhoneSendCodeInvalidPhone(), TestPhoneSendCodeRateLimited(), TestPhoneVerifyEndToEnd(), TestPhoneVerifyWrongCode() (+6 more)

### Community 41 - "include"
Cohesion: 0.09
Nodes (21): compilerOptions, jsx, outDir, types, extends, include, jest, jest.config.cts (+13 more)

### Community 42 - "Hatef Identity Platform - Compliance & Data Governance"
Cohesion: 0.09
Nodes (21): 10. Data Subject Rights, 11. Consent Management, 12. Breach Notification & Incident Response, 13. Records of Processing & Impact Assessments, 14. Roles & Accountability, 15. Vendor / Sub-processor Management, 16. Standards & Certifications Posture, 17. Cross-References (+13 more)

### Community 43 - "cn"
Cohesion: 0.21
Nodes (13): Button, ButtonProps, buttonVariants, Card, CardContent, CardDescription, CardFooter, CardHeader (+5 more)

### Community 44 - "Service"
Cohesion: 0.19
Nodes (17): Service, New(), calculateHOTP(), GenerateCode(), GenerateSecret(), GenerateURI(), parseSecret(), TestGenerateSecret() (+9 more)

### Community 45 - "ParseAuthorizationRequest"
Cohesion: 0.21
Nodes (18): containsScope(), isValidS256Challenge(), newFatalError(), newRedirectableError(), ParseAuthorizationRequest(), RedirectErrorURL(), asAuthErr(), baseQuery() (+10 more)

### Community 46 - "dependencies"
Cohesion: 0.10
Nodes (21): class-variance-authority, clsx, lucide-react, dependencies, class-variance-authority, clsx, lucide-react, next (+13 more)

### Community 47 - "compilerOptions"
Cohesion: 0.10
Nodes (20): hatef-identity-platform, compilerOptions, composite, customConditions, declarationMap, emitDeclarationOnly, importHelpers, isolatedModules (+12 more)

### Community 48 - "Nx Workspace Exploration"
Cohesion: 0.10
Nodes (18): Affected Projects, Affected Projects, "Cannot find configuration for task X:target", Common Exploration Patterns, "How do I build/test/lint project X?", Listing Projects, Listing Projects, Nx Workspace Exploration (+10 more)

### Community 49 - "NewCookieCodec"
Cohesion: 0.17
Nodes (14): NewCookieCodec(), newTestCodec(), TestCookieClearExpires(), TestCookieReadEmptyValue(), TestCookieReadMissing(), TestCookieReadRoundTrip(), TestCookieWriteAttributes(), TestNewCookieCodecAcceptsHostPrefixWithSecure() (+6 more)

### Community 50 - "Nx Workspace Exploration"
Cohesion: 0.10
Nodes (18): Affected Projects, Affected Projects, "Cannot find configuration for task X:target", Common Exploration Patterns, "How do I build/test/lint project X?", Listing Projects, Listing Projects, Nx Workspace Exploration (+10 more)

### Community 51 - "Nx Workspace Exploration"
Cohesion: 0.10
Nodes (18): Affected Projects, Affected Projects, "Cannot find configuration for task X:target", Common Exploration Patterns, "How do I build/test/lint project X?", Listing Projects, Listing Projects, Nx Workspace Exploration (+10 more)

### Community 52 - "Status Handling by Code"
Cohesion: 0.11
Nodes (18): Apply Locally + Enhance Flow, Apply via MCP, cipe_no_tasks, Commit Message Format, Detailed Status Handling & Fix Flows, environment_issue, Environment vs Code Failure Recognition, Fix Action Flows (+10 more)

### Community 53 - "Jest"
Cohesion: 0.11
Nodes (18): CI Atomization, Common Post-Import Issues, Core (always needed), Environment-specific, Fix Order, How `@nx/jest` Works, Jest, Jest Preset (+10 more)

### Community 54 - "Status Handling by Code"
Cohesion: 0.11
Nodes (18): Apply Locally + Enhance Flow, Apply via MCP, cipe_no_tasks, Commit Message Format, Detailed Status Handling & Fix Flows, environment_issue, Environment vs Code Failure Recognition, Fix Action Flows (+10 more)

### Community 55 - "Jest"
Cohesion: 0.11
Nodes (18): CI Atomization, Common Post-Import Issues, Core (always needed), Environment-specific, Fix Order, How `@nx/jest` Works, Jest, Jest Preset (+10 more)

### Community 56 - "Status Handling by Code"
Cohesion: 0.11
Nodes (18): Apply Locally + Enhance Flow, Apply via MCP, cipe_no_tasks, Commit Message Format, Detailed Status Handling & Fix Flows, environment_issue, Environment vs Code Failure Recognition, Fix Action Flows (+10 more)

### Community 57 - "Jest"
Cohesion: 0.11
Nodes (18): CI Atomization, Common Post-Import Issues, Core (always needed), Environment-specific, Fix Order, How `@nx/jest` Works, Jest, Jest Preset (+10 more)

### Community 58 - "newTestService"
Cohesion: 0.33
Nodes (16): authCodeForm(), Service, issueTestCode(), newTestService(), TestAuthorizationCodeBindingChecks(), TestAuthorizationCodeExchangeSuccess(), TestAuthorizationCodeReplayRejected(), TestAuthorizationCodeWrongVerifier() (+8 more)

### Community 59 - "NewRequireSession"
Cohesion: 0.16
Nodes (9): Server, FromContext(), WithSession(), Manager, NewRequireSession(), TestNewRequireSessionNilManager(), net/http.Handler, contextKey (+1 more)

### Community 60 - "Hatef Identity Platform - Architecture Documentation"
Cohesion: 0.11
Nodes (17): 3. Observability & Secret Management, 4. Monorepo Strategy, 5. API Design & Integration, 6. Infrastructure & Deployment, 7. Contribution Guidelines, Coding Standards, Deployment Strategy, Development Workflow (+9 more)

### Community 61 - "Hatef Identity Platform - Data Architecture & Database Schemas"
Cohesion: 0.11
Nodes (17): 1.1.1 Persistence & Deletion Rules for Ledger and Holds, 1.1 Physical Schema Definition (DDL), 1.2 `sqlc` & `pgx` Configurations, 1. PostgreSQL Relational Schema (DDL), 2.1 Cryptographic Implementation Details, 2.2 Cryptographic Blind Indexes for Secure Exact-Match Searches, 2. PII Storage & Application-Layer Encryption, 3.1 Redis Keyspaces & TTL Policies (+9 more)

### Community 62 - "components.json"
Cohesion: 0.11
Nodes (17): aliases, components, hooks, lib, ui, utils, iconLibrary, rsc (+9 more)

### Community 63 - "database/sql.DB"
Cohesion: 0.27
Nodes (14): main(), run(), Down(), NewProvider(), Open(), Reset(), Status(), openTestDB() (+6 more)

### Community 64 - "Load"
Cohesion: 0.19
Nodes (14): getEnv(), getEnvBool(), getEnvDuration(), Load(), LoadSession(), TestAddr(), TestDefaultTimeoutsArePositive(), TestLoadDefaults() (+6 more)

### Community 65 - "buildSMSOTPService"
Cohesion: 0.27
Nodes (13): buildKeyManager(), buildRedisClient(), buildSessionManager(), buildSMSOTPService(), buildTokenService(), buildWebAuthnService(), redis.Client, main() (+5 more)

### Community 66 - "New"
Cohesion: 0.27
Nodes (13): Equal(), New(), normalize(), newTestPepper(), TestComputeDeterministic(), TestComputeDifferentInputs(), TestComputeDigestFormat(), TestComputeNormalization() (+5 more)

### Community 67 - "credentials_test.go"
Cohesion: 0.23
Nodes (14): aaguidFromBytes(), aaguidToBytes(), credentialToCreateParams(), dbToCredential(), TestAAGUIDFromBytesEdgeCases(), TestAAGUIDRoundTrip(), TestCredentialMappingRoundTrip(), TestCredentialToCreateParams() (+6 more)

### Community 68 - "password_test.go"
Cohesion: 0.27
Nodes (13): decode(), Hash(), NeedsRehash(), TestCrossPasswordVerifyFails(), TestHashEncodingFormat(), TestHashUniqueSalt(), TestHashVerifyRoundTrip(), TestNeedsRehash() (+5 more)

### Community 69 - "Verify"
Cohesion: 0.28
Nodes (12): Sign(), signDigest(), testES256Key(), testRS256Key(), TestSignNilKey(), TestSignVerifyRoundTrip(), TestVerifyRejectsMalformed(), TestVerifyRejectsTamperedPayload() (+4 more)

### Community 70 - "newClientCredentialsServer"
Cohesion: 0.45
Nodes (13): ccClaims(), ccForm(), Server, newCCSigner(), newClientCredentialsServer(), stripSig(), TestClientCredentialsDisallowedScopeRejected(), TestClientCredentialsMalformedAssertionRejected() (+5 more)

### Community 71 - "writeJSON"
Cohesion: 0.39
Nodes (4): writeJSON(), Server, net/http.ResponseWriter, healthResponse

### Community 72 - "net/http.HandlerFunc"
Cohesion: 0.28
Nodes (4): Server, Server, Server, net/http.HandlerFunc

### Community 73 - "Steps"
Cohesion: 0.14
Nodes (13): 1. Discover Available Generators, 2. Match Generator to User Request, 3. Get Generator Options, 4. Read Generator Source Code, 5. Examine Existing Patterns, 6. Dry-Run to Verify File Placement, 7. Run the Generator, 8. Modify Generated Code (If Needed) (+5 more)

### Community 74 - "Service"
Cohesion: 0.30
Nodes (10): Limiter, Service, New(), subnetRateKey(), BlindIndexer, Config, Encryptor, OTPStore (+2 more)

### Community 75 - "2.2 Constructing the Client JWT Assertion"
Cohesion: 0.14
Nodes (13): 2.1 Client Authentication Parameters, 2.2 Constructing the Client JWT Assertion, 2. Confidential Clients Integration (`private_key_jwt`), 3.1 SPIFFE/SPIRE Bootstrapping, 3.2 Dynamic mTLS gRPC Connections, 3.3 Passing Metadata & Token Validation API, 3. Internal gRPC Integration (Zero-Trust), Exchange Request: (+5 more)

### Community 76 - "Steps"
Cohesion: 0.14
Nodes (13): 1. Discover Available Generators, 2. Match Generator to User Request, 3. Get Generator Options, 4. Read Generator Source Code, 5. Examine Existing Patterns, 6. Dry-Run to Verify File Placement, 7. Run the Generator, 8. Modify Generated Code (If Needed) (+5 more)

### Community 77 - "Steps"
Cohesion: 0.14
Nodes (13): 1. Discover Available Generators, 2. Match Generator to User Request, 3. Get Generator Options, 4. Read Generator Source Code, 5. Examine Existing Patterns, 6. Dry-Run to Verify File Placement, 7. Run the Generator, 8. Modify Generated Code (If Needed) (+5 more)

### Community 78 - "setupMFATestFixture"
Cohesion: 0.23
Nodes (9): Server, setupMFATestFixture(), TestMFARoutesEndToEnd(), TestMFARoutesRequireSession(), github.com/hatefsystems/identity/apps/identity-api/internal/db.SetMfaTotpSecretParams, mfaFakeStore, mfaTestEncryptor, mfaTestFixture (+1 more)

### Community 79 - "dependencies"
Cohesion: 0.15
Nodes (12): dependencies, @hatef/ui, next, react, react-dom, next, react, react-dom (+4 more)

### Community 80 - "1. External APIs (REST & OIDC)"
Cohesion: 0.15
Nodes (13): 1.1 Standard OIDC/OAuth2 Endpoints, 1.2 Authentication Flow (Frontend API), 1.3 Advanced Security, WebAuthn & Step-up Auth, 1.4 User Profile & Privacy (GDPR), 1.5 Account Verification & Anti-Spam, 1.6 Password Reset & Account Recovery, 1.7 Admin & Moderation API, 1. External APIs (REST & OIDC) (+5 more)

### Community 81 - "Hatef Identity Platform - DevOps & Operational Playbook"
Cohesion: 0.15
Nodes (12): 1.0 MVP Phase: Host-Level Nginx Configuration (Reverse Proxy & TLS Termination), 1.1.1 Security Middlewares Configuration:, 1.1 Traefik Ingress Configuration, 1.2 SPIRE Runtime Environment Agent Deployment, 1. Kubernetes Deployment & Networking, 2.1 ExternalSecret Definition, 2. Secrets Injection & Configuration, 3.1 Core Operational Metrics (+4 more)

### Community 82 - "setupTestService"
Cohesion: 0.27
Nodes (9): Service, newFakeUserStore(), setupTestService(), TestGenerateSetupAlreadyEnabled(), TestGenerateSetupHappyPath(), TestVerifyAndEnableHappyPath(), TestVerifyAndEnableInvalidCode(), TestVerifyCodeAndDisable() (+1 more)

### Community 83 - "command"
Cohesion: 0.21
Nodes (12): executor, options, executor, options, command, cwd, migrate-down, migrate-status (+4 more)

### Community 84 - "Hatef Identity Platform - Disaster Recovery & High Availability"
Cohesion: 0.17
Nodes (11): 1.1 PostgreSQL Patroni-Driven Clustering, 1.2 Redis Sentinel Setup, 1. Database High Availability & Failover, 2.1 KMS Offline Contingency Fallback, 2.2 Master Key Encryption Key (KEK) Rotation Schedule, 2. Key Management Service (KMS) Fallback Protocols, 3.1 Backup Schedules & Specifications, 3.2 Recovery Validation Drills (+3 more)

### Community 85 - "Hatef Identity Platform - Frontend Pages Structure"
Cohesion: 0.17
Nodes (12): 1. Authentication & Public Pages: `(auth)`, 2. SSO Authorization: `/oauth2`, 3. User Dashboard & Privacy Settings: `(dashboard)`, 4. Admin & Moderation Panel: `(admin)`, 5.1 Cookie-Based Session Protection, 5.2 Client-Side Sender-Constrained Tokens (DPoP) & Strict-Nonce CSP, 5.3 UX Step-up Authentication Trigger Flow, 5.4 Account-Harvesting Resistant Login UX & Discoverable Credentials (+4 more)

### Community 86 - "2. STRIDE Threat Analysis Matrix"
Cohesion: 0.17
Nodes (11): 1.1 Critical Assets, 1.2 Trust Boundaries, 1. Security Assets & Boundaries, 2.1 Spoofing (Identity Spoofing), 2.2 Tampering (Data Modification), 2.3 Repudiation (Denying Actions), 2.4 Information Disclosure (Exposing Secrets), 2.5 Denial of Service (DoS) (+3 more)

### Community 87 - "newAuthorizeTestServer"
Cohesion: 0.45
Nodes (10): authorizeQuery(), doAuthorize(), Server, locationURL(), newAuthorizeTestServer(), TestAuthorizeNonRedirectableErrorGoesToErrorPage(), TestAuthorizeRedirectableErrorGoesToClient(), TestAuthorizeRouteAbsentWithoutRegistry() (+2 more)

### Community 88 - "Link Workspace Packages"
Cohesion: 0.20
Nodes (9): bun, Detect Package Manager, Examples, Link Workspace Packages, Notes, npm, pnpm, Workflow (+1 more)

### Community 89 - "LoadOIDC"
Cohesion: 0.33
Nodes (7): OIDCConfig, LoadOIDC(), TestLoadOIDCDevelopmentDefaultsIssuer(), TestLoadOIDCProductionRequiresHTTPSIssuer(), TestLoadOIDCProductionRequiresKeys(), TestLoadOIDCProductionValid(), TestLoadOIDCTrimsTrailingSlash()

### Community 90 - "sqlc-generate"
Cohesion: 0.20
Nodes (10): cache, executor, inputs, options, outputs, sqlc-generate, {projectRoot}/db/migrations/**/*.sql, {projectRoot}/db/queries/**/*.sql (+2 more)

### Community 91 - "Link Workspace Packages"
Cohesion: 0.20
Nodes (9): bun, Detect Package Manager, Examples, Link Workspace Packages, Notes, npm, pnpm, Workflow (+1 more)

### Community 92 - "nx-mcp"
Cohesion: 0.20
Nodes (9): mcp, nx-mcp, command, enabled, type, $schema, mcp, npx (+1 more)

### Community 93 - "Link Workspace Packages"
Cohesion: 0.20
Nodes (9): bun, Detect Package Manager, Examples, Link Workspace Packages, Notes, npm, pnpm, Workflow (+1 more)

### Community 94 - "package.json"
Cohesion: 0.20
Nodes (9): engines, node, npm, name, private, version, workspaces, apps/* (+1 more)

### Community 95 - "Hatef Identity Platform (LDP) - Implementation Roadmap"
Cohesion: 0.20
Nodes (9): Definition of Done (DoD), Hatef Identity Platform (LDP) - Implementation Roadmap, Phase 1: Workspace Setup & Infrastructure Configuration, Phase 2: Database Schemas & Cryptography Engine, Phase 3: OIDC & OAuth 2.1 Protocol Engine (Go Backend), Phase 4: User Authentication & Device Hardening, Phase 5: Privacy (GDPR), Admin Mod, & Cryptographic Logging, Phase 6: gRPC Microservices & Inter-Service Security (+1 more)

### Community 96 - "net/http.Request"
Cohesion: 0.39
Nodes (3): Server, Server, net/http.Request

### Community 97 - "NormalizePhone"
Cohesion: 0.33
Nodes (7): generateCode(), NormalizePhone(), TestGenerateCodeShape(), TestNormalizePhone(), TestNormalizePhoneRejectsInvalid(), TestZeroPad(), zeroPad()

### Community 98 - "ui/package.json"
Cohesion: 0.22
Nodes (8): exports, ./package.json, main, name, nx, name, types, version

### Community 99 - "Hatef Identity Platform (LDP)"
Cohesion: 0.22
Nodes (9): 1. System Overview & Architecture, 2. MVP Resource Optimization Strategy, 3. Repository Directory Structure, 4. Documentation Index, 5. Local Setup & Development (MVP Targeted Stack), 6. Coding Standards & Contribution Policy, Getting Started, Hatef Identity Platform (LDP) (+1 more)

### Community 100 - ".agents/skills/monitor-ci/scripts/ci-state-update.mjs"
Cohesion: 0.50
Nodes (7): args, cycleCheck(), gate(), getArg(), getFlag(), output(), postAction()

### Community 101 - "ESLint"
Cohesion: 0.25
Nodes (7): Duplicate `lint` and `eslint:lint` Targets, ESLint, Flat Config `.cjs` Files Self-Linting, How `@nx/eslint/plugin` Works, Legacy `.eslintrc.*` Configs Linting Generated Files, Mixed ESLint v8 and v9 in One Workspace, `typescript-eslint` Version Conflict With ESLint 9

### Community 102 - ".agents/skills/nx-import/references/TURBOREPO.md"
Cohesion: 0.25
Nodes (7): Check for Root Config Files First, General Cleanup, Key Pitfalls, Merging ESLint Config (Only When Root eslint.config Exists), Merging TypeScript Config (Only When Root tsconfig.base.json Exists), The Config-as-Package Pattern, Turborepo

### Community 103 - "Fix Orders"
Cohesion: 0.25
Nodes (8): Fix Orders, Multiple-Source Imports, Non-Nx Source (additional steps), Non-Nx Source: React Router 7, Non-Nx Source: TanStack Start, Nx Source, Quick Reference: React vs Vue, Quick Reference: Vite-Based React Frameworks

### Community 104 - "identity-api/project.json"
Cohesion: 0.25
Nodes (7): name, projectType, $schema, sourceRoot, tags, lang:go, scope:backend

### Community 105 - "identity-api"
Cohesion: 0.25
Nodes (7): Configuration, Database access (sqlc + pgx), Database migrations (goose), Endpoints, identity-api, Layout, Local development

### Community 106 - "Commands"
Cohesion: 0.25
Nodes (7): CI Monitor Subagent, Commands, FETCH_HEAVY, FETCH_STATUS, FETCH_THROTTLE_INFO, Important, UPDATE_FIX

### Community 107 - "README.md"
Cohesion: 0.25
Nodes (5): 2.1 Identity SAN Validation (gRPC RBAC), 2.2 `IdentityService`, 2. Internal APIs (gRPC), 3. Asynchronous Events (NATS JetStream), Hatef Identity Platform - API Design

### Community 108 - "2. Identity & Security (Privacy-First)"
Cohesion: 0.25
Nodes (8): 2. Identity & Security (Privacy-First), Account Security & Advanced Authentication, Admin Roles & Scopes, Advanced Cryptographic Controls & Data Protection, IdP Architecture & Standard Compliance, Privacy & GDPR Compliance, Role-Based Access Control (RBAC) & Admin Capabilities, The "Zero Trust" Admin Philosophy

### Community 109 - "Commands"
Cohesion: 0.25
Nodes (7): CI Monitor Subagent, Commands, FETCH_HEAVY, FETCH_STATUS, FETCH_THROTTLE_INFO, Important, UPDATE_FIX

### Community 110 - ".github/skills/monitor-ci/scripts/ci-state-update.mjs"
Cohesion: 0.50
Nodes (7): args, cycleCheck(), gate(), getArg(), getFlag(), output(), postAction()

### Community 111 - "ESLint"
Cohesion: 0.25
Nodes (7): Duplicate `lint` and `eslint:lint` Targets, ESLint, Flat Config `.cjs` Files Self-Linting, How `@nx/eslint/plugin` Works, Legacy `.eslintrc.*` Configs Linting Generated Files, Mixed ESLint v8 and v9 in One Workspace, `typescript-eslint` Version Conflict With ESLint 9

### Community 112 - ".github/skills/nx-import/references/TURBOREPO.md"
Cohesion: 0.25
Nodes (7): Check for Root Config Files First, General Cleanup, Key Pitfalls, Merging ESLint Config (Only When Root eslint.config Exists), Merging TypeScript Config (Only When Root tsconfig.base.json Exists), The Config-as-Package Pattern, Turborepo

### Community 113 - "Fix Orders"
Cohesion: 0.25
Nodes (8): Fix Orders, Multiple-Source Imports, Non-Nx Source (additional steps), Non-Nx Source: React Router 7, Non-Nx Source: TanStack Start, Nx Source, Quick Reference: React vs Vue, Quick Reference: Vite-Based React Frameworks

### Community 114 - "Commands"
Cohesion: 0.25
Nodes (7): CI Monitor Subagent, Commands, FETCH_HEAVY, FETCH_STATUS, FETCH_THROTTLE_INFO, Important, UPDATE_FIX

### Community 115 - ".opencode/skills/monitor-ci/scripts/ci-state-update.mjs"
Cohesion: 0.50
Nodes (7): args, cycleCheck(), gate(), getArg(), getFlag(), output(), postAction()

### Community 116 - "ESLint"
Cohesion: 0.25
Nodes (7): Duplicate `lint` and `eslint:lint` Targets, ESLint, Flat Config `.cjs` Files Self-Linting, How `@nx/eslint/plugin` Works, Legacy `.eslintrc.*` Configs Linting Generated Files, Mixed ESLint v8 and v9 in One Workspace, `typescript-eslint` Version Conflict With ESLint 9

### Community 117 - ".opencode/skills/nx-import/references/TURBOREPO.md"
Cohesion: 0.25
Nodes (7): Check for Root Config Files First, General Cleanup, Key Pitfalls, Merging ESLint Config (Only When Root eslint.config Exists), Merging TypeScript Config (Only When Root tsconfig.base.json Exists), The Config-as-Package Pattern, Turborepo

### Community 118 - "Fix Orders"
Cohesion: 0.25
Nodes (8): Fix Orders, Multiple-Source Imports, Non-Nx Source (additional steps), Non-Nx Source: React Router 7, Non-Nx Source: TanStack Start, Nx Source, Quick Reference: React vs Vue, Quick Reference: Vite-Based React Frameworks

### Community 119 - ".agents/skills/nx-import/references/VITE.md"
Cohesion: 0.29
Nodes (6): Iteration Log, React Router 7 — Keep ALL scripts, Redundant npm Scripts After Import, Scenario 6: Multiple non-Nx React apps (CRA, Next.js, React Router 7, TanStack Start, Vite) → TS preset (PASS), Standalone Vite App (`create-vite`), TanStack Start

### Community 120 - "Vite"
Cohesion: 0.29
Nodes (7): Dependency Version Conflicts, Missing TypeScript `types` (Non-Nx Sources), `noEmit` Fix: Vite-Specific Notes, @nx/vite Plugin Install Failure, `@nx/vite/plugin` Typecheck Target, Vite, Vite `resolve.alias` and `__dirname` (Non-Nx Sources)

### Community 121 - "Vue-Specific"
Cohesion: 0.29
Nodes (7): ESLint Plugin Installation Order (Critical), Vue Dependencies, Vue ESLint Config Pattern, `vue-shims.d.ts`, Vue-Specific, `vue-tsc` Auto-Detection, Vue TypeScript Configuration

### Community 122 - "Subnet"
Cohesion: 0.38
Nodes (5): parseAddr(), Subnet(), TestSubnet(), TestSubnetGroupsWholeAllocation(), net/netip.Addr

### Community 123 - "1.2 Demonstrating Proof-of-Possession (DPoP - RFC 9449)"
Cohesion: 0.29
Nodes (7): 1.1 Mandatory PKCE (S256), 1.2.1 Ephemeral Key Generation (Browser), 1.2.2 Generating the DPoP Proof Assertion, 1.2.3 Token Endpoint Authentication Configuration, 1.2 Demonstrating Proof-of-Possession (DPoP - RFC 9449), 1. Public Clients Integration (OAuth 2.1 & OIDC), Flow Sequence:

### Community 124 - "sync.Mutex"
Cohesion: 0.38
Nodes (3): MemoryNonceStore, sync.Mutex, fakeSender

### Community 125 - ".github/skills/nx-import/references/VITE.md"
Cohesion: 0.29
Nodes (6): Iteration Log, React Router 7 — Keep ALL scripts, Redundant npm Scripts After Import, Scenario 6: Multiple non-Nx React apps (CRA, Next.js, React Router 7, TanStack Start, Vite) → TS preset (PASS), Standalone Vite App (`create-vite`), TanStack Start

### Community 126 - "Vite"
Cohesion: 0.29
Nodes (7): Dependency Version Conflicts, Missing TypeScript `types` (Non-Nx Sources), `noEmit` Fix: Vite-Specific Notes, @nx/vite Plugin Install Failure, `@nx/vite/plugin` Typecheck Target, Vite, Vite `resolve.alias` and `__dirname` (Non-Nx Sources)

### Community 127 - "Vue-Specific"
Cohesion: 0.29
Nodes (7): ESLint Plugin Installation Order (Critical), Vue Dependencies, Vue ESLint Config Pattern, `vue-shims.d.ts`, Vue-Specific, `vue-tsc` Auto-Detection, Vue TypeScript Configuration

### Community 128 - "schemas/package.json"
Cohesion: 0.29
Nodes (6): description, name, nx, name, private, version

### Community 129 - "@hatef/schemas"
Cohesion: 0.29
Nodes (6): Commands, @hatef/schemas, Layout, Notes, Tooling (reproducible, no global installs), Windows: `buf format` requires a `diff` binary

### Community 130 - ".opencode/skills/nx-import/references/VITE.md"
Cohesion: 0.29
Nodes (6): Iteration Log, React Router 7 — Keep ALL scripts, Redundant npm Scripts After Import, Scenario 6: Multiple non-Nx React apps (CRA, Next.js, React Router 7, TanStack Start, Vite) → TS preset (PASS), Standalone Vite App (`create-vite`), TanStack Start

### Community 131 - "Vite"
Cohesion: 0.29
Nodes (7): Dependency Version Conflicts, Missing TypeScript `types` (Non-Nx Sources), `noEmit` Fix: Vite-Specific Notes, @nx/vite Plugin Install Failure, `@nx/vite/plugin` Typecheck Target, Vite, Vite `resolve.alias` and `__dirname` (Non-Nx Sources)

### Community 132 - "Vue-Specific"
Cohesion: 0.29
Nodes (7): ESLint Plugin Installation Order (Critical), Vue Dependencies, Vue ESLint Config Pattern, `vue-shims.d.ts`, Vue-Specific, `vue-tsc` Auto-Detection, Vue TypeScript Configuration

### Community 133 - "TanStack Start (Vite-Based)"
Cohesion: 0.33
Nodes (6): Generated and Build Directories, `paths` Aliases, TanStack Start (Vite-Based), Targets, tsconfig Notes, Uncommitted Source Repo

### Community 134 - "React-Specific"
Cohesion: 0.33
Nodes (6): React Dependencies, React ESLint Config, React-Specific, React TypeScript Configuration, React Version Conflicts, `@testing-library/jest-dom` with Vitest

### Community 135 - ".agents/skills/nx-run-tasks/SKILL.md"
Cohesion: 0.33
Nodes (5): Run a single task, Run multiple tasks, Run tasks for affected projects, Understand which tasks can be run, Useful flags

### Community 136 - "NewEphemeralES256"
Cohesion: 0.53
Nodes (5): NewEphemeralES256(), Server, newOIDCTestServer(), TestDiscoveryEndpoint(), TestJWKSEndpoint()

### Community 137 - "TestVerifyPKCE"
Cohesion: 0.47
Nodes (4): isValidVerifier(), challengeFor(), TestVerifyPKCE(), VerifyPKCE()

### Community 138 - "build"
Cohesion: 0.33
Nodes (6): cache, dependsOn, executor, options, build, sqlc-generate

### Community 139 - "targets"
Cohesion: 0.33
Nodes (6): executor, options, targets, sqlc-vet, tidy, executor

### Community 140 - "1. System Architecture"
Cohesion: 0.33
Nodes (6): 1. System Architecture, Asynchronous Operations & Task Queues, High-Level Design, Inter-Service Communication (gRPC) & Zero-Trust Service Identity, Monorepo Benefits for Web/Identity Layer, Network Flow & API Gateway (Ingress)

### Community 141 - "TanStack Start (Vite-Based)"
Cohesion: 0.33
Nodes (6): Generated and Build Directories, `paths` Aliases, TanStack Start (Vite-Based), Targets, tsconfig Notes, Uncommitted Source Repo

### Community 142 - "React-Specific"
Cohesion: 0.33
Nodes (6): React Dependencies, React ESLint Config, React-Specific, React TypeScript Configuration, React Version Conflicts, `@testing-library/jest-dom` with Vitest

### Community 143 - ".github/skills/nx-run-tasks/SKILL.md"
Cohesion: 0.33
Nodes (5): Run a single task, Run multiple tasks, Run tasks for affected projects, Understand which tasks can be run, Useful flags

### Community 144 - "ui/tsconfig.json"
Cohesion: 0.33
Nodes (5): extends, files, include, ../../tsconfig.base.json, references

### Community 145 - "TanStack Start (Vite-Based)"
Cohesion: 0.33
Nodes (6): Generated and Build Directories, `paths` Aliases, TanStack Start (Vite-Based), Targets, tsconfig Notes, Uncommitted Source Repo

### Community 146 - "React-Specific"
Cohesion: 0.33
Nodes (6): React Dependencies, React ESLint Config, React-Specific, React TypeScript Configuration, React Version Conflicts, `@testing-library/jest-dom` with Vitest

### Community 147 - ".opencode/skills/nx-run-tasks/SKILL.md"
Cohesion: 0.33
Nodes (5): Run a single task, Run multiple tasks, Run tasks for affected projects, Understand which tasks can be run, Useful flags

### Community 148 - "tsconfig.json"
Cohesion: 0.33
Nodes (5): compileOnSave, extends, files, ./tsconfig.base.json, references

### Community 149 - "React Router 7 (Vite-Based)"
Cohesion: 0.40
Nodes (5): Build Output, Generated Types Directory, React Router 7 (Vite-Based), Targets, tsconfig Notes

### Community 150 - "server/phone.go"
Cohesion: 0.40
Nodes (4): phoneErrorResponse, phoneSendCodeRequest, phoneStatusResponse, phoneVerifyRequest

### Community 152 - "toWebAuthnCredentialResponse"
Cohesion: 0.50
Nodes (4): toWebAuthnCredentialResponse(), webauthnCredentialResponse, webauthnErrorResponse, webauthnLoginOptionsRequest

### Community 153 - "web/jest.config.js"
Cohesion: 0.40
Nodes (4): config, createJestConfig, jestConfig, nextJest

### Community 154 - "React Router 7 (Vite-Based)"
Cohesion: 0.40
Nodes (5): Build Output, Generated Types Directory, React Router 7 (Vite-Based), Targets, tsconfig Notes

### Community 155 - "React Router 7 (Vite-Based)"
Cohesion: 0.40
Nodes (5): Build Output, Generated Types Directory, React Router 7 (Vite-Based), Targets, tsconfig Notes

### Community 156 - "General Guidelines for working with Nx"
Cohesion: 0.50
Nodes (3): General Guidelines for working with Nx, Scaffolding & Generators, When to use nx_docs

### Community 157 - "Mixed React + Vue"
Cohesion: 0.50
Nodes (4): ESLint — Three-Tier Config, Mixed React + Vue, tsconfig `jsx` — Per-Project Only, Typecheck — Auto-Detects Framework

### Community 158 - "mfa.go"
Cohesion: 0.50
Nodes (3): mfaErrorResponse, mfaStatusResponse, mfaVerifyRequest

### Community 159 - "lint"
Cohesion: 0.50
Nodes (4): cache, executor, options, lint

### Community 160 - "test"
Cohesion: 0.50
Nodes (4): test, cache, executor, options

### Community 161 - "Mixed React + Vue"
Cohesion: 0.50
Nodes (4): ESLint — Three-Tier Config, Mixed React + Vue, tsconfig `jsx` — Per-Project Only, Typecheck — Auto-Detects Framework

### Community 162 - "Mixed React + Vue"
Cohesion: 0.50
Nodes (4): ESLint — Three-Tier Config, Mixed React + Vue, tsconfig `jsx` — Per-Project Only, Typecheck — Auto-Detects Framework

### Community 163 - "options"
Cohesion: 0.67
Nodes (3): executor, options, migrate-up

### Community 164 - "options"
Cohesion: 0.67
Nodes (3): executor, options, serve

## Knowledge Gaps
- **1125 isolated node(s):** `args`, `waitMode`, `prevCipeUrl`, `expectedSha`, `prevStatus` (+1120 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **49 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `openTestDB()` connect `database/sql.DB` to `testing.T`, `context.Context`?**
  _High betweenness centrality (0.012) - this node is a cross-community bridge._
- **Why does `Client` connect `Client` to `clientauth_test.go`, `ParseAuthorizationRequest`, `ParsePublicJWK`?**
  _High betweenness centrality (0.011) - this node is a cross-community bridge._
- **Why does `resetToClean()` connect `database/sql.DB` to `testing.T`, `context.Context`?**
  _High betweenness centrality (0.009) - this node is a cross-community bridge._
- **Are the 3 inferred relationships involving `newFixture()` (e.g. with `newFixedChallengeStore()` and `New()`) actually correct?**
  _`newFixture()` has 3 INFERRED edges - model-reasoned connections that need verification._
- **What connects `args`, `waitMode`, `prevCipeUrl` to the rest of the system?**
  _1125 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `testing.T` be split into smaller, more focused modules?**
  _Cohesion score 0.051037527593818986 - nodes in this community are weakly interconnected._
- **Should `dpop_test.go` be split into smaller, more focused modules?**
  _Cohesion score 0.062066063538817585 - nodes in this community are weakly interconnected._