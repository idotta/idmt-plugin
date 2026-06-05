# Phase 3 — Middleware + Config Hardening

Pipeline order, URL validation, rate limit, strong defaults, DP key ring enforce. Depend Phase 0-2.

---

## Project overview

IDMT (Identity MultiTenant) Plugin — reusable NuGet lib for ASP.NET Core. Multi-tenant identity mgmt. Built on Finbuckle.MultiTenant + ASP.NET Core Identity. Per-tenant cookie isolation, hybrid cookie/bearer auth, vertical slice arch. ErrorOr for results, FluentValidation for requests. Target: net10.0.

Key services/concepts:
- **Finbuckle.MultiTenant** resolve tenants via strategies (Header, Route, Claim, BasePath).
- `IdmtUser` global (post-Phase-1); `IdmtRole` per-tenant; `SysRole` global enum on `IdmtUser`.
- `TenantAccess` map users to tenants w/ `IsActive` + optional `ExpiresAt`.
- Per-tenant cookie isolation: each tenant gets separate auth cookie name.
- `ValidateBearerTokenTenantMiddleware` ensures bearer token tenant match request tenant.
- Two EF contexts: `IdmtDbContext` (multi-tenant app data) + `IdmtTenantStoreDbContext` (tenant metadata).
- Pre-configured auth policies: `RequireSysAdmin`, `RequireSysUser`, `RequireTenantManager`, `CookieOnly`, `BearerOnly`.
- Token revocation via `ITokenRevocationService` (now enforced on access-token validation post-Phase-2).
- Bearer auth use `AddBearerToken` w/ DataProtection opaque tokens.

Build/test: `dotnet build Idmt.slnx`, `dotnet test Idmt.slnx`, `dotnet format Idmt.slnx --verify-no-changes`.

---

## Architectural context (carried from Phase 1)

**Canonical `IdmtUser` + `TenantAccess` + global `SysRole` column.**

`IdmtUser` global (not per-tenant). One canonical `Id` per human. Revocation keyed by `(userId, tenantId)` coherent across tenants. `SysRole` non-nullable enum (`None | SysAdmin | SysSupport`), emit as role claim at login when `!= None`. Sys users reach any tenant w/o `TenantAccess` row; normal cross-tenant access still need `TenantAccess` + per-tenant `IdentityUserRole`.

Phase 2 wired `OnTokenValidated` to call `IsTokenRevokedAsync` for access tokens, implemented refresh-token rotation w/ reuse detection, made `Logout` fail-closed on null tenant.

---

## Phase 3 scope

Seven finding clusters — middleware pipeline order, config validation, rate limit, defaults, Data Protection:

1. **H3** — Middleware order: tenant-validation runs before `UseAuthorization`.
2. **H4** — `ClientUrl` validate HTTPS + absolute + root path at startup.
3. **H2** — Rate limit on by default w/ distinct per-endpoint policies.
4. **H1 + N4** — `DiscoverTenants` gated, always rate-limited, fixed-shape response, kill response-length oracle.
5. **N6** — `ForgotPassword` per-email throttle.
6. **M9, M10, M11, M12, M13** — config validator throw on `SameSite=None` rewrites; no default email stub; tenant identifier char-class validation; stronger password defaults; shorter token/cookie defaults.
7. **N8** — Data Protection key ring persistence required at startup in non-dev envs.

Order in phase: H3 first (pipeline), then config-validator tighten (H4, M9, M10, M11, M12, M13, N8), then rate limit (H2, N6, H1, N4). H3 safer to ship isolated; config tighten may surface consumer misconfigs needing coordinated rollout.

---

## Finding H3 (architectural smell — ship for correctness) — Middleware order

### File
`Idmt.Plugin/Extensions/ApplicationBuilderExtensions.cs:50-59`

### Current pipeline
`UseMultiTenant → UseAuthentication → UseAuthorization → ValidateBearerTokenTenantMiddleware → CurrentUserMiddleware`

### Problem
Authz policies evaluate principal *before* tenant validation. Current policies (`ServiceCollectionExtensions.cs:426-438`) pure `RequireRole(...)`, don't read tenant-scoped services, so no exploit today. But consumer adding custom authz handler reading `ICurrentUserService` or other tenant-scoped services would see mismatched state. Defensive fix.

### Fix
Reorder to: `UseMultiTenant → UseAuthentication → ValidateBearerTokenTenantMiddleware → CurrentUserMiddleware → UseAuthorization`.

Tenant validation + current-user population happen *between* authentication and authorization so all authz handlers see coherent tenant-scoped view.

### Files to modify
- `Idmt.Plugin/Extensions/ApplicationBuilderExtensions.cs`

### Verification
- Integration test: custom authz handler registered by test harness reads resolved tenant; cross-tenant bearer token rejected *before* handler runs.
- Regression: all existing auth/authz tests pass.

### Dependencies
None in Phase 3; ship first.

---

## Finding H4 (High) — `ClientUrl` validation

### Files
- `Idmt.Plugin/Services/IdmtLinkGenerator.cs:91-108`
- `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs:39-45`

### Problem
Validator only checks `ClientUrl` non-empty. Not required absolute, HTTPS, or rooted at `/`. Password-reset + confirm-email links embed tokens in URL query string; misconfigured or poisoned `ClientUrl` send token to attacker-controlled host.

### Fix
In `IdmtOptionsValidator`, require:
- `Uri.IsWellFormedUriString(url, UriKind.Absolute)` — must be absolute.
- `scheme == Uri.UriSchemeHttps` — must be HTTPS (allow `http` only when new explicit option `Application.AllowInsecureClientUrl = true` set).
- `uri.AbsolutePath == "/"` — no path segments (client routes appended by `IdmtLinkGenerator`).
- Host must be non-empty.

Fail fast at startup w/ actionable error message.

### Files to modify
- `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs`
- `Idmt.Plugin/Configuration/IdmtOptions.cs` — add `Application.AllowInsecureClientUrl` flag (default false).

### Verification
- Startup test: `ClientUrl = "http://evil.com/path"` → options validation throws.
- Startup test: `ClientUrl = "https://app.example.com/"` → passes.
- Startup test: `ClientUrl = "not-a-url"` → fails.
- Startup test: `ClientUrl = "http://localhost:5000/"` + `AllowInsecureClientUrl = true` → passes (dev scenario).

### Dependencies
None; ship w/ other config-validator tightening.

---

## Finding H2 (High) — Rate limiting disabled by default

### Files
- `Idmt.Plugin/Configuration/IdmtOptions.cs:310` (`RateLimitingOptions.Enabled = false`)
- `Idmt.Plugin/Features/AuthEndpoints.cs:30-33`

### Problem
Account lockout (5 attempts / 5 min, per-user) does not protect against:
- Credential stuffing across *different* accounts.
- `/forgot-password` spam (mailstorm + token churn).
- `/resend-confirmation-email` spam.
- `/discover-tenants` enumeration.

Default `Enabled = false` means consumers get zero rate limit out of box.

### Fix
1. Flip default: `RateLimitingOptions.Enabled = true`. Consumers fronting app w/ own limiter (Cloudflare, reverse proxy) can explicitly opt out.
2. Define distinct per-endpoint policies:
   - `/auth/login`: 20 requests / minute / IP.
   - `/auth/token` (refresh): 60 requests / minute / IP (legit clients refresh often).
   - `/auth/forgot-password`: 5 requests / minute / IP (plus N6 per-email throttle).
   - `/auth/discover-tenants`: 10 requests / minute / IP (always-on, see H1/N4).
   - `/auth/resend-confirmation-email`: 5 requests / minute / IP.
3. Policies apply regardless of `Enabled` flag when endpoint security-sensitive (discover-tenants, forgot-password, resend-confirmation). "Enabled = false" is consumer override for login/refresh policies only; discovery-class endpoints always enforce limit.

### Files to modify
- `Idmt.Plugin/Configuration/IdmtOptions.cs` — flip default; define per-endpoint policy knobs.
- `Idmt.Plugin/Features/AuthEndpoints.cs` — attach rate-limiter policies to each endpoint.
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — register rate-limiter services.

### Verification
- Integration test: 25 login attempts in 60s → last 5 return 429.
- Integration test: 6 forgot-password calls in 60s → last call returns 429 (regardless of `Enabled` flag).
- Contract test: `RateLimitingOptions.Enabled` default = `true`.

### Dependencies
None in Phase 3.

---

## Finding H1 + N4 (High) — `DiscoverTenants` enumeration oracle

### Files
- `Idmt.Plugin/Features/Auth/DiscoverTenants.cs:42-88,99-122`
- `Idmt.Plugin/Configuration/IdmtOptions.cs:310` (RateLimiting)
- `Idmt.Plugin/Features/AuthEndpoints.cs:30-33`

### Problem
Unauthenticated `POST /auth/discover-tenants` returns list of `(Identifier, Name)` tuples for known emails, empty array for unknown. Response shape (Content-Length) is oracle: attackers enumerate valid emails + tenant membership by comparing payload sizes, bypass timing-only protections.

### Fix
1. Gate endpoint behind explicit `Auth.AllowTenantDiscovery` option (default **false**). Consumers needing feature opt in.
2. When enabled, always attach per-endpoint rate limiter regardless of global `RateLimiting.Enabled`.
3. Equalize response timing: perform same work regardless of email known (dummy query, constant-time response construction).
4. Equalize response shape: return fixed-shape payload for both known + unknown emails. Options:
   - Return opaque blob (e.g., HMAC-signed nonce), deliver real tenant list via email to address (out-of-band, no oracle).
   - Return fixed-length array padded w/ placeholder entries, client matches against claim at login.
   - Return consistent "request queued, check your email" 202 response every call.
   Prefer email-delivery: strongest guarantee, matches how account-recovery flows typically work.
5. If endpoint returns tuples at all, return only tenant IDs (not names) — names leak org info.

### Files to modify
- `Idmt.Plugin/Features/Auth/DiscoverTenants.cs` — full rewrite of handler + response shape.
- `Idmt.Plugin/Configuration/IdmtOptions.cs` — add `Auth.AllowTenantDiscovery` (default false).
- `Idmt.Plugin/Features/AuthEndpoints.cs` — conditional mapping based on feature flag; always attach limiter.
- `Idmt.Plugin/Services/IdmtEmailSender.cs` — new email template for "tenant discovery result" (if email-delivery path).

### Verification
- Integration test: feature flag off → endpoint returns 404 / not mapped.
- Integration test: feature flag on + unknown email + known email → identical HTTP status, identical Content-Length, timing within ±10 ms.
- Integration test: 11 calls in 60s → at least one 429 (always-on limiter).
- Integration test: known email → email dispatched w/ tenant list.

### Dependencies
H2 rate-limiter infrastructure must exist (may ship together).

---

## Finding N6 (High) — `ForgotPassword` per-email throttle

### File
`Idmt.Plugin/Features/Auth/ForgotPassword.cs:42-58`

### Problem
Every unauthenticated `/auth/forgot-password` call triggers Identity token generation + email dispatch. Global per-IP rate limit (H2) not prevent attacker rotating IPs to flood reset emails for specific target — burying legit reset messages, exhausting mail-provider quotas.

### Fix
Add per-email sliding-window throttle on top of global per-IP limiter. Suggested default: **1 request / 5 minutes / email**. Store in existing `IdmtDbContext` (new table `EmailThrottle` w/ `EmailNormalized`, `LastAttemptUtc`, `AttemptCount`) or use distributed cache abstraction consumers can configure (IMemoryCache for single-instance; IDistributedCache for scale-out).

Respond identically whether throttled or not (don't leak throttle state to attackers).

### Files to modify
- `Idmt.Plugin/Features/Auth/ForgotPassword.cs` — consult throttle before work.
- New: `Idmt.Plugin/Services/IEmailThrottleService.cs` + default impl.
- `Idmt.Plugin/Configuration/IdmtOptions.cs` — `Auth.ForgotPasswordThrottle.Window = TimeSpan.FromMinutes(5)`, `.MaxPerWindow = 1`.
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — register throttle service.

### Verification
- Integration test: 2 forgot-password calls for same email within 5 min → second call returns 200 (uniform) but **no email dispatched**.
- Integration test: 2 calls for different emails within 5 min → both dispatched.

### Dependencies
None; ship parallel to H2.

Also handles **H8** in passing: replace hand-rolled 3-char mask in `ForgotPassword.cs:62-64` w/ `PiiMasker.MaskEmail(request.Email)` while editing.

---

## Finding M9 (Medium) — Cookie `SameSite=None` silently rewritten

### File
`Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:333-335`

### Problem
Consumer configures `SameSite=None` for legit cross-site flows. Current code silently rewrites to `Strict`. Cross-site flow then breaks invisibly.

### Fix
In `IdmtOptionsValidator`, throw at startup w/ actionable message when `SameSite=None` configured: explain CSRF implications, require `SecurePolicy=Always`, reject if those not set together. Never mutate consumer config.

### Files to modify
- `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs`
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — remove silent rewrite.

### Verification
- Startup test: `SameSite=None, SecurePolicy=Always` → passes (explicit opt-in).
- Startup test: `SameSite=None, SecurePolicy=SameAsRequest` → throws w/ explanatory message.

---

## Finding M10 (Medium) — `IdmtEmailSender` stub registered by default

### Files
- `Idmt.Plugin/Services/IdmtEmailSender.cs`
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:452`

### Problem
Default stub email sender registered if consumer doesn't provide one. Warning logged at startup but app runs. Password-reset + email-confirm emails silently vanish in prod.

### Fix
- Do not register default `IEmailSender<IdmtUser>`.
- Throw at startup if no registration exists.
- Provide opt-in `services.UseStubEmailSender()` for dev/test, clearly marked non-production.

### Files to modify
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — remove default; add startup validation.
- `Idmt.Plugin/Services/IdmtEmailSender.cs` — keep as class consumers opt into, rename to e.g., `StubEmailSender`.
- `Idmt.Plugin/Extensions/*` — add `UseStubEmailSender()` extension method.

### Verification
- Startup test: no `IEmailSender<IdmtUser>` registered → `AddIdmt<T>()` throws.
- Startup test: `services.UseStubEmailSender()` → passes, warning logged.

Also handles part of **M8**: route all email logging through `PiiMasker.MaskEmail`.

---

## Finding M11 (Medium) — `IdmtTenantInfo.Identifier` character-class validation

### Files
- `Idmt.Plugin/Models/IdmtTenantInfo.cs:17-20`
- `Idmt.Plugin/Validation/CreateTenantRequestValidator.cs`
- `Idmt.Plugin/Services/IdmtLinkGenerator.cs:26-65`

### Problem
Identifier only length-validated (≥ 3). Values like `foo/admin/../` could inject path segments into emitted confirm/reset URLs via `IdmtLinkGenerator`.

### Fix
Enforce `^[a-z0-9-]+$` (or consumer-configurable regex w/ safe default) in:
- `IdmtTenantInfo` constructor.
- `CreateTenantRequestValidator`.
- Reject URL-unsafe identifiers both at create time + whenever tenant resolved from request header.

### Files to modify
- `Idmt.Plugin/Models/IdmtTenantInfo.cs`
- `Idmt.Plugin/Validation/CreateTenantRequestValidator.cs`

### Verification
- Unit test: `IdmtTenantInfo.Create("bad/identifier")` throws.
- Unit test: `CreateTenantRequestValidator` rejects `"FOO"`, `"foo_bar"`, `"foo/bar"`, `""`.
- Integration test: `POST /admin/tenants` w/ invalid identifier → 400.

---

## Finding M12 (Medium) — Password-policy defaults

### File
`Idmt.Plugin/Configuration/IdmtOptions.cs:148-153`

### Current defaults
- `RequiredLength = 8`
- Lowercase + uppercase + digit required; symbol not required.

### Problem
Meets OWASP ASVS L1 but falls below NIST SP 800-63B (prefers ≥ 12 chars) and below typical enterprise defaults.

### Fix
- Raise `RequiredLength` default to **12**.
- Keep existing character-class requirements; `RequireNonAlphanumeric = true` optional — NIST prefers length over class mandates, industry practice still requires symbol. Leave default length-first w/ classes as-is unless team prefers stricter.
- Expose `MaxFailedAccessAttempts` (currently hard-coded 5 at `ServiceCollectionExtensions.cs:298-300`) and `DefaultLockoutTimeSpan` (currently hard-coded 5 min) via `IdmtOptions.Password` or new `IdmtOptions.Lockout` section.

### Files to modify
- `Idmt.Plugin/Configuration/IdmtOptions.cs`
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs`

### Verification
- Contract test: default `RequiredLength` = 12.
- Contract test: consumer can override `MaxFailedAccessAttempts` and `DefaultLockoutTimeSpan`.

---

## Finding M13 (Medium) — Cookie + bearer expiration defaults amplify C1

### File
`Idmt.Plugin/Configuration/IdmtOptions.cs:198-199, 215`

### Current defaults
- Cookie `ExpireTimeSpan = 14 days, SlidingExpiration = true`.
- `BearerTokenExpiration = 60 min`.

### Problem
Before Phase 2 fixes, stolen bearer token valid 60 min post-revocation; stolen cookie up to 14 days. Phase 2 fixes make bearer revocation real-time, but generous defaults amplify impact of any future regression.

### Fix
- Cookie `ExpireTimeSpan = 7 days` default.
- `BearerTokenExpiration = 5 min` default. W/ Phase 2's refresh-rotation + revocation-on-validate, short-lived access tokens harmless (UX preserved by fast refresh); stolen tokens have tiny window.
- `RefreshTokenExpiration` can stay 14 days (rotation + reuse detection make long refresh windows safe).

### Files to modify
- `Idmt.Plugin/Configuration/IdmtOptions.cs`

### Verification
- Contract test: defaults match new values.
- Integration test: protected endpoint accepts token within 5 min, rejects after (expiry).
- Integration test: refresh flow within 5-min window succeeds; access token rolls correctly.

---

## Finding N8 (High) — Data Protection key ring not required

### File
`Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` (documentation + optional validation)

### Problem
Bearer tokens + cookies protected w/ DataProtection. Without persisted key ring, host restart rotates keys → all pre-rotation tokens fail to unprotect. Combined w/ M2 (pre-Phase-2 IssuedUtc missing), revocation fallback path drifts after rotation, making revocation checks compare inconsistent timestamps. Post-Phase-2 this specific drift gone (M2 fixed), but fundamental issue remains: scaled-out deployments rolling-restart individual instances get inconsistent key rings unless persisted shared keys configured.

### Fix
1. Document requirement clearly in `AddIdmt<T>()` XML docs.
2. At startup in non-Development envs, check whether `IDataProtectionProvider` has key-ring repository persisting to known-non-ephemeral backing store. Non-trivial to introspect reliably; simplest approach:
   - Require consumer to call `services.AddDataProtection().PersistKeysToX(...).SetApplicationName(...)` before `AddIdmt<T>`.
   - In `AddIdmt`, record flag saying "DataProtection configured". If flag absent at validation time (non-Development), throw.
   - Provide helper `services.AddIdmtDataProtectionDefault(configureKeyRing)` making happy path explicit.
3. In Development, allow default in-memory key ring w/ warning.

### Files to modify
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — validate DP config at startup.
- `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs` — non-dev requirement.
- Documentation: `CLAUDE.md` + XML docs on `AddIdmt`.

### Verification
- Startup test: `Production` env + no key-ring config → throws.
- Startup test: `Development` + no key-ring → warning logged, startup proceeds.
- Startup test: `Production` + explicit key-ring → passes.

---

## Phase 3 implementation order

1. **H3** — middleware reorder (one-line change). Safe, ship first.
2. **H4, M9, M10, M11, M12, M13, N8** — config-validator tighten + default adjustments. Batch into one PR; expect consumer rollout coordination b/c defaults change.
3. **H2 + N6 + H1 + N4** — rate-limit infra + per-endpoint policies + discovery-endpoint fix. Single PR: H2 lays rails; N6 + H1/N4 plug into rails.

---

## Files to modify (summary)

- `Idmt.Plugin/Extensions/ApplicationBuilderExtensions.cs` — pipeline reorder (H3).
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — remove default email stub (M10); remove SameSite rewrite (M9); register rate limiter (H2); validate DP config (N8); expose lockout options (M12).
- `Idmt.Plugin/Configuration/IdmtOptions.cs` — defaults for password, token expiry, rate limit, discovery feature flag, `AllowInsecureClientUrl`; lockout options (M12, M13, H1/N4, H2, H4).
- `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs` — URL validation (H4); SameSite validation (M9); DP validation (N8).
- `Idmt.Plugin/Models/IdmtTenantInfo.cs` — identifier regex (M11).
- `Idmt.Plugin/Validation/CreateTenantRequestValidator.cs` — identifier validator (M11).
- `Idmt.Plugin/Features/AuthEndpoints.cs` — rate-limiter policies per endpoint (H2); conditional discovery mapping (H1).
- `Idmt.Plugin/Features/Auth/DiscoverTenants.cs` — fixed-shape response, email delivery (H1, N4).
- `Idmt.Plugin/Features/Auth/ForgotPassword.cs` — per-email throttle (N6) + `PiiMasker` swap (H8).
- `Idmt.Plugin/Services/IdmtEmailSender.cs` — rename / split into `StubEmailSender` (M10).
- `Idmt.Plugin/Services/IEmailThrottleService.cs` — new service (N6).
- EF migration: new `EmailThrottle` table if persistent store chosen.

---

## Verification (phase-wide)

- All unit/integration tests under each finding pass.
- Regression: all existing auth/authz integration tests still pass after pipeline reorder.
- `dotnet test Idmt.slnx` passes.
- `dotnet format Idmt.slnx --verify-no-changes` passes.
- Build w/ warnings-as-errors passes.

---

## Phase 3 done-criteria

- Pipeline order: `UseMultiTenant → UseAuthentication → ValidateBearerTokenTenantMiddleware → CurrentUserMiddleware → UseAuthorization`.
- `ClientUrl` rejected at startup if not absolute HTTPS w/ `Path == "/"` (or explicit `AllowInsecureClientUrl` flag).
- Rate limit on by default; per-endpoint policies enforced; discovery + forgot-password + resend-confirmation endpoints always rate-limited.
- `DiscoverTenants` gated by feature flag, fixed-shape response, email-delivery mode.
- `ForgotPassword` per-email throttle enforced; PII mask consistent.
- No default stub `IEmailSender`; opt-in only.
- Tenant identifier char-class validated.
- Stronger password, cookie, bearer, lockout defaults.
- Non-dev startup requires persisted DP key ring.
- Full test suite + format + warnings-as-errors pass.

Phase 4 may begin when all above satisfied.