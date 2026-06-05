# IDMT Plugin — Security Findings & Remediation Plan (Revised)

## Context

Security audit of IDMT (Identity MultiTenant) ASP.NET Core plugin at `/home/iuri/code/idmt-plugin`. Three review agents (security-auditor, feature-dev:code-reviewer, architect-reviewer) produced initial findings; fourth (architect-critic) attacked consolidation. Doc reflects critic pass: findings downgraded/rejected with evidence, new blockers added, remediation order corrected, foundational architectural decision locked in.

Scope: authentication (cookie + bearer), authorization policies, multi-tenancy isolation, identity flows (register/confirm/reset), admin CRUD, middleware ordering, token revocation, config defaults, PII logging, rate limiting, data model coherence.

**Overall posture**: solid fundamentals (per-tenant cookie naming, SameSite=Strict, centralized ErrorOr, options validator, scheme policy selector), but **per-tenant shadow-user data model** root of several coherence bugs (password rotation, stamp invalidation, revocation keying). Access-token revocation structurally incomplete; admin authorization conflates SysSupport with SysAdmin; ambient tenant-context mutation leaks across async boundaries.

---

## Architectural decision (foundation for all other fixes)

**Canonical `IdmtUser` + `TenantAccess` + global `SysRole` column.**

Current code stores one `IdmtUser` row per tenant (shadow rows created by `GrantTenantAccess.cs:117-133`, copying `PasswordHash` and `LockoutEnd`). Model makes password rotation, security-stamp invalidation, lockout propagation, token revocation keying incoherent across tenants (see new blockers N1, N2). Primary use case for `GrantTenantAccess`: SysUsers hop into any tenant; secondary: normal user with multiple tenant memberships. Canonical model serves both without cloning.

### Target schema

```
IdmtUser (global — drop IsMultiTenant)
  Id, Email, NormalizedEmail, PasswordHash, SecurityStamp,
  LockoutEnd, EmailConfirmed, IsActive, ...
  SysRole : SysRoleKind   // non-null enum: None | SysAdmin | SysSupport   <-- NEW
                          // default = None (stored as int)

IdmtRole (per-tenant, IsMultiTenant — unchanged)
  Id, Name, TenantId
  Populated with TenantAdmin, TenantUser, or consumer-defined roles.
  (Drop pre-seeded SysAdmin/SysSupport rows; they move to IdmtUser.SysRole.)

IdentityUserRole<Guid> (per-tenant, IsMultiTenant — unchanged)
  UserId -> IdmtUser.Id, RoleId -> IdmtRole.Id, TenantId (Finbuckle shadow)

TenantAccess (per-tenant — unchanged)
  UserId, TenantId, IsActive, ExpiresAt
```

### Flow impact

| Flow | Before | After |
|---|---|---|
| SysUser into tenant B | `GrantTenantAccess` clones user, copies hash, compensation window | Set `IdmtUser.SysRole = SysAdmin`. No clone, no `TenantAccess` row required. Works in every tenant immediately. |
| Normal user granted role in tenant B | `TenantAccess` + `IdentityUserRole` per tenant | Unchanged. |
| Sys + tenant role combo | Clone + role assign in shadow | `SysRole` set + per-tenant `IdentityUserRole` row. Factory emits both claims. |
| Password rotation | Only updates tenant-A hash | One hash, coherent. |
| Security-stamp invalidation | Per-tenant only | One stamp, coherent. |
| Token revocation by `(userId, tenantId)` | Wrong `userId` for shadow rows | One canonical `userId`; per-tenant revoke still valid. |
| Email change | Per-tenant | One place. Document as intentional. |

### Claim assembly (`IdmtUserClaimsPrincipalFactory.cs:26`)

```csharp
var roles = await userManager.GetRolesAsync(user);   // per-tenant (Finbuckle-filtered) — unchanged
foreach (var role in roles)
    identity.AddClaim(new Claim(ClaimTypes.Role, role));
if (user.SysRole != SysRoleKind.None)
    identity.AddClaim(new Claim(ClaimTypes.Role, user.SysRole.ToString()));
```

### Finbuckle integration

`IdmtUser` entity drops `.IsMultiTenant()` in `IdmtDbContext.cs`. Relocate `IdmtUser` DbSet ownership: either (a) keep in `IdmtDbContext` with no tenant filter applied to that entity only, or (b) move to `IdmtTenantStoreDbContext` (global store). Option (a) less invasive — one `modelBuilder.Entity<IdmtUser>()` adjustment — keeps Identity's UserStore resolver pointed at single context.

`UserManager.FindByEmailAsync` / `FindByIdAsync` resolve globally. `GetRolesAsync` still filters per-tenant via `IdentityUserRole` multi-tenancy.

### Migration (existing deployments)

Offline script:
1. Group existing `IdmtUser` rows by `NormalizedEmail`. Pick canonical `Id` (oldest row).
2. Rewrite `TenantAccess.UserId`, `IdentityUserRole.UserId`, `RevokedToken.UserId`, audit rows to canonical id.
3. Merge `SysRole` from any tenant row where user was `SysAdmin`/`SysSupport` → set on canonical row. All other rows default to `SysRoleKind.None`.
4. Drop duplicate `IdmtUser` rows.
5. Force password reset for all users (hashes may have diverged across shadows).

Document as breaking change. Bump major.

### Blast-radius note

Canonical model means compromise of user's canonical hash grants access to every tenant they're in. Current shadow model *appears* to bound this but actually shares hash via `GrantTenantAccess.cs:117-133`, so canonical strictly better: rotation and stamp invalidation now actually work. Document explicitly.

---

## Critical

### C1. Access tokens never checked against revocation store
- Files: `Idmt.Plugin/Middleware/ValidateBearerTokenTenantMiddleware.cs`, `Idmt.Plugin/Services/TokenRevocationService.cs`, `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:370-384` (`BearerTokenEvents`)
- `IsTokenRevokedAsync` called only inside `RefreshToken.HandleAsync:74`. No middleware, auth event, or policy checks revocation for plain access-token requests. After logout/password-reset/revoke-tenant-access, previously-issued bearer access token keeps working until expiration.
- Attack: stolen bearer survives logout/password reset up to `BearerTokenExpiration` (60 min default).
- Fix: wire `BearerTokenEvents.OnTokenValidated` to read principal `NameIdentifier` + tenant + ticket `IssuedUtc` and call `IsTokenRevokedAsync`; fail ticket on hit. Cache recent revocations with short TTL (~30 s) to bound DB load. Middleware alternative acceptable but must run between `UseAuthentication` and `UseAuthorization`.
- **Must ship together with M2 (IssuedUtc set explicitly).** C1 relies on `IssuedUtc`; if unset, revocation check fails soft.

### C2. Admin endpoints guarded by `RequireSysUser` instead of `RequireSysAdmin`
- Files: `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:426-432`, `Idmt.Plugin/Features/AdminEndpoints.cs:14`, `Features/Admin/DeleteTenant.cs:74`, `CreateTenant.cs`, `GrantTenantAccess.cs:239`, `RevokeTenantAccess.cs:116`, `GetAllTenants.cs:91`, `GetUserTenants.cs:102`
- `RequireSysAdminPolicy` defined but never referenced. `RequireSysUserPolicy = SysAdmin OR SysSupport`. SysSupport can create/delete tenants and grant themselves tenant access.
- Attack: SysSupport → `GrantTenantAccess(userId=self, tenantIdentifier=any)` → arbitrary tenant access. Full escalation.
- Fix: tenant lifecycle (create/delete) and grant/revoke must require `RequireSysAdminPolicy`. Listing may stay on `RequireSysUser`. Add self-grant guard in `GrantTenantAccess`: reject when `request.UserId == currentUserService.UserId`.

### C4. `GrantTenantAccess` copies source user's `PasswordHash` verbatim (subsumed by canonical-user migration)
- File: `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs:117-133`
- `CreateAsync(targetUser)` without password arg stores copied hash directly. Stamp regenerated but hash shared. Root cause of stamp/hash drift (see N1).
- Fix: **delete shadow-user creation branch entirely.** Under canonical model, `GrantTenantAccess` only writes `TenantAccess` row + optional `IdentityUserRole` for canonical user. No `IdmtUser` creation.

### C7. `UpdateUserInfo` email change + `ResetPassword` auto-confirm → account takeover chain
- Files: `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs:86-104`, `Features/Auth/ResetPassword.cs:52-56`
- `UpdateUserInfo` generates own change-email token inline and immediately calls `ChangeEmailAsync` — no out-of-band confirmation of new address. Then `ResetPassword` sets `user.EmailConfirmed = true` silently after successful reset.
- Attack: attacker with temp session → `PUT /manage/info` with `NewEmail` (attacker's address) → attacker calls `ForgotPassword` on new email → resets password → `EmailConfirmed` flipped to `true`. Account rebound, no victim-side confirmation.
- Fix: change-email requires out-of-band confirmation link on new address. New address staged (not committed to `Email`) until confirmation link opened. Remove silent `EmailConfirmed = true` from `ResetPassword`.

### N1 (new). Split-identity renders revocation and stamp rotation incoherent across tenants
- Evidence: `GrantTenantAccess.cs:117-133` produces tenant-B shadow with fresh `Id` and fresh `SecurityStamp`. `TokenRevocationService.RevokeUserTokensAsync(userId, tenantId)` at `TokenRevocationService.cs:16` stores revocations keyed on passed-in `userId`. Callers that pass tenant-A's `userId` never revoke tenant-B sessions (tenant-B shadow has different id). `RevokeTenantAccess.cs:67-80` precisely this bug: revoke by caller's `userId`, then flip `IsActive` on *different* row.
- Also: `UpdateSecurityStampAsync` mutates tenant-A row only. Sessions in tenant B survive.
- Attack: admin "revokes" user X in tenant A after suspected compromise. Attacker keeps using tenant-B bearer token for 60 min. Password rotation in A also doesn't propagate.
- Fix: resolved by canonical migration. Single `IdmtUser.Id` → one revocation key, one stamp. C4's "don't copy hash" would not fix this; C4 necessary but not sufficient.

### N2 (new). `TenantOperationService` mutates ambient `IMultiTenantContext` without restore; outer request reads wrong tenant
- File: `Idmt.Plugin/Services/TenantOperationService.cs:33`
- Resolves `IMultiTenantContextSetter` from child scope and writes to it. `IMultiTenantContextAccessor` in Finbuckle backed by `AsyncLocal<T>`; writes via child-scope setter mutate ambient flow. On return, outer `DbContext`, `UserManager`, `ICurrentUserService`, any audit writer see tenant B, not outer request's tenant.
- `GrantTenantAccess.cs:181` already uses compensating re-entrant call — symptom of this confusion.
- Attack vector: any handler using `ExecuteInTenantScopeAsync` mid-request then writing data after delegate lands those writes under wrong tenant. Currently no handler does this, but latent cross-tenant write-corruption bug one `git commit` away.
- Fix: capture `previous = accessor.MultiTenantContext` on entry; `try { setter.MultiTenantContext = target; await operation(provider); } finally { setter.MultiTenantContext = previous; }`. Must block C4, C7, anything else routing through service. Upgraded from H6 to Critical.

### N3 (new). Partial-failure window in `GrantTenantAccess`
- File: `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs:106-214`
- Order of writes: tenant-B user created and committed inside `ExecuteInTenantScopeAsync` at ~line 152; outer `dbContext.SaveChangesAsync` for `TenantAccess` at line 171. Between these two points, if request cancelled or outer `SaveChanges` fails, tenant-B user already persisted and can authenticate without `TenantAccess` row (depending how tenant-access validation applied — see `TenantAccessService.cs:42-60`). Compensation (line 181+) best-effort; `LogCritical` fires if compensation throws.
- Fix: under canonical model window evaporates (no user creation — only `TenantAccess` row insert). Retain single-transaction invariant: all writes in `GrantTenantAccess` succeed or none. No compensating actions.

---

## Demoted / reclassified (formerly Critical)

### C3 → Informational gap (not exploitable as stated)
- Files: `Idmt.Plugin/Features/Auth/ConfirmEmail.cs:21,32-57`, `Features/Auth/ResetPassword.cs:21,32-66`
- Original claim: reset token from tenant A replayable against tenant B shadow user.
- Evidence against: `IdmtUser.cs:11,13` initializers give every new row fresh `Id` (Guid v7) and fresh `SecurityStamp`. Shadow row in `GrantTenantAccess.cs:117-133` is `new IdmtUser { ... }` — no `Id` or `SecurityStamp` copy. Identity's `DataProtectorTokenProvider` binds token to `userId + stamp + purpose`. Tenant-B shadow has different `Id` AND different `SecurityStamp` → token fails validation in tenant B.
- Real issue: body-supplied `TenantIdentifier` still decouples token handling from request's tenant strategy; invalidates "resolve tenant from request context" invariant and creates regression trap if anyone ever copies `Id`/`SecurityStamp`.
- Fix: remove `TenantIdentifier` from request records; resolve from context (header/claim/route). **Downgraded from Critical to hygiene gap** — ship alongside canonical migration cleanup.

### C5 → Defensive hardening (not exploitable bypass)
- `RefreshToken.cs:62-67` already returns `Unauthorized` on null tenant before reaching revocation check at line 74. `tenantId is not null` at line 72 dead defense.
- Fix: remove dead guard; revocation check unconditional. Hygiene change only.

### C6 → Fail-closed hygiene (narrow reach)
- `Logout.cs:69-79` silent-success branch reachable only under cookie auth with null tenant context (bearer path rejected by `ValidateBearerTokenTenantMiddleware.cs:45-54`; cookies per-tenant-named, so cookie implies tenant). Attack surface minimal — user logs out without refresh-token revocation, but they had no refresh token if they used cookie.
- Fix: return `IdmtErrors.Auth.Unauthorized` instead of 204. Never succeed logout that did not revoke. **Downgraded to Medium.**

### H3 → Architectural smell (not exploitable)
- Current policies at `ServiceCollectionExtensions.cs:426-438` pure `RequireRole(...)`. None reads tenant-scoped services. No consumer authorization handler registered that would hit mismatched state.
- Fix: reorder middleware for correctness regardless (move `ValidateBearerTokenTenantMiddleware` + `CurrentUserMiddleware` between `UseAuthentication` and `UseAuthorization`), but impact defensive.

---

## High

### H1. `DiscoverTenants` unauthenticated + rate limiting off → enumeration oracle
- Files: `Idmt.Plugin/Features/Auth/DiscoverTenants.cs:42-88,99-122`, `Features/AuthEndpoints.cs:30-33`
- Fix: gate behind explicit `Auth.AllowTenantDiscovery` option (default false). When enabled, attach rate limiter regardless of global `RateLimiting.Enabled`. Equalize response timing AND response-length (fixed-shape placeholder payload — see N4). Consider returning only tenant IDs, not names; consider delivering list via email to address.

### H2. Rate limiting disabled by default
- Files: `Idmt.Plugin/Configuration/IdmtOptions.cs:310`, `Features/AuthEndpoints.cs:30-33`
- Account lockout (5/5m per-user) does not cover credential stuffing across accounts, `/forgot-password` spam, `/resend-confirmation-email` spam, `/discover-tenants` enumeration.
- Fix: default `RateLimitingOptions.Enabled = true`. Apply distinct policies for `/auth/login`, `/auth/token`, `/auth/forgot-password`, `/auth/discover-tenants`, `/auth/resend-confirmation-email`.

### H4. `ClientUrl` not validated for scheme/host → open redirect + token exfil
- Files: `Idmt.Plugin/Services/IdmtLinkGenerator.cs:91-108`, `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs:39-45`
- Fix: in validator, require `Uri.IsWellFormedUriString(url, UriKind.Absolute)` + `scheme == UriSchemeHttps` (allow `http` only via explicit `Application.AllowInsecureClientUrl = true`). Reject paths other than `/`.

### H5. `UpdateUserInfo` transaction boundary is fake
- File: `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs:87-115`
- `UserManager.ChangeEmailAsync` calls own `SaveChangesAsync` internally; outer `BeginTransactionAsync` wrapping it does not provide atomicity. Later step failure + `RollbackAsync` leaves email change persisted.
- Fix: remove false guarantee. Serialize email change as last step after all other mutations; treat as non-atomic explicitly.

### H7. `GrantTenantAccess` / `RevokeTenantAccess` non-normalized lookups
- Files: `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs:113,187`, `RevokeTenantAccess.cs:80`
- Under canonical migration, tenant-B-user lookup by `(Email, UserName)` goes away; any remaining case-sensitive comparisons should move to `NormalizedEmail` / `NormalizedUserName`.
- Fix: use `FindByEmailAsync` and assert identity via `Id` equality — never raw `Email == ...`.

### H8. `ForgotPassword` hand-rolled email mask
- File: `Idmt.Plugin/Features/Auth/ForgotPassword.cs:62-64`
- Fix: replace inline masker with `PiiMasker.MaskEmail(request.Email)`.

### N4 (new). `DiscoverTenants` response-length oracle
- File: `Idmt.Plugin/Features/Auth/DiscoverTenants.cs`
- Even with rate limiting, response shape oracle: empty array for unknown email, populated array for known. Content-Length differs.
- Fix: always return fixed-shape placeholder payload (e.g., consistent array length with deterministic masking, or opaque blob). Or deliver tenant list out-of-band via email only.

### N5 (new). No refresh-token rotation
- File: `Idmt.Plugin/Features/Auth/RefreshToken.cs:41-81`
- Refresh call returns new access token but does not issue new refresh token nor invalidate presented one. Stolen refresh reusable for full `RefreshTokenExpiration` window.
- Fix: on refresh, issue new refresh token, revoke old one (store its `IssuedUtc` in revocation list keyed by `(userId, tenantId)` or token-id). Must precede C1 — C1 without rotation half the fix.

### N6 (new). `ForgotPassword` no per-email throttle
- File: `Idmt.Plugin/Features/Auth/ForgotPassword.cs:42-58`
- Every unauthenticated call triggers Identity token generation + email send. No per-email throttle. Attackers flood reset mail, drown real users' reset messages.
- Fix: per-email sliding window (e.g., 1 request / 5 min / email). Separate from global endpoint rate limit.

### N7 (new). Audit-log writes couple durability to audit correctness
- Files: `Idmt.Plugin/Persistence/IdmtDbContext.cs:159-229`
- Audits written inside same `SaveChangesAsync` transaction as business data. Malformed audit builder fails business write; L1 "swallowed on failure" then detaches all audit entries and business write proceeds with zero audit. Either way, audit correctness and business-data durability coupled in wrong direction.
- Fix: audits go to separate transaction or append-only outbox. Per-entry try/catch at build time; on failure, record `AuditEntry { Success = false, Error = ... }` rather than dropping. For security-critical tables (`IdmtUser`, `TenantAccess`, `RevokedToken`), rethrow on audit failure — do not allow business write without audit row.
- **Upgraded from L1 to High.**

### N8 (new). Data Protection key ring unpersisted → bearer revocation incoherence after key rotation
- File: documentation gap; `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs`
- Bearer tokens use Data Protection. Without persisted key ring, host restart rotates keys; `refreshTokenProtector.Unprotect` at `RefreshToken.cs:44` fails for all pre-rotation tokens → 401. Combined with M2 (missing `IssuedUtc`), fallback `issuedAt = expiresUtc - RefreshTokenExpiration` drifts after key rotation because new tokens get new `expiresUtc` baselines, making revocation checks compare inconsistent timestamps.
- Fix: require consumer call `services.AddDataProtection().PersistKeysToX(...)` — throw at startup if no key ring configured for non-development environments. Couple with M2.
- **Upgraded from L8 to High.**

---

## Medium

### M1. Login timing oracle — no dummy hash on null user
- File: `Idmt.Plugin/Features/Auth/Login.cs:89-101,207-220`
- Fix: `userManager.PasswordHasher.VerifyHashedPassword(new IdmtUser(), DummyHash, request.Password)` on null branch. Mirror in `TokenLoginHandler`.

### M2. Refresh-token `IssuedUtc` unset → revocation check drifts
- File: `Idmt.Plugin/Features/Auth/RefreshToken.cs:70-77`, `Features/Auth/Login.cs:290-297`
- Fix: set `IssuedUtc = timeProvider.GetUtcNow()` explicitly on auth and refresh properties in `TokenLoginHandler`. **Ship with C1 and N5.**

### M3. `is_active` claim stamped at login — not re-evaluated for active sessions
- Files: `Idmt.Plugin/Services/IdmtUserClaimsPrincipalFactory.cs:26`, `Services/CurrentUserService.cs:34`
- Fix: in `UpdateUser`, when `IsActive` flips to false, call `userManager.UpdateSecurityStampAsync(appUser)` AND `tokenRevocationService.RevokeUserTokensAsync(...)`. Under canonical model, revocation covers all tenants in one call.

### M4. Handler lookups by email instead of `NameIdentifier`
- Files: `Idmt.Plugin/Features/Manage/GetUserInfo.cs:35-44`, `UpdateUserInfo.cs:47-53`
- Fix: switch to `FindByIdAsync(FindFirstValue(NameIdentifier))`. Validate security stamp post-lookup.

### M5. `UpdateUser` / `UnregisterUser` do not block self-target or peer-rank destruction
- Files: `Idmt.Plugin/Features/Manage/UpdateUser.cs:31-56`, `Manage/UnregisterUser.cs:31-56`, `Services/TenantAccessService.cs:42-60`
- Fix: reject `userId == currentUserService.UserId` on destructive actions. TenantAdmin-on-TenantAdmin in same tenant requires "danger" flag or double-sign.

### M6. Admin endpoints rely on group-level authorization only
- File: `Idmt.Plugin/Features/Admin/CreateTenant.cs:132-159` (and `GetAllTenants`, `GetUserTenants`, `GrantTenantAccess`, `RevokeTenantAccess`)
- Fix: add explicit `.RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)` on each endpoint for defense-in-depth.

### M7. `ResendConfirmationEmail` enumeration via email-dispatch side-channel
- File: `Idmt.Plugin/Features/Auth/ResendConfirmationEmail.cs:39-67`
- Fix: enqueue email send asynchronously so response timing uniform. Rate-limit by default (H2).

### M8. PII masker inconsistent — Identity error descriptions logged unmasked
- Files: `Idmt.Plugin/Services/PiiMasker.cs:11-15`, `Features/Manage/RegisterUser.cs:92,100`, `Manage/UpdateUserInfo.cs:74,91`, `Features/Admin/GrantTenantAccess.cs:196`, `Services/IdmtEmailSender.cs:11,17,23`
- Fix: log only `IdentityError.Code`, not `Description`, where inputs can echo. Route all email logging through `PiiMasker.MaskEmail`.

### M9. Cookie `SameSite=None` silently downgraded to `Strict`
- File: `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:333-335`
- Fix: throw at startup in `IdmtOptionsValidator` with helpful message. Don't mutate.

### M10. `IdmtEmailSender` stub registered by default
- Files: `Idmt.Plugin/Services/IdmtEmailSender.cs`, `Extensions/ServiceCollectionExtensions.cs:452`
- Fix: do not register default. Throw at startup if `IEmailSender<IdmtUser>` missing. Optional `UseStubEmailSender()` for dev.

### M11. `IdmtTenantInfo.Identifier` not character-class validated
- Files: `Idmt.Plugin/Models/IdmtTenantInfo.cs:17-20`, `Validation/CreateTenantRequestValidator.cs`, `Services/IdmtLinkGenerator.cs:26-65`
- Fix: enforce `^[a-z0-9-]+$` in constructor and validator.

### M12. Password-policy defaults: 8-char, no symbol
- File: `Idmt.Plugin/Configuration/IdmtOptions.cs:148-153`
- Fix: raise `RequiredLength` default to 12. Expose `MaxFailedAccessAttempts` and `DefaultLockoutTimeSpan` via `IdmtOptions` (hardcoded at `ServiceCollectionExtensions.cs:298-300`).

### M13. 14-day sliding cookie + 60-min access token amplifies C1
- File: `Idmt.Plugin/Configuration/IdmtOptions.cs:198-199,215`
- Fix: default `ExpireTimeSpan` to 7 days; default `BearerTokenExpiration` to 5 min. Refresh rotation (N5) + revocation check (C1) make safe.

### N9 (new). `SameSite=Strict` not sole CSRF defense
- File: `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:328-335`
- Safari (pre-2024 builds) and extension-initiated requests bypass `SameSite=Strict` in edge cases. Plan relies on it as CSRF defense.
- Fix: add `IAntiforgery` as defense-in-depth for cookie flows, OR explicitly document plugin as "cookie auth is browser-only, same-origin" and validate `Origin`/`Referer` on state-changing cookie requests.

### C6 (demoted). `Logout` silent success on null tenant (cookie path)
- See reclassification above. Return `IdmtErrors.Auth.Unauthorized` instead of 204.

---

## Low / Informational

### L2. No request-body size/length caps
- All request records — FluentValidation covers format, not length.
- Fix: `.MaximumLength(256)` or similar on every string input. Document Kestrel body-size limit recommendation.

### L3. `ConfirmEmail` GET endpoint triggers state change on link-preview fetch
- File: `Idmt.Plugin/Features/Auth/ConfirmEmail.cs:104-137`
- Fix: keep `EmailConfirmationMode.ClientForm` as default. Document `ServerConfirm` risk in XML docs.

### L4. Revoked-token cleanup 1-hour startup delay
- File: `Idmt.Plugin/Services/TokenRevocationCleanupService.cs:14-20`
- Fix: run one cleanup pass immediately then enter loop.

### L5. `CleanupExpiredAsync` revocation check uses `<` not `<=`
- File: `Idmt.Plugin/Services/TokenRevocationService.cs:73`
- Design documented; informational only.

### L6. `ApiPrefix` lacks validation on `CreateTenant`'s Created response
- File: `Idmt.Plugin/Features/Admin/CreateTenant.cs:155`
- Fix: validate `ApiPrefix` as relative path.

### L7. `customizeAuthentication` / `customizeAuthorization` can regress defaults
- File: `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:404,440`
- Fix: document customizers as additive-only. Consider additive-only hooks.

### L9. Health endpoint exposes exception
- File: `Idmt.Plugin/Features/Health/BasicHealthCheck.cs:34-39`
- Fix: scrub stack trace in production.

### L10. CLAUDE.md mismatch: roles described as "global", code per-tenant
- File: `Idmt.Plugin/Persistence/IdmtDbContext.cs:99-102` applies `IsMultiTenant()` to `IdmtRole`.
- Fix: update CLAUDE.md to match canonical-user migration (roles still per-tenant; only `IdmtUser` becomes global). Clarify `SysRole` column global.

---

## Reclassified findings

- **C3** → downgraded to hygiene gap.
- **C5** → defensive hardening only.
- **C6** → Medium (fail-closed).
- **H3** → architectural smell; fix for correctness.
- **H6** → upgraded to N2 (Critical).
- **L1** → upgraded to N7 (High).
- **L8** → upgraded to N8 (High).

---

## Missing controls (entirely absent)

1. Access-token-level revocation enforcement (C1).
2. Refresh-token rotation (N5).
3. Anti-forgery defense-in-depth (N9).
4. Audit log integrity — same DB, no hash chain, no append-only guarantee.
5. Data Protection key ring persistence (N8).
6. CAPTCHA / proof-of-work on unauthenticated auth endpoints.
7. IP allowlist / MFA / step-up for admin endpoints.
8. Session inventory — no "list my active sessions / revoke single device" capability.
9. Individual-session revocation granularity — `RevokeUserTokensAsync` per-user, invalidates all sessions. Under canonical model now coherent, but still lacks per-device targeting.
10. Per-tenant encryption boundary — all tenants share one DB, one DP key ring. Any bug disabling multi-tenant filtering leaks everything.

---

## Recommended remediation order

Phase gates: A must ship before B.

**Phase 0 — Foundation (blocks everything)**
1. **N2** — `TenantOperationService` try/finally context restore. Latent cross-tenant write corruption; blocks C4, C7, any handler using `ExecuteInTenantScopeAsync`.
2. **C2** — switch admin policies to `RequireSysAdmin`. Add self-grant guard in `GrantTenantAccess`. One hour; blocks privilege escalation.

**Phase 1 — Canonical identity migration**
3. **Architectural decision implementation**:
   - Drop `IsMultiTenant()` on `IdmtUser`.
   - Add `SysRole` enum column to `IdmtUser`.
   - Migration script for existing deployments (see architectural section).
   - Update `IdmtUserClaimsPrincipalFactory` to emit `SysRole` claim.
   - Force password reset for migrated users.
4. **C4 / N1 / N3** — rewrite `GrantTenantAccess` to only write `TenantAccess` + optional `IdentityUserRole` for canonical user. Delete shadow-user creation. Fix `GrantTenantAccess` / `RevokeTenantAccess` normalized lookups (H7).
5. **C7** — out-of-band email-change confirmation; remove silent `EmailConfirmed=true` from `ResetPassword`.
6. **C3 (demoted)** — drop `TenantIdentifier` from `ConfirmEmail`/`ResetPassword` bodies.

**Phase 2 — Bearer-token coherence**
7. **M2** — set `IssuedUtc` explicitly. Prerequisite for C1 correctness.
8. **N5** — refresh-token rotation. Revoke presented refresh on use; issue fresh.
9. **C1** — wire `BearerTokenEvents.OnTokenValidated` to call `IsTokenRevokedAsync`.
10. **C5, C6** — remove dead null-tenant guards; fail closed on null-tenant logout.

**Phase 3 — Middleware + config hardening**
11. **H3** — move `ValidateBearerTokenTenantMiddleware` + `CurrentUserMiddleware` between `UseAuthentication` and `UseAuthorization`.
12. **H4** — validate `ClientUrl` HTTPS absolute + `Path == "/"`.
13. **H2** — default `RateLimiting.Enabled = true`; distinct policies per auth endpoint.
14. **H1 / N4** — gate `DiscoverTenants`; always-on rate limiter; fixed-shape payload.
15. **N6** — per-email throttle on `ForgotPassword`.
16. **M9, M10, M11, M12, M13** — config validation, remove default email stub, validate tenant identifier, stronger defaults.
17. **N8** — require persisted DP key ring at startup.

**Phase 4 — Hygiene**
18. **H5** — remove fake transaction boundary in `UpdateUserInfo`.
19. **H8** — `PiiMasker` in `ForgotPassword`.
20. **M1** — login timing oracle dummy hash.
21. **M3** — propagate deactivation via stamp + revocation.
22. **M4** — handler lookups by `NameIdentifier`.
23. **M5** — self-target / peer-rank guards.
24. **M6** — endpoint-level `RequireAuthorization` defense-in-depth.
25. **M7** — `ResendConfirmationEmail` async dispatch.
26. **M8** — Identity error logging sanitized.
27. **N7** — audit log separated from business-data transaction; rethrow on audit failure for security-critical tables.
28. **N9** — antiforgery / `Origin` validation for cookie flows.
29. Lows as hygiene pass.

---

## Critical files to modify

- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs`
- `Idmt.Plugin/Extensions/ApplicationBuilderExtensions.cs`
- `Idmt.Plugin/Configuration/IdmtOptions.cs`
- `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs`
- `Idmt.Plugin/Middleware/ValidateBearerTokenTenantMiddleware.cs`
- `Idmt.Plugin/Models/IdmtUser.cs` (+ new `SysRole` column)
- `Idmt.Plugin/Features/Auth/Login.cs`
- `Idmt.Plugin/Features/Auth/Logout.cs`
- `Idmt.Plugin/Features/Auth/RefreshToken.cs`
- `Idmt.Plugin/Features/Auth/ResetPassword.cs`
- `Idmt.Plugin/Features/Auth/ConfirmEmail.cs`
- `Idmt.Plugin/Features/Auth/ForgotPassword.cs`
- `Idmt.Plugin/Features/Auth/DiscoverTenants.cs`
- `Idmt.Plugin/Features/Auth/ResendConfirmationEmail.cs`
- `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs`
- `Idmt.Plugin/Features/Manage/UpdateUser.cs`
- `Idmt.Plugin/Features/Manage/UnregisterUser.cs`
- `Idmt.Plugin/Features/Manage/GetUserInfo.cs`
- `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs` (rewritten)
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs`
- `Idmt.Plugin/Features/Admin/CreateTenant.cs`
- `Idmt.Plugin/Features/Admin/DeleteTenant.cs`
- `Idmt.Plugin/Features/Admin/GetAllTenants.cs`
- `Idmt.Plugin/Features/Admin/GetUserTenants.cs`
- `Idmt.Plugin/Services/TenantOperationService.cs`
- `Idmt.Plugin/Services/TokenRevocationService.cs`
- `Idmt.Plugin/Services/IdmtEmailSender.cs`
- `Idmt.Plugin/Services/IdmtLinkGenerator.cs`
- `Idmt.Plugin/Services/IdmtUserClaimsPrincipalFactory.cs`
- `Idmt.Plugin/Persistence/IdmtDbContext.cs`
- `Idmt.Plugin/Features/AuthEndpoints.cs`, `ManageEndpoints.cs`, `AdminEndpoints.cs`
- `CLAUDE.md` (update data model description)
- New: EF migration + data migration script for shadow → canonical.

---

## Verification plan

Beyond happy-path assertions, critic surfaced bypass vectors not covered by simple endpoint tests. Add:

1. **C1 access-token revocation**
   - Mock time, issue bearer, logout, call protected endpoint → expect 401.
   - Concurrent logout + protected-endpoint-call race: verify `DbUpdateException` branch at `TokenRevocationService.cs:43` handled without silent pass.
   - Clock-skew test: revoke at T, token `IssuedUtc = T - 1ms`, verify revoked (exercises L5 `<` boundary).
2. **C2 SysAdmin enforcement** — SysSupport → `POST /admin/tenants`, `POST /admin/tenant-access/grant`, etc. → expect 403 each.
3. **C3 tenant-identifier replay** — seed canonical `alice@corp.com` with `TenantAccess` to A and B. Generate reset token in A, POST `/auth/reset-password` with tenant resolved from header = B. **Expect success** (same canonical user, one stamp). Then assert fix removes body-supplied `TenantIdentifier`. Cross-tenant reset now intended consequence of canonical model (one password) — document explicitly.
4. **C4 / N1 / N3** — `GrantTenantAccess` creates zero `IdmtUser` rows; only `TenantAccess` and optional `IdentityUserRole`. Assert atomic: kill outer DB between inner context execution and `SaveChanges` → no partial state.
5. **C5 / C6** — missing tenant header → 401, not 204/200.
6. **C7 email takeover** — attempt `ChangeEmailAsync`, assert new email staged but `Email` column unchanged; only confirmation link commits. `ForgotPassword` against staged (unconfirmed) email → reject.
7. **N2 context restore** — call `ExecuteInTenantScopeAsync` that throws, assert outer request's `IMultiTenantContextAccessor.MultiTenantContext` equals pre-call value.
8. **N5 refresh rotation** — present same refresh token twice → second call 401.
9. **H1 / H2 / N6 rate limiting** — 20 logins in 60s → 429; 3 forgot-password for same email in 5 min → 429.
10. **N4 response-length oracle** — `DiscoverTenants` for known and unknown email → identical Content-Length.
11. **H3 middleware ordering** — cross-tenant bearer token against tenant-B route → 401 before any authorization policy evaluates (hook observed via test logger).
12. **H4 `ClientUrl`** — startup with `ClientUrl=http://evil.com/foo` → options validation error.
13. **H5 transaction** — `UpdateUserInfo` with email change first + password change second, forced failure on password change → email already committed (document non-atomicity in test assertion).
14. **N7 audit coupling** — inject audit builder that throws for security-critical table write → business write rejected.
15. **N8 DP key ring** — startup without key ring in `Production` environment → error.
16. **Mixed auth with cross-tenant claim** — cookie for tenant A + request against tenant-B route → rejected (covers `ValidateBearerTokenTenantMiddleware` cookie path).
17. **Canonical migration sanity** — after migration, all duplicate `IdmtUser` rows gone; every `TenantAccess.UserId` resolves to extant canonical user; `SysRole` claim emitted correctly at login for sys users.
18. Run full suite: `dotnet test Idmt.slnx`, `dotnet format Idmt.slnx --verify-no-changes`, build with warnings-as-errors.

Follow-up: dedicated `Idmt.SecurityTests` project exercising above as scenarios.