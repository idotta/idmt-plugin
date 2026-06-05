# Phase 4 — Hygiene

Cleanup, smaller Mediums, Lows, plus two new High findings not structural (N7 audit coupling, N9 CSRF defense-in-depth). Depend on Phases 0-3.

---

## Project overview

IDMT (Identity MultiTenant) Plugin — reusable NuGet library for ASP.NET Core. Multi-tenant identity management. Built on Finbuckle.MultiTenant + ASP.NET Core Identity. Per-tenant cookie isolation, hybrid cookie/bearer auth, vertical slice architecture. ErrorOr for results, FluentValidation for requests. Target: net10.0.

Key services + concepts:
- **Finbuckle.MultiTenant** resolve tenants via configurable strategies (Header, Route, Claim, BasePath).
- `IdmtUser` global (post-Phase-1); `IdmtRole` per-tenant; `SysRole` global enum on `IdmtUser`.
- `TenantAccess` map users to tenants with `IsActive` + optional `ExpiresAt`.
- Per-tenant cookie isolation: each tenant get separate auth cookie name.
- `ValidateBearerTokenTenantMiddleware` run between authentication + authorization (post-Phase-3).
- Two EF contexts: `IdmtDbContext` (multi-tenant app data) + `IdmtTenantStoreDbContext` (tenant metadata).
- Pre-configured auth policies: `RequireSysAdmin`, `RequireSysUser`, `RequireTenantManager`, `CookieOnly`, `BearerOnly`.
- Token revocation via `ITokenRevocationService`; access-token validation consult revocation (post-Phase-2).
- Bearer auth use `AddBearerToken` with DataProtection-based opaque tokens. Refresh tokens rotate per use.
- Rate limiting on by default with per-endpoint policies; tenant-discovery endpoint gated behind explicit feature flag (post-Phase-3).

Build/test: `dotnet build Idmt.slnx`, `dotnet test Idmt.slnx`, `dotnet format Idmt.slnx --verify-no-changes`.

---

## Architectural context (carried from Phase 1)

**Canonical `IdmtUser` + `TenantAccess` + global `SysRole` column.**

`IdmtUser` global (not per-tenant). One canonical `Id` per human. Revocation keyed by `(userId, tenantId)` coherent across tenants. `SysRole` non-nullable enum (`None | SysAdmin | SysSupport`) emit as role claim at login when `!= None`. Sys users reach any tenant without `TenantAccess` row; normal cross-tenant access still need `TenantAccess` + per-tenant `IdentityUserRole`.

---

## Phase 4 scope

Mostly mediums + lows plus two stragglers (N7, N9):

- **H5** — Fake transaction boundary in `UpdateUserInfo`.
- **M1** — Login timing oracle (no dummy hash on null user).
- **M3** — `is_active` claim staleness; propagate deactivation via stamp update + revocation.
- **M4** — Handler lookups by `NameIdentifier` (canonical `Id`) instead of email.
- **M5** — Self-target / peer-rank guards on destructive user-management actions.
- **M6** — Endpoint-level `RequireAuthorization` defense-in-depth (mostly covered by Phase 0 C2 pass; finalize here).
- **M7** — `ResendConfirmationEmail` async email dispatch to kill side-channel timing oracle.
- **M8** — Sanitize Identity error descriptions in logs; consistent `PiiMasker` use.
- **N7** — Decouple audit log writes from business-data transaction; rethrow on audit failure for security-critical tables.
- **N9** — Antiforgery / `Origin` validation as CSRF defense-in-depth on cookie flows.
- Lows (**L2**–**L10**) — request-body size caps, `ConfirmEmail` GET mode docs, revoked-token cleanup startup delay, `<` vs `<=` docs, `ApiPrefix` validation, customizer regression docs, health-check exception leak, CLAUDE.md alignment (subsumed by Phase 1 mostly; verify).

---

## Finding H5 (High) — Fake transaction boundary in `UpdateUserInfo`

### File
`Idmt.Plugin/Features/Manage/UpdateUserInfo.cs:87-115`

### Problem
Handler call `BeginTransactionAsync` around block that include `UserManager.ChangeEmailAsync`. `ChangeEmailAsync` issue own internal `SaveChangesAsync` — outer transaction not encompass it. If later step (e.g., password change or final `UpdateAsync`) fail and outer `RollbackAsync` run, email change already committed.

Post-Phase-1, `UpdateUserInfo` stage new emails out-of-band (email change not commit until confirmation token presented). So H5 largely dissolve — no in-flight `ChangeEmailAsync` call during main handler. But other ops in `UpdateUserInfo` (password change, `UpdateAsync` for other fields) may still share misleading transaction scope.

### Fix
- Remove outer `BeginTransactionAsync` entirely if handler no longer need atomicity across multiple Identity API calls.
- If transaction retained, ensure every op inside participate correctly with EF `DbContext.Database.BeginTransactionAsync`.
- Serialize ops so any side-effect (like Identity internal saves) land last, after all other mutations succeed. Document explicit that compound identity updates non-atomic at user-visible level.
- Remove false guarantee from method XML docs.

### Files to modify
- `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs`

### Verification
- Code review: no outer `BeginTransactionAsync` wrapping `UserManager` calls.
- Integration test: simulate password-change failure after email stage → `PendingEmail` unaffected (or fully staged if change-email meant to be second step).
- Regression: existing `UpdateUserInfo` happy-path tests still pass.

---

## Finding M1 (Medium) — Login timing oracle

### File
`Idmt.Plugin/Features/Auth/Login.cs:89-101, 207-220` (`Login.Handler` and `TokenLoginHandler`)

### Problem
```csharp
if (user is null || !user.IsActive) return Unauthorized;
```
Short-circuit *before* PBKDF2 verify step. Existing users pay ~100 ms hashing cost; unknown or inactive users return in few ms. Timing analysis distinguish valid/invalid accounts.

### Fix
On null / inactive branch, do dummy hash verification to equalize timing:
```csharp
userManager.PasswordHasher.VerifyHashedPassword(new IdmtUser(), DummyHash, request.Password);
return Unauthorized;
```
`DummyHash` pre-computed PBKDF2 hash stored as constant. Work comparable to real hash verify without exposing real user hash.

Same fix in `TokenLoginHandler` for bearer login path.

### Files to modify
- `Idmt.Plugin/Features/Auth/Login.cs`

### Verification
- Unit test: `Login` with unknown email → timing within ±20 ms of login with known email + wrong password.
- Unit test: `TokenLoginHandler` equivalent.

---

## Finding M3 (Medium) — `is_active` claim staleness

### Files
- `Idmt.Plugin/Services/IdmtUserClaimsPrincipalFactory.cs:26`
- `Idmt.Plugin/Services/CurrentUserService.cs:34`
- `Idmt.Plugin/Features/Manage/UpdateUser.cs` (deactivation path)

### Problem
`is_active` claim stamped at login. Admin deactivate user via `UpdateUser` → existing tokens still carry `is_active = true`. Cookie re-validate stamp every 30 min; bearer used to not re-validate at all (fixed in C1/Phase 2), but deactivation event need to actively invalidate sessions.

### Fix
In `UpdateUser` when `IsActive` flip `true → false`:
1. Call `userManager.UpdateSecurityStampAsync(appUser)` — invalidate cookie sessions.
2. Call `tokenRevocationService.RevokeUserTokensAsync(userId, tenantId)` — invalidate bearer sessions (Phase 2 ensure honored). Under canonical model, one call cover user across all tenants they active in (key is canonical `userId`).

Same pattern in `RevokeTenantAccess.cs` where `IsActive` flip on `TenantAccess` should also trigger stamp + revocation.

### Files to modify
- `Idmt.Plugin/Features/Manage/UpdateUser.cs`
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs` — ensure already covered in Phase 1; re-audit.

### Verification
- Integration test: deactivate user; cached bearer token return 401 on next request.
- Integration test: deactivate user; cookie session rejected within 30 min (stamp re-validation interval).

---

## Finding M4 (Medium) — Handler lookups by email

### Files
- `Idmt.Plugin/Features/Manage/GetUserInfo.cs:35-44`
- `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs:47-53`

### Problem
`FindByEmailAsync(user.FindFirstValue(ClaimTypes.Email))` — break identity correlation if email changed between token issuance and request. `NameIdentifier` (canonical `Id`) is stable lookup key.

### Fix
Use `FindByIdAsync(user.FindFirstValue(ClaimTypes.NameIdentifier))`. Validate security stamp against claim stamp value post-lookup (standard Identity pattern). Reject if mismatch.

### Files to modify
- `Idmt.Plugin/Features/Manage/GetUserInfo.cs`
- `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs`

### Verification
- Integration test: issue token, change email via `UpdateUserInfo` flow, old token still resolve correct user via `Id` (not email).

---

## Finding M5 (Medium) — Self-target / peer-rank destruction guards

### Files
- `Idmt.Plugin/Features/Manage/UpdateUser.cs:31-56`
- `Idmt.Plugin/Features/Manage/UnregisterUser.cs:31-56`
- `Idmt.Plugin/Services/TenantAccessService.cs:42-60` (`CanManageUser`)

### Problem
`CanManageUser` block TenantAdmin from touching SysAdmin/SysSupport but allow TenantAdmin to delete/deactivate another TenantAdmin or themselves. Self-destructive actions produce orphaned tenants; peer-rank destruction create DoS for fellow admins.

### Fix
1. In every destructive action (`UpdateUser` when setting `IsActive = false`, `UnregisterUser`, `RevokeTenantAccess`), reject when `request.UserId == currentUserService.UserId`. Return `IdmtErrors.General.SelfTarget` (or equivalent).
2. For TenantAdmin-on-TenantAdmin in same tenant, require opt-in danger flag (`request.ConfirmPeerRank = true`) or double-sign pattern (second TenantAdmin approve). Simplest: boolean flag in request + audit op as `HighRiskAdminAction`.
3. SysAdmins keep ability to override tenant-admin conflicts; don't apply guard to sys operations.

### Files to modify
- `Idmt.Plugin/Features/Manage/UpdateUser.cs`
- `Idmt.Plugin/Features/Manage/UnregisterUser.cs`
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs`
- `Idmt.Plugin/Services/TenantAccessService.cs`
- `Idmt.Plugin/Errors/IdmtErrors.cs` — add `General.SelfTarget`, `General.PeerRankDanger` (or similar).

### Verification
- Integration test: TenantAdmin call `UnregisterUser` with own userId → 400 `SelfTarget`.
- Integration test: TenantAdmin A call `UnregisterUser` on TenantAdmin B (same tenant) → 400 `PeerRankDanger` unless `ConfirmPeerRank = true`.
- Integration test: SysAdmin override freely.

---

## Finding M6 (Medium) — Endpoint-level `RequireAuthorization` defense-in-depth

### Files
- `Idmt.Plugin/Features/Admin/CreateTenant.cs:132-159`
- `Idmt.Plugin/Features/Admin/GetAllTenants.cs`
- `Idmt.Plugin/Features/Admin/GetUserTenants.cs`
- `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs`
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs`
- `Idmt.Plugin/Features/AdminEndpoints.cs:14` (group-level)

### Problem
Group-level `.RequireAuthorization` is only guard on several endpoints. If future refactor map endpoint outside group, become anonymous. `DeleteTenant.cs:74` already apply policy at endpoint level — use as template.

### Fix
Add `.RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)` (or `RequireSysUserPolicy` for read endpoints) to every individual endpoint mapper. Redundant with group-level guard, intentional.

Most covered by Phase 0 C2 implementation. Phase 4 finalize any remaining gaps discovered during review.

### Files to modify
- Every endpoint mapper under `Idmt.Plugin/Features/Admin/*`.

### Verification
- Contract test: enumerate all mapped endpoints under `/admin/*`; assert each has endpoint-level authorization metadata.

---

## Finding M7 (Medium) — `ResendConfirmationEmail` timing/dispatch oracle

### File
`Idmt.Plugin/Features/Auth/ResendConfirmationEmail.cs:39-67`

### Problem
Return `Ok` regardless of user existence, but only dispatch email when user exist + active + unconfirmed. Response timing and downstream email traffic observable — attacker can tell whether account exist by timing differences or by watching their mail server incoming queue for honeypot address.

### Fix
1. Enqueue email dispatch async (e.g., via background queue or `Task.Run`-safe equivalent) so response time uniform regardless of user state.
2. Rate-limit endpoint (covered by Phase 3 H2).
3. Optional: dispatch placeholder "request received" email even for non-existent users. Trade-offs (spam risk) — decide per team policy.

### Files to modify
- `Idmt.Plugin/Features/Auth/ResendConfirmationEmail.cs`
- Optional: background email queue service.

### Verification
- Integration test: request with known-unconfirmed email + request with unknown email → identical response time ±20 ms.
- Integration test: known-unconfirmed email → email dispatched (observed via mocked `IEmailSender`).

---

## Finding M8 (Medium) — PII masker inconsistent

### Files
- `Idmt.Plugin/Services/PiiMasker.cs:11-15`
- `Idmt.Plugin/Features/Manage/RegisterUser.cs:92, 100`
- `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs:74, 91`
- `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs:196`
- `Idmt.Plugin/Services/IdmtEmailSender.cs:11, 17, 23` (after Phase 3 rename to `StubEmailSender`)

### Problem
`IdentityError.Description` messages like `"Username 'foo@bar.com' is already taken."` logged verbatim. Stub email sender log unmasked emails.

### Fix
- Log only `IdentityError.Code`, not `Description`, for errors that may echo input.
- Route all email logging through `PiiMasker.MaskEmail`.
- Audit every logger statement that take user-provided strings; mask or omit as appropriate.

### Files to modify
- All files referenced above.

### Verification
- Grep source for `logger.Log*(...)` calls referencing `IdentityError.Description`, `request.Email`, `user.Email` — assert each masked or replaced with `IdentityError.Code`.
- Unit test: provoke duplicate-username error; capture log output; assert raw email not appear.

---

## Finding N7 (High) — Audit log coupled to business-data transaction

### File
`Idmt.Plugin/Persistence/IdmtDbContext.cs:159-229` (`SaveChangesAsync` audit-building overrides)

### Problem
Audit entries built inside same `SaveChangesAsync` transaction as business data. Two failure modes:
- **L1 (original)**: malformed audit entry cause whole build step to fail; code detach *all* audit entries and commit business data with zero audit — compliance risk (SOC2 CC7.2).
- **Coupling (new)**: valid but large/problematic audit entries can block legitimate business writes.

Either way, audit durability tied to business-data durability in wrong direction.

### Fix
1. Move audit writes to **separate transaction** or **append-only outbox**:
   - Simplest: after `SaveChangesAsync` for business data complete successfully, write audits in second `SaveChangesAsync` (own transaction). Failures log + alert but don't roll back business write.
   - Better: append to outbox table in same transaction as business data (so no loss) but process async into audit store.
2. **Per-entry try/catch** at build time: if one audit entry fail to construct, record `AuditEntry { Success = false, Error = ... }` rather than drop *all* audits.
3. **For security-critical tables** (`IdmtUser`, `TenantAccess`, `RevokedToken`), rethrow on audit-build failure — do NOT allow business write without corresponding audit row. Deliberate inversion: for these tables want fail-closed on audit.

### Files to modify
- `Idmt.Plugin/Persistence/IdmtDbContext.cs` — restructure audit-build pipeline.
- Potentially new `AuditOutbox` DbSet if outbox path chosen.

### Verification
- Unit test: inject audit builder that throw for one entry → other audits succeed, business write proceed.
- Unit test: inject audit builder that throw for `IdmtUser` entry → business write rejected.
- Integration test: simulate audit-store failure after business write succeed → business write persist, audit outbox retain pending entry.

---

## Finding N9 (Medium) — `SameSite=Strict` not sole CSRF defense

### File
`Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:328-335`

### Problem
Plan relied on `SameSite=Strict` as CSRF mitigation for cookie flows. Not bulletproof:
- Safari builds before ~2024 had different default behaviors for unset SameSite.
- Extension-initiated requests may present same-site origin.
- Certain redirect chains and iframe scenarios circumvent `Strict`.

For security library meant for broad use, relying on single browser-side control insufficient.

### Fix
Pick one (or both):
1. **Add `IAntiforgery`** as defense-in-depth for cookie state-changing flows. Issue antiforgery tokens on login; require on state-changing POST/PUT/DELETE endpoints when authed via cookie. Bearer flows exempt (tokens not sent automatically by browsers).
2. **Validate `Origin` / `Referer` headers** on state-changing cookie requests. Reject requests whose `Origin` host doesn't match configured `ClientUrl` host.

Minimum viable: (2), lower friction for consumers. If team want stronger guarantee, layer (1) on top.

Document clear: "IDMT cookie auth assume browser-only, same-origin usage. Consumers deploying cookie auth to cross-origin flows must enable `SameSite=None` + `AllowInsecureClientUrl=false` + confirm `Origin` matches."

### Files to modify
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — register antiforgery and/or origin-check middleware.
- New middleware: `Idmt.Plugin/Middleware/OriginValidationMiddleware.cs` if path (2) chosen.
- Docs: XML docs + CLAUDE.md.

### Verification
- Integration test: state-changing POST with cookie + `Origin: https://evil.com` → 403.
- Integration test: same call with `Origin` matching configured `ClientUrl` → 200.
- Integration test: bearer-authed state change unaffected.

---

## Lows

Ship as single hygiene PR at end of Phase 4.

### L2 — No request-body size/length caps
All request records — FluentValidation cover format, not length.
**Fix**: add `.MaximumLength(256)` (or per-field appropriate limit) on every string input. Document Kestrel body-size limit recommendation.
**Files**: every file under `Idmt.Plugin/Validation/*`.

### L3 — `ConfirmEmail` GET state-change on link-preview fetch
`Idmt.Plugin/Features/Auth/ConfirmEmail.cs:104-137`. Email security scanners auto-fetch links, consume tokens.
**Fix**: keep `EmailConfirmationMode.ClientForm` as default (already is). Document `ServerConfirm` risk prominent in XML docs and CLAUDE.md.

### L4 — Revoked-token cleanup 1-hour startup delay
`Idmt.Plugin/Services/TokenRevocationCleanupService.cs:14-20`. `await Task.Delay(_interval)` before first pass.
**Fix**: run one cleanup pass immediately on `ExecuteAsync`, then enter loop.

### L5 — `<` vs `<=` in revocation check
`Idmt.Plugin/Services/TokenRevocationService.cs:73`. Token issued at exact millisecond of revocation not revoked. Design-documented; keep as `<`. Add code comment explaining intentional exclusive comparison.

### L6 — `ApiPrefix` not validated on `CreateTenant` `Location` response
`Idmt.Plugin/Features/Admin/CreateTenant.cs:155`. `Location` header use unvalidated `ApiPrefix`.
**Fix**: validate `ApiPrefix` as relative path at options load time.
**Files**: `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs`.

### L7 — Customizer delegates can regress defaults
`Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:404, 440`. `customizeAuthentication` / `customizeAuthorization` run *after* defaults and can replace policies with permissive ones.
**Fix**: document customizers as additive-only; consider adding separate `addAuthentication` / `addAuthorization` hooks that strictly additive. Start with docs; move to structural change only if abuse observed.

### L9 — Health endpoint expose exception stack trace
`Idmt.Plugin/Features/Health/BasicHealthCheck.cs:34-39`. `HealthCheckResult.Unhealthy(..., ex, ...)` leak stack trace. Gated by `RequireSysUser` so limit to admins, but should scrub in production.
**Fix**: check hosting environment; in `Production` omit exception or pass sanitized summary.

### L10 — CLAUDE.md mismatch
Should already update in Phase 1 as part of doc alignment. Re-verify in this phase.

---

## Phase 4 implementation order

1. **H5 + M1 + M3 + M4** — small-touch correctness fixes. One PR.
2. **M5 + M6** — user-management guard pass + endpoint-level auth backfill. One PR.
3. **M7 + M8** — async email dispatch + consistent PII masking. One PR.
4. **N7** — audit decoupling. Own PR because of scope + migration risk.
5. **N9** — antiforgery / origin validation. Own PR because of consumer impact.
6. **Lows** — batched hygiene PR at end.

---

## Files to modify (summary)

- `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs` — H5, M4.
- `Idmt.Plugin/Features/Manage/GetUserInfo.cs` — M4.
- `Idmt.Plugin/Features/Manage/UpdateUser.cs` — M3, M5.
- `Idmt.Plugin/Features/Manage/UnregisterUser.cs` — M5.
- `Idmt.Plugin/Features/Auth/Login.cs` — M1.
- `Idmt.Plugin/Features/Auth/ResendConfirmationEmail.cs` — M7.
- `Idmt.Plugin/Features/Auth/ConfirmEmail.cs` — L3 doc.
- `Idmt.Plugin/Features/Admin/*` — M6 finalization.
- `Idmt.Plugin/Services/TokenRevocationCleanupService.cs` — L4.
- `Idmt.Plugin/Services/TokenRevocationService.cs` — L5 comment.
- `Idmt.Plugin/Services/TenantAccessService.cs` — M5 peer-rank.
- `Idmt.Plugin/Services/PiiMasker.cs` — M8 (if needed).
- `Idmt.Plugin/Persistence/IdmtDbContext.cs` — N7.
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — N9 registration.
- New: `Idmt.Plugin/Middleware/OriginValidationMiddleware.cs` — N9.
- `Idmt.Plugin/Validation/*` — L2.
- `Idmt.Plugin/Configuration/IdmtOptionsValidator.cs` — L6.
- `Idmt.Plugin/Features/Health/BasicHealthCheck.cs` — L9.
- `Idmt.Plugin/Errors/IdmtErrors.cs` — new error codes (M5).
- `CLAUDE.md` — L10 verification.

---

## Verification (phase-wide)

- Each finding unit / integration tests listed above pass.
- Regression: full test suite continue pass.
- `dotnet test Idmt.slnx`, `dotnet format Idmt.slnx --verify-no-changes`, and warnings-as-errors build all pass.

---

## Phase 4 done-criteria

- `UpdateUserInfo` no longer present false transaction guarantee.
- Login timing equalized across null/inactive/known branches.
- User deactivation + tenant-access revocation invalidate both cookie and bearer sessions immediately.
- Handler lookups use canonical `Id` and validate security stamp post-lookup.
- Self-target and peer-rank destruction guarded by explicit opt-in.
- All admin endpoints have endpoint-level authorization metadata.
- `ResendConfirmationEmail` response time uniform regardless of user state.
- Identity error descriptions no longer logged verbatim; PII masking consistent.
- Audit writes decoupled from business-data transaction; security-critical table audits fail-closed.
- Antiforgery / origin validation layered on top of `SameSite=Strict` for cookie flows.
- Lows cleaned up (body-size caps, startup cleanup pass, scrubbed health-check, documented customizer contract, validated `ApiPrefix`, CLAUDE.md accurate).
- Full test suite + format + warnings-as-errors pass.

End state: plugin security posture match consolidated audit recommendations. Follow-up work (beyond this plan): dedicated `Idmt.SecurityTests` project, session inventory / per-device revocation granularity, per-tenant DataProtection isolation, MFA / step-up for sys operations.