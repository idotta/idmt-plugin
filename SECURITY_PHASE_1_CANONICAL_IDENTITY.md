# Phase 1 — Canonical Identity Migration

Foundational data-model change. Fix several Critical findings at root, not patch symptoms. Depend on Phase 0 (N2 context-restore).

---

## Project overview

IDMT (Identity MultiTenant) Plugin — reusable NuGet library for ASP.NET Core, multi-tenant identity management. Built on Finbuckle.MultiTenant + ASP.NET Core Identity, per-tenant cookie isolation, hybrid cookie/bearer auth, vertical slice architecture. Use ErrorOr for results, FluentValidation for requests. Target: net10.0.

Key services + concepts:
- **Finbuckle.MultiTenant** resolve tenants via strategies (Header, Route, Claim, BasePath).
- Today `IdmtUser` extend `IdentityUser<Guid>` as multi-tenant; `IdmtRole` per-tenant. This Phase make `IdmtUser` global.
- `TenantAccess` map users to tenants with `IsActive` + optional `ExpiresAt`.
- Per-tenant cookie isolation: each tenant get separate auth cookie name.
- `ValidateBearerTokenTenantMiddleware` ensure bearer token tenant match request tenant.
- Two EF contexts: `IdmtDbContext` (multi-tenant app data) + `IdmtTenantStoreDbContext` (tenant metadata).
- `ITenantOperationService` run code in tenant-scoped DI scope (fixed Phase 0).
- Pre-configured auth policies: `RequireSysAdmin`, `RequireSysUser`, `RequireTenantManager`, `CookieOnly`, `BearerOnly`.
- Token revocation via `ITokenRevocationService` + background cleanup (`TokenRevocationCleanupService`).

Build/test: `dotnet build Idmt.slnx`, `dotnet test Idmt.slnx`, `dotnet format Idmt.slnx --verify-no-changes`.

---

## Architectural decision

**Canonical `IdmtUser` + `TenantAccess` + global `SysRole` column.**

### Rationale

Current code store one `IdmtUser` row per tenant. `GrantTenantAccess.cs:117-133` create shadow row in target tenant, copy `PasswordHash` + `LockoutEnd`, generate fresh `Id` + `SecurityStamp`. Model make coherent identity ops impossible across tenants:
- Password rotation update only current-tenant row.
- `UpdateSecurityStampAsync` affect only current-tenant row.
- `TokenRevocationService.RevokeUserTokensAsync(userId, tenantId)` key on *row-specific* `userId`; shadow row in another tenant have different `userId`, so revocations no cross tenants.
- Lockout state no propagate.
- Email-change state drift.

Primary use case for `GrantTenantAccess` per product intent: SysUsers hop into any tenant. Secondary: normal user with multi-tenant membership. Canonical model serve both without shadow rows.

### Target schema

```
IdmtUser (global — drop IsMultiTenant)
  Id, Email, NormalizedEmail, PasswordHash, SecurityStamp,
  LockoutEnd, EmailConfirmed, IsActive, ...
  SysRole : SysRoleKind   // non-null enum: None | SysAdmin | SysSupport
                          // default = None (stored as int)

IdmtRole (per-tenant, IsMultiTenant — unchanged)
  Id, Name, TenantId
  Populated with TenantAdmin, TenantUser, or consumer-defined roles.
  Drop pre-seeded SysAdmin/SysSupport rows — they move to IdmtUser.SysRole.

IdentityUserRole<Guid> (per-tenant, IsMultiTenant — unchanged)
  UserId -> IdmtUser.Id, RoleId -> IdmtRole.Id, TenantId (Finbuckle shadow)

TenantAccess (per-tenant — unchanged)
  UserId, TenantId, IsActive, ExpiresAt
```

### Flow impact

| Flow | Before | After |
|---|---|---|
| SysUser into tenant B | `GrantTenantAccess` clone user, copy hash, compensation window | Set `IdmtUser.SysRole = SysAdmin`. No clone, no `TenantAccess` row required. Work in every tenant immediately. |
| Normal user granted role in tenant B | `TenantAccess` + `IdentityUserRole` per tenant | Unchanged. |
| Sys + tenant role combo | Clone + role assign in shadow | `SysRole` set + per-tenant `IdentityUserRole` row. Factory emit both claims. |
| Password rotation | Only update tenant-A hash | One hash, coherent. |
| Security-stamp invalidation | Per-tenant only | One stamp, coherent. |
| Token revocation by `(userId, tenantId)` | Wrong `userId` for shadow rows | One canonical `userId`; per-tenant revoke still valid. |
| Email change | Per-tenant | One place. Document as intentional. |

### Claim assembly change (`IdmtUserClaimsPrincipalFactory.cs:26`)

```csharp
var roles = await userManager.GetRolesAsync(user);   // per-tenant (Finbuckle-filtered) — unchanged
foreach (var role in roles)
    identity.AddClaim(new Claim(ClaimTypes.Role, role));
if (user.SysRole != SysRoleKind.None)
    identity.AddClaim(new Claim(ClaimTypes.Role, user.SysRole.ToString()));
```

### Finbuckle integration

`IdmtUser` entity drop `.IsMultiTenant()` in `IdmtDbContext.cs:99-102`. Two options:
- **(a)** Keep in `IdmtDbContext` with no tenant filter on `IdmtUser` only. Less invasive — one `modelBuilder.Entity<IdmtUser>()` adjustment — and keep Identity's UserStore resolver pointed at single context.
- **(b)** Move to `IdmtTenantStoreDbContext` (global store). Larger refactor; cleaner conceptually.

Recommend **(a)** this phase.

`UserManager.FindByEmailAsync` / `FindByIdAsync` resolve globally. `GetRolesAsync` still filter per-tenant via `IdentityUserRole` multi-tenancy. No change to Identity APIs.

### Blast-radius note

Canonical model mean compromise of user's hash grant access to every tenant they in. Current shadow model *appear* to bound this but share hash via `GrantTenantAccess.cs:117-133`, so canonical strictly better: rotation + stamp invalidation now work. Document explicit in CLAUDE.md + release notes.

### Migration for existing deployments

Offline script (document as breaking change; bump major version):
1. Group existing `IdmtUser` rows by `NormalizedEmail`. Pick canonical `Id` (oldest row).
2. Rewrite `TenantAccess.UserId`, `IdentityUserRole.UserId`, `RevokedToken.UserId`, audit rows to canonical id.
3. Merge `SysRole` from any tenant row where user was `SysAdmin`/`SysSupport` → set on canonical row. All other rows default `SysRoleKind.None`.
4. Drop duplicate `IdmtUser` rows.
5. Force password reset for all migrated users — hashes may have diverged across shadows.

Provide idempotent SQL/EF script + rollback plan + deployment runbook.

---

## Phase 1 findings

### 1. Schema + code migration

Implementation order this phase:
1. Add `SysRoleKind` enum + `SysRole` column to `IdmtUser`.
2. Remove `IsMultiTenant()` from `IdmtUser` entity in `IdmtDbContext`.
3. Adjust claim factory to emit `SysRole` claim.
4. EF migration: column add + (new deployments) seed-role cleanup.
5. Data migration script for existing deployments (see above).
6. Update CLAUDE.md: `IdmtUser` global, `IdmtRole` per-tenant, `SysRole` global.

### 2. Rewrite `GrantTenantAccess` (subsumes C4, N1, N3)

Originally three findings:
- **C4**: `GrantTenantAccess.cs:117-133` copy `PasswordHash`, `LockoutEnd` verbatim into shadow row. `CreateAsync(user)` (no password arg) persist hash directly. Hash-copy = root cause of stamp/hash drift.
- **N1**: Revocation keying incoherent across tenants (shadow rows have different `userId`). `RevokeTenantAccess.cs:67-80` revoke by caller's `userId`, then flip `IsActive` on *different* row. Admin "revoke" in tenant A leave tenant-B bearer session alive 60 min.
- **N3**: Partial-failure window at `GrantTenantAccess.cs:106-214`. Tenant-B user committed inside `ExecuteInTenantScopeAsync` (~line 152) *before* outer `dbContext.SaveChangesAsync` for `TenantAccess` (line 171). If outer save fails or request cancelled, tenant-B user exists without `TenantAccess` row. Compensation (line 181+) best-effort; `LogCritical` fire if compensation throws.

Under canonical model all three collapse:
- No `IdmtUser` creation — canonical user already exist.
- Handler only write:
  - `TenantAccess(UserId=canonical, TenantId=target, IsActive=true, ExpiresAt=...)` row.
  - Optional `IdentityUserRole(UserId=canonical, RoleId, TenantId=target)` row if role requested.
- Single `SaveChangesAsync`, single transaction. No compensation logic.
- SysUsers (anyone with `SysRole != None`) reach any tenant *without* `TenantAccess` row — grant only required for normal-user cross-tenant access.

Also fix **H7**: current code at `GrantTenantAccess.cs:113,187` and `RevokeTenantAccess.cs:80` use `.FirstOrDefaultAsync(u => u.Email == x && u.UserName == x)` — case-sensitive, vulnerable to null-username collision. Use `FindByEmailAsync` + assert identity via `Id` equality.

### 3. C7 — email-change + reset-password account takeover chain

**Files**: `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs:86-104`, `Idmt.Plugin/Features/Auth/ResetPassword.cs:52-56`.

**Detail**: `UpdateUserInfo` generate own change-email token inline + call `ChangeEmailAsync` immediately — no out-of-band confirmation of new address. `ResetPassword` silently set `user.EmailConfirmed = true` after successful reset.

**Attack**: attacker with temp session → `PUT /manage/info` with `NewEmail` = attacker's address → `Email` column rebound, `EmailConfirmed` = false → attacker call `ForgotPassword` on new email (they control) → reset password → `EmailConfirmed` silently flip to `true`. Account now fully bound to attacker, no victim-side confirmation ever sent.

**Fix**:
1. `UpdateUserInfo` stage new email in pending column (e.g., `IdmtUser.PendingEmail`) without touching `Email`. Send confirmation link to *new* address. Only upon click link + submit valid token does `Email` update + `EmailConfirmed` = true.
2. `ResetPassword` stop setting `EmailConfirmed = true` as side effect. Password reset prove mailbox possession at *current* `Email`, not new one.

**Implementation**:
- Add `PendingEmail` (nullable string) + `PendingEmailTokenHash` (nullable string) to `IdmtUser`. Or reuse Identity's built-in change-email token mechanism properly.
- New endpoint `POST /auth/confirm-email-change` validate token + commit `Email` swap.
- `UpdateUserInfo` return 202 (accepted, pending confirmation) when email change requested; other fields update immediately.
- `ResetPassword`: remove `EmailConfirmed = true` line.

### 4. C3 (demoted) — body-supplied `TenantIdentifier`

**Files**: `Idmt.Plugin/Features/Auth/ConfirmEmail.cs:21,32-57`, `Idmt.Plugin/Features/Auth/ResetPassword.cs:21,32-66`.

**Detail**: Both handlers accept `TenantIdentifier` in request body + pass to `ITenantOperationService.ExecuteInTenantScopeAsync`. Decouple token handling from request's tenant strategy.

Original claim (reset-token replay across tenants) not exploitable because shadow rows had independent `Id` + `SecurityStamp`. Under canonical model, same canonical user has one stamp + one password, so reset global anyway (intentional). Body-supplied `TenantIdentifier` = hygiene gap: create regression trap if anyone ever reinstate copied `Id`/`SecurityStamp`.

**Fix**: remove `TenantIdentifier` from `ConfirmEmailRequest` + `ResetPasswordRequest`. Resolve tenant from request context (header/claim/route) like every other handler. Reject if unresolvable.

### 5. Update CLAUDE.md (subsumes L10)

- `IdmtUser` global (not per-tenant).
- `IdmtRole` remain per-tenant (correct existing doc claim of "global").
- `SysRole` column on `IdmtUser` global — store `None | SysAdmin | SysSupport`.
- `TenantAccess` control cross-tenant access for non-sys users; sys users no need `TenantAccess` rows.
- Password + security-stamp now single-source; rotations propagate everywhere automatic.

---

## Dependencies

- **Phase 0 must complete.** N2 fix required before rewriting `GrantTenantAccess`, `ConfirmEmail`, `ResetPassword`, all use `ExecuteInTenantScopeAsync`. Without N2, outer-request context corrupted after delegate returns.
- Canonical migration = breaking change at DB layer — require coordinated deployment with consumer apps.

---

## Files to modify

- `Idmt.Plugin/Models/IdmtUser.cs` — add `SysRole` property (`SysRoleKind` enum, default `None`).
- `Idmt.Plugin/Models/SysRoleKind.cs` — new enum file (`None = 0, SysAdmin = 1, SysSupport = 2`).
- `Idmt.Plugin/Persistence/IdmtDbContext.cs` — drop `IsMultiTenant()` on `IdmtUser` entity; update model config.
- `Idmt.Plugin/Services/IdmtUserClaimsPrincipalFactory.cs` — emit `SysRole` as role claim when `!= None`.
- `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs` — full rewrite (delete shadow-user creation; single-transaction `TenantAccess` + optional `IdentityUserRole`).
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs` — remove cross-row lookup; revoke by canonical `userId`.
- `Idmt.Plugin/Features/Auth/ConfirmEmail.cs` — remove `TenantIdentifier` from request record; resolve from context.
- `Idmt.Plugin/Features/Auth/ResetPassword.cs` — remove `TenantIdentifier`; remove `EmailConfirmed = true`.
- `Idmt.Plugin/Features/Manage/UpdateUserInfo.cs` — stage new email instead of commit; issue OOB confirmation link.
- `Idmt.Plugin/Features/AuthEndpoints.cs` — add `POST /auth/confirm-email-change` endpoint.
- `Idmt.Plugin/Validation/*` — update validators for new/removed fields.
- `Idmt.Plugin/Services/IdmtLinkGenerator.cs` — add email-change confirmation link generator method.
- EF migration: new column + index, drop SysAdmin/SysSupport pre-seeded `IdmtRole` rows.
- Data migration script (SQL + EF seed-adjust) for existing deployments.
- `CLAUDE.md` — doc alignment.

---

## Verification

- **Canonical schema**: unit test confirm `IdmtUser` *not* filtered by Finbuckle tenant query filter; `FindByEmailAsync` work across tenant contexts.
- **SysRole claim**: integration test — user with `SysRole = SysAdmin` authenticate in two different tenants; role claim present both times.
- **GrantTenantAccess create zero users**: integration test — `POST /admin/tenant-access/grant` for existing canonical user; assert `IdmtUser` row count unchanged; `TenantAccess` row added.
- **GrantTenantAccess atomicity**: integration test — simulate `SaveChangesAsync` failure after `TenantAccess` addition; assert no partial state persist.
- **Self-grant guard** (from C2): already covered Phase 0 testing; re-run.
- **Revocation coherence** (N1): integration test — canonical user has tenant A + tenant B access; revoke via `RevokeTenantAccess` for tenant A; assert bearer token issued in tenant B still active until next Phase 2 revocation fix. Test document that revocation now coherent by `userId` alone (no shadow-row mismatch), but bearer-token enforcement itself land Phase 2.
- **C7 email-change OOB**: integration test — `PUT /manage/info` with new email → assert `IdmtUser.Email` unchanged, `IdmtUser.PendingEmail` set, confirmation email dispatched; `POST /auth/confirm-email-change` with valid token → `Email` committed, `PendingEmail` cleared.
- **C7 forgot-password on pending email**: integration test — stage new email; `POST /auth/forgot-password` with new email → 404 or no-op (pending email not the identity); legitimate `forgot-password` on current `Email` still works.
- **C7 reset no flip EmailConfirmed**: integration test — user with `EmailConfirmed = false`; successful password reset; assert `EmailConfirmed` still `false`.
- **C3 body `TenantIdentifier` gone**: contract test — `ConfirmEmailRequest` + `ResetPasswordRequest` have no `TenantIdentifier` property.
- **Data migration**: run script against test DB seeded with shadow rows; assert every `TenantAccess.UserId` resolve to extant `IdmtUser`; duplicate `IdmtUser` rows removed; `SysRole` correct backfilled.
- `dotnet test Idmt.slnx` pass.
- `dotnet format Idmt.slnx --verify-no-changes` pass.
- Build with warnings-as-errors pass.

---

## Phase 1 done-criteria

- `IdmtUser` global (no Finbuckle tenant filter); `SysRole` column present + populated.
- `GrantTenantAccess` no create `IdmtUser` rows; all writes in one transaction.
- `RevokeTenantAccess` operate on canonical `UserId`.
- `ConfirmEmail` / `ResetPassword` resolve tenant from request context.
- `ResetPassword` no mutate `EmailConfirmed`.
- Email-change flow out-of-band (new email not committed until confirmation).
- CLAUDE.md accurately reflect new data model.
- EF + data migrations exist + test-run against seeded shadow-row DB.
- Full test suite + format + warnings-as-errors pass.

Phase 2 may begin when all above satisfied.