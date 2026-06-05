# Phase 2 — Bearer-Token Coherence

Make revocation enforceable. Depend on Phase 1 (canonical identity) — revocation key on canonical `userId`.

---

## Project overview

IDMT (Identity MultiTenant) Plugin — reusable NuGet lib for ASP.NET Core, multi-tenant identity. Built on Finbuckle.MultiTenant + ASP.NET Core Identity. Per-tenant cookie isolation, hybrid cookie/bearer auth, vertical slice arch. Use ErrorOr for results, FluentValidation for requests. Target: net10.0.

Key services + concepts:
- **Finbuckle.MultiTenant** resolve tenants via strategies (Header, Route, Claim, BasePath).
- `IdmtUser` global (post-Phase-1); `IdmtRole` per-tenant; `SysRole` global enum column on `IdmtUser`.
- `TenantAccess` map users to tenants with `IsActive` + optional `ExpiresAt`.
- Per-tenant cookie isolation: each tenant separate auth cookie name.
- `ValidateBearerTokenTenantMiddleware` ensure bearer token tenant match request tenant.
- Two EF contexts: `IdmtDbContext` (multi-tenant app data) + `IdmtTenantStoreDbContext` (tenant metadata).
- Pre-configured auth policies: `RequireSysAdmin`, `RequireSysUser`, `RequireTenantManager`, `CookieOnly`, `BearerOnly`.
- Token revocation via `ITokenRevocationService` + background cleanup (`TokenRevocationCleanupService`).
- Bearer auth use `AddBearerToken` with DataProtection-based opaque tokens (not JWT).

Build/test: `dotnet build Idmt.slnx`, `dotnet test Idmt.slnx`, `dotnet format Idmt.slnx --verify-no-changes`.

---

## Architectural context (from Phase 1)

**Canonical `IdmtUser` + `TenantAccess` + global `SysRole` column.**

Phase 1 made `IdmtUser` global. One hash, one stamp, one canonical `Id` per human. Revocation keyed by `(userId, tenantId)` now resolve unambiguously — single revocation entry for user X in tenant Y covers every bearer token issued to that user for that tenant.

Phase 2 build on this: revocation store coherent, but *not consulted* on access-token use (only on refresh). That core gap closed this phase.

### Target schema (relevant portion, carried from Phase 1)

```
IdmtUser (global — no IsMultiTenant)
  Id, Email, PasswordHash, SecurityStamp, LockoutEnd, IsActive,
  SysRole : SysRoleKind (None | SysAdmin | SysSupport, default None)

RevokedToken (or equivalent revocation record)
  UserId, TenantId, RevokedAt
  (Stores the "everything issued to this user/tenant before RevokedAt is invalid" marker.)
```

### Claim factory (carried from Phase 1)

```csharp
var roles = await userManager.GetRolesAsync(user);   // per-tenant, Finbuckle-filtered
foreach (var role in roles) identity.AddClaim(new Claim(ClaimTypes.Role, role));
if (user.SysRole != SysRoleKind.None)
    identity.AddClaim(new Claim(ClaimTypes.Role, user.SysRole.ToString()));
```

---

## Phase 2 scope

Five findings, all on bearer/refresh-token revocation + timestamp correctness:

1. **M2** — `IssuedUtc` set explicitly on issued tickets. Prereq for rest of phase.
2. **N5** — Refresh-token rotation: presented refresh token invalidated on use; fresh refresh token issued.
3. **C1** — Access tokens check revocation store via `BearerTokenEvents.OnTokenValidated`.
4. **C5** — Remove dead null-tenant guard in `RefreshToken`.
5. **C6** — `Logout` return Unauthorized instead of silent 204 when tenant unresolvable.

**Ship order matters**: M2 → N5 → C1 → C5/C6. M2 first because N5 and C1 rely on `IssuedUtc`. N5 before C1 so refresh tokens already rotated when access-token revocation tightens.

---

## Finding M2 (Medium → ship first) — Refresh/auth `IssuedUtc` unset, revocation check drifts

### Files
- `Idmt.Plugin/Features/Auth/RefreshToken.cs:70-77`
- `Idmt.Plugin/Features/Auth/Login.cs:290-297`

### Detail
`AuthenticationProperties` built for bearer + refresh issuance don't set `IssuedUtc`. Revocation check in `RefreshToken.HandleAsync:74` (+ new C1 check) compare token `IssuedUtc` vs store `RevokedAt`. When `IssuedUtc` unset, code fall back to `issuedAt = expiresUtc - RefreshTokenExpiration` (or equivalent for access tokens).

Failure mode: operator shorten `RefreshTokenExpiration` (or `BearerTokenExpiration`) after issuing tokens → computed `issuedAt` for older tokens become *later* than true issuance. Tokens issued before revocation compute false `issuedAt >= RevokedAt` → revocation check pass → token accepted despite revoked.

### Fix
Set `IssuedUtc = timeProvider.GetUtcNow()` explicit on *both* auth ticket + refresh ticket properties in `TokenLoginHandler` (login) and on newly-issued properties during refresh rotation (N5).

```csharp
var now = timeProvider.GetUtcNow();
var authProperties = new AuthenticationProperties
{
    IssuedUtc = now,
    ExpiresUtc = now.Add(options.BearerTokenExpiration),
    // ...
};
var refreshProperties = new AuthenticationProperties
{
    IssuedUtc = now,
    ExpiresUtc = now.Add(options.RefreshTokenExpiration),
    // ...
};
```

Remove fallback path in revocation check. If `IssuedUtc` missing on incoming ticket, reject as invalid — don't compute from expiry.

### Files to modify
- `Idmt.Plugin/Features/Auth/Login.cs` (`TokenLoginHandler`)
- `Idmt.Plugin/Features/Auth/RefreshToken.cs`
- `Idmt.Plugin/Services/TokenRevocationService.cs` (remove fallback computation)

### Verification
- Unit test: decode fresh ticket; assert `IssuedUtc` set.
- Unit test: `IsTokenRevokedAsync` called with ticket whose `IssuedUtc` null → return "invalid" (not false-negative).
- Unit test: after `TimeProvider` advance 5 min, `IssuedUtc` reflect original issuance time, not now.

### Dependencies
None within Phase 2. Ship first. M2 prereq for N5 + C1.

---

## Finding N5 (High) — Refresh-token rotation absent

### File
`Idmt.Plugin/Features/Auth/RefreshToken.cs:41-81`

### Detail
Current refresh flow validate presented refresh token, check expiry, optionally check revocation (only when `tenantId is not null`), issue new access token. Does **not** issue new refresh token, does **not** invalidate presented refresh token. Same refresh token replayable until absolute expiration (default 14 days).

Impact: stolen refresh token reusable for full lifetime window. C1 access-token revocation half-fix without rotation — attacker simply refresh when access token rejected.

### Fix
On every successful refresh:
1. Issue **new refresh token** alongside new access token. Include `IssuedUtc` per M2.
2. **Mark presented refresh token used**. Options:
   - **Option A (recommended)**: store presented ticket `IssuedUtc` in revocation store keyed `(userId, tenantId)` — raise per-tenant revocation point above old `IssuedUtc` but below new one. Coarse (revokes *all* tokens issued before new one), simple with existing schema. Acceptable — new refresh token supersede all prior anyway.
   - **Option B**: introduce token-id (`jti`-equivalent) into ticket payload + track revoked-id set. Heavier — extend protected payload. Defer later phase.
3. Detect **refresh-token reuse**: if presented refresh `IssuedUtc < current per-user-tenant revocation point`, treat as compromised-refresh event. Revoke all user tokens in tenant (`RevokeUserTokensAsync`) + log security event. Standard rotated-refresh reuse-detection pattern.

Start Option A. If finer tracking needed later, layer Option B.

### Files to modify
- `Idmt.Plugin/Features/Auth/RefreshToken.cs`
- `Idmt.Plugin/Services/TokenRevocationService.cs` (optional: expose `SetRevocationPointAsync(userId, tenantId, utc)` helper distinct from `RevokeUserTokensAsync`).

### Verification
- Integration test: present refresh token twice → second call 401.
- Integration test: present refresh, receive new refresh, present new → 200.
- Integration test: present refresh, receive new, present *old* → 401 **and** newly-issued refresh also revoked (reuse detection).
- Integration test: `IssuedUtc` of new refresh > old refresh.

### Dependencies
M2 ship first.

---

## Finding C1 (Critical) — Access tokens never checked against revocation store

### Files
- `Idmt.Plugin/Middleware/ValidateBearerTokenTenantMiddleware.cs`
- `Idmt.Plugin/Services/TokenRevocationService.cs`
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:370-384` (`BearerTokenEvents` configuration)

### Detail
`IsTokenRevokedAsync` called only inside `RefreshToken.HandleAsync:74`. No middleware, auth event, or policy check revocation for plain access-token requests. After logout / password reset / revoke-tenant-access, previously-issued bearer access token keep working until natural expiration (`BearerTokenExpiration`, default 60 min).

**Attack**: stolen bearer token survive logout + password reset up to 60 min. Combined with N5 (refresh rotation), closing this gap mean stolen credentials lose access within access-token window after any revocation.

### Fix
Wire `BearerTokenEvents.OnTokenValidated` to call `IsTokenRevokedAsync` after ticket unprotected + principal available. Reject on revocation hit.

```csharp
.AddBearerToken(IdmtAuthOptions.BearerScheme, options =>
{
    options.Events = new BearerTokenEvents
    {
        OnTokenValidated = async ctx =>
        {
            var userId = ctx.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
            var tenantClaim = ctx.Principal?.FindFirstValue(IdmtClaims.Tenant);
            var issuedUtc = ctx.Properties?.IssuedUtc;

            if (userId is null || tenantClaim is null || issuedUtc is null)
            {
                ctx.Fail("Invalid token ticket");
                return;
            }

            var revocationSvc = ctx.HttpContext.RequestServices
                .GetRequiredService<ITokenRevocationService>();
            if (await revocationSvc.IsTokenRevokedAsync(
                    Guid.Parse(userId), tenantClaim, issuedUtc.Value))
            {
                ctx.Fail("Token revoked");
            }
        }
    };
    // other configuration ...
});
```

**Caching**: add short-TTL (~30s) in-memory cache keyed `(userId, tenantId)` to bound DB load. Cache revocation point (`RevokedAt` timestamp). On cache hit with stale entry, compare vs token `IssuedUtc` without DB roundtrip. Invalidate on new revocations written by `RevokeUserTokensAsync`.

**Alternative**: middleware between `UseAuthentication` + `UseAuthorization` doing same check. `OnTokenValidated` preferred — fails early (within auth handler), participates natively in auth result pipeline.

### Files to modify
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — extend `AddBearerToken` config with `OnTokenValidated`.
- `Idmt.Plugin/Services/TokenRevocationService.cs` — add cache layer.
- Potentially new file: `Idmt.Plugin/Services/TokenRevocationCache.cs` (memory cache for revocation points).

### Verification
- Integration test: login, call protected endpoint → 200; logout; call same endpoint with cached bearer → 401.
- Integration test: login tenant A, revoke tenant-access for user in A, call protected A endpoint with cached bearer → 401.
- Integration test: login tenant A, issue two tokens at different moments; revoke user; both rejected.
- Integration test: cache behavior — revoke user; wait < TTL for cache invalidation propagation; assert token rejected within TTL.
- Concurrency test: logout race — concurrent logout + protected-endpoint call; expected either one succeeds and other fails, never both succeed. Exercise `DbUpdateException` branch at `TokenRevocationService.cs:43`.
- Clock-skew test: revoke at T, token `IssuedUtc = T - 1ms`, verify revoked (exercise L5 `<` boundary — confirm comparison strictly `IssuedUtc < RevokedAt`, meaning token issued *after* revocation honored).

### Dependencies
- M2 (IssuedUtc set) ship first.
- N5 (refresh rotation) ship first. Without rotation, C1 force attackers to call refresh; close both together close loop.

---

## Finding C5 (demoted) — Remove dead null-tenant guard in `RefreshToken`

### File
`Idmt.Plugin/Features/Auth/RefreshToken.cs:62-67, 72-76`

### Detail
`RefreshToken.cs:62-67` already return `Unauthorized` on null tenant (from token claim or current resolved tenant). `if (tenantId is not null && await IsTokenRevokedAsync(...))` guard at line 72 dead — `tenantId` can't be null there.

Originally Critical (null-tenant revocation bypass); evidence show earlier check already 401s. Reclassified hygiene.

### Fix
Remove `tenantId is not null &&` conjunction. Call `IsTokenRevokedAsync` unconditional. If something slip past earlier guard (refactor), call should throw or return definitive answer — never silently skip.

### Files to modify
- `Idmt.Plugin/Features/Auth/RefreshToken.cs`

### Verification
- Code review confirm dead guard removed.
- Integration test: unreachable-by-design, but assert `RefreshToken` return 401 when `X-Tenant` header missing (pre-existing behavior, regression).

### Dependencies
Can ship with C1 — both touch `RefreshToken`.

---

## Finding C6 (demoted to Medium) — `Logout` silent-success on null tenant

### File
`Idmt.Plugin/Features/Auth/Logout.cs:46-79`

### Detail
Bearer-authenticated logout with no resolvable tenant context hit `else` branch (line 69-79) — logs warning, return 204 **without calling `RevokeUserTokensAsync`**. Refresh tokens stay valid. Current code reach this branch only under cookie auth with null tenant — cookies per-tenant-named so path narrow, but fail-closed > fail-open.

### Fix
Return `IdmtErrors.Auth.Unauthorized` (or new `IdmtErrors.Tenant.NotResolved` → 401/400 per convention) instead of 204. Never succeed logout that didn't revoke. Remove silent-warn branch; log event as error if it fires post-Phase-1.

### Files to modify
- `Idmt.Plugin/Features/Auth/Logout.cs`
- Potentially `Idmt.Plugin/Errors/IdmtErrors.cs` if new error code introduced.

### Verification
- Integration test: authenticated request with no resolvable tenant → `/auth/logout` return 401, not 204.
- Integration test: normal authenticated logout path → 204 + refresh tokens revoked (regression).

### Dependencies
None; ship alongside C5.

---

## Phase 2 implementation order

1. **M2** — set `IssuedUtc` explicit. Unit tests.
2. **N5** — refresh-token rotation with reuse detection. Integration tests.
3. **C1** — `OnTokenValidated` revocation check with short-TTL cache. Integration + concurrency tests.
4. **C5** — remove dead null-tenant guard. Code-review verification.
5. **C6** — fail-closed logout. Integration test.

Split two-three PRs if helpful: PR#1 = M2 + N5, PR#2 = C1, PR#3 = C5 + C6. Each build on prior.

---

## Files to modify (summary)

- `Idmt.Plugin/Features/Auth/Login.cs` — set `IssuedUtc` at token issuance (M2).
- `Idmt.Plugin/Features/Auth/RefreshToken.cs` — set `IssuedUtc`, implement rotation + reuse detection, remove dead guard (M2, N5, C5).
- `Idmt.Plugin/Features/Auth/Logout.cs` — fail-closed on null tenant (C6).
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs` — wire `OnTokenValidated` handler (C1).
- `Idmt.Plugin/Services/TokenRevocationService.cs` — remove fallback, add cache integration, optionally add `SetRevocationPointAsync` for rotation (M2, N5, C1).
- `Idmt.Plugin/Services/TokenRevocationCache.cs` — new in-memory cache for recent revocation points (C1).
- `Idmt.Plugin/Errors/IdmtErrors.cs` — optionally add `Tenant.NotResolved` (C6).

---

## Verification (phase-wide)

- All unit/integration tests above pass.
- Regression: full Phase 1 test suite (canonical identity) still pass — revocation coherent across tenants for single canonical user.
- `dotnet test Idmt.slnx` passes.
- `dotnet format Idmt.slnx --verify-no-changes` passes.
- Build with warnings-as-errors passes.

---

## Phase 2 done-criteria

- All bearer tickets carry explicit `IssuedUtc`; revocation service reject tickets without one.
- Present same refresh token twice → second call rejected; reuse trigger full-user revocation in tenant.
- Protected endpoints with revoked bearer token return 401.
- `RefreshToken.cs` contain no conditional revocation check.
- `Logout` return 401 (not 204) when tenant unresolvable; success path revoke tokens.
- Full test suite + format + warnings-as-errors pass.

Phase 3 begin when all above satisfied.