# Phase 0 — Foundation

Block every next phase. Ship first.

---

## Project overview

IDMT (Identity MultiTenant) Plugin — reusable NuGet lib for ASP.NET Core. Multi-tenant identity mgmt. Built on Finbuckle.MultiTenant + ASP.NET Core Identity. Per-tenant cookie isolation, hybrid cookie/bearer auth, vertical slice arch. ErrorOr for results, FluentValidation for requests. Target: net10.0.

Key services + concepts:
- **Finbuckle.MultiTenant** resolve tenants via strategies (Header, Route, Claim, BasePath).
- `IdmtUser` extend `IdentityUser<Guid>` as multi-tenant; `IdmtRole` per-tenant (docs sometimes wrong say global).
- `TenantAccess` map users to tenants with `IsActive` + optional `ExpiresAt`.
- Per-tenant cookie isolation: each tenant get separate auth cookie name.
- `ValidateBearerTokenTenantMiddleware` ensure bearer token tenant match request tenant.
- Two EF contexts: `IdmtDbContext` (multi-tenant app data) + `IdmtTenantStoreDbContext` (tenant metadata).
- `ITenantOperationService` run code in tenant-scoped DI scope.
- Pre-configured auth policies: `RequireSysAdmin`, `RequireSysUser`, `RequireTenantManager`, `CookieOnly`, `BearerOnly`.
- Token revoke via `ITokenRevocationService` + background cleanup (`TokenRevocationCleanupService`).
- Vertical slices under `Idmt.Plugin/Features/` grouped `Auth/`, `Manage/`, `Admin/`, `Health/`.

Build/test: `dotnet build Idmt.slnx`, `dotnet test Idmt.slnx`, `dotnet format Idmt.slnx --verify-no-changes`.

---

## Phase 0 scope

Two items, both foundational:

1. **N2 — `TenantOperationService` ambient-context restore** (Critical). Latent cross-tenant write-corruption bug; block Phase 1 canonical-migration work touching `ExecuteInTenantScopeAsync`.
2. **C2 — Admin policies need `RequireSysAdmin`, not `RequireSysUser`** (Critical). One-hour fix, block active privilege escalation. Ship now.

Both model-agnostic — work under current shadow-row schema and under canonical-user schema in Phase 1.

---

## Finding N2 (Critical) — `TenantOperationService` mutate ambient tenant context without restore

### File
`Idmt.Plugin/Services/TenantOperationService.cs:33`

### Detail
`ExecuteInTenantScopeAsync` resolve `IMultiTenantContextSetter` from child scope and write to it. But `IMultiTenantContextAccessor` in Finbuckle backed by `AsyncLocal<T>` — writes via child-scope setter mutate ambient AsyncLocal for rest of async flow. No `try/finally` restore.

Consequence: on return from delegate, outer-request `DbContext`, `UserManager`, `ICurrentUserService`, audit writer, any tenant-scoped service see tenant B (inner context) not outer request tenant. Any data written after delegate land under wrong tenant.

`GrantTenantAccess.cs:181` already issue compensating re-entrant call — symptom of this confusion.

### Attack / failure mode
Latent. No current handler write data *after* `ExecuteInTenantScopeAsync` return, so no exploit today. But one-commit-away cross-tenant write-corruption bug: soon as future handler run inner-tenant op then outer-tenant write (audit row, telemetry, follow-up `SaveChanges`), writes land wrong tenant.

Also, if delegate throw, AsyncLocal left mutated for rest of HTTP request.

### Fix
```csharp
public async Task ExecuteInTenantScopeAsync(IdmtTenantInfo target, Func<IServiceProvider, Task> operation)
{
    using var scope = serviceScopeFactory.CreateScope();
    var setter = scope.ServiceProvider.GetRequiredService<IMultiTenantContextSetter>();
    var accessor = scope.ServiceProvider.GetRequiredService<IMultiTenantContextAccessor>();
    var previous = accessor.MultiTenantContext;
    try
    {
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo> { TenantInfo = target };
        await operation(scope.ServiceProvider);
    }
    finally
    {
        setter.MultiTenantContext = previous;
    }
}
```

Document invariant: outer request tenant context transient unstable during delegate, but restored before delegate task complete.

### Files to modify
- `Idmt.Plugin/Services/TenantOperationService.cs`

### Verification
- Unit test: call `ExecuteInTenantScopeAsync` where delegate throw; assert outer-scope `accessor.MultiTenantContext` equal pre-call value.
- Unit test: same, delegate return normal; assert restoration.
- Unit test: delegate mutate tenant B, write entity, then outer scope write another entity — assert each entity persist under intended tenant filter.

### Why this must be Phase 0
Phase 1 rewrite `GrantTenantAccess` and `ConfirmEmail` / `ResetPassword`, all route through `ExecuteInTenantScopeAsync`. Ship Phase 1 on broken service cement compensating-action pattern into new code paths. Fix service first.

---

## Finding C2 (Critical) — Admin endpoints guard by `RequireSysUser` not `RequireSysAdmin`

### Files
- `Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs:426-432`
- `Idmt.Plugin/Features/AdminEndpoints.cs:14`
- `Idmt.Plugin/Features/Admin/DeleteTenant.cs:74`
- `Idmt.Plugin/Features/Admin/CreateTenant.cs`
- `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs:239`
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs:116`
- `Idmt.Plugin/Features/Admin/GetAllTenants.cs:91`
- `Idmt.Plugin/Features/Admin/GetUserTenants.cs:102`

### Detail
`RequireSysAdminPolicy` defined in `IdmtAuthOptions` but **never referenced**. `RequireSysUserPolicy = SysAdmin OR SysSupport`. Admin endpoints group in `AdminEndpoints.cs:14` use `RequireSysUser`, so SysSupport accounts can create/delete tenants and grant self tenant access.

### Attack
SysSupport user:
1. `POST /admin/tenants` → create new tenant.
2. `POST /admin/tenant-access/grant` with `{ userId: self, tenantIdentifier: "target-tenant" }` → grant self access to any existing tenant.
3. Log into that tenant as role assigned during grant (often TenantAdmin).

Full privilege escalation from Support tier to arbitrary tenant admin.

### Fix
1. **Tenant lifecycle** (`CreateTenant`, `DeleteTenant`) and **tenant-access mutations** (`GrantTenantAccess`, `RevokeTenantAccess`) must require `RequireSysAdminPolicy`.
2. **Listing endpoints** (`GetAllTenants`, `GetUserTenants`) may stay on `RequireSysUserPolicy` (SysSupport has legit read access).
3. Add self-grant guard in `GrantTenantAccess`: reject when `request.UserId == currentUserService.UserId`.
4. Apply policy **both** at group level (`AdminEndpoints.cs`) **and** endpoint level (`.RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)` on each `Map*Endpoint`) for defense-in-depth. Close M6 gap (endpoints like `CreateTenant.cs:132-159` rely on group-level auth only today).

### Files to modify
- `Idmt.Plugin/Features/AdminEndpoints.cs` — split group or add sub-group for SysAdmin-only endpoints.
- `Idmt.Plugin/Features/Admin/CreateTenant.cs`
- `Idmt.Plugin/Features/Admin/DeleteTenant.cs`
- `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs`
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs`
- `Idmt.Plugin/Features/Admin/GetAllTenants.cs`
- `Idmt.Plugin/Features/Admin/GetUserTenants.cs`

### Verification
- Integration test: seed SysSupport user; try `POST /admin/tenants` → expect 403.
- Integration test: SysSupport → `POST /admin/tenant-access/grant` → 403.
- Integration test: SysSupport → `GET /admin/tenants` → 200.
- Integration test: SysAdmin grant-access where `userId == caller.userId` → 403 with `IdmtErrors.General.SelfTarget`.
- Integration test: SysAdmin → `POST /admin/tenants` → 201.

### Why Phase 0
Active privilege-escalation path. Ship within hour. No arch dependency; work under current shadow-row model and Phase 1 canonical model.

---

## Phase 0 implementation order

1. **N2 first.** Wrap delegate in `try/finally`. Ship + test. Nothing else depend on phase 0 state except Phase 1.
2. **C2 second.** Mechanical policy rename + endpoint-level redundancy + self-grant guard. Ship independent.

Both PR parallel if work split across contributors.

---

## Phase 0 done-criteria

- `TenantOperationService.ExecuteInTenantScopeAsync` restore ambient tenant context on normal return and on throw.
- All SysAdmin-only admin endpoints reject SysSupport callers with 403.
- `GrantTenantAccess` reject self-target with domain error.
- All admin endpoints have endpoint-level `.RequireAuthorization` plus group-level.
- `dotnet test Idmt.slnx` pass.
- `dotnet format Idmt.slnx --verify-no-changes` pass.
- `dotnet build Idmt.slnx` with warnings-as-errors pass.

Phase 1 begin when all above satisfied.