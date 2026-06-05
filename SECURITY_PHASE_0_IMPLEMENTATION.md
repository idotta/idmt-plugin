# Phase 0 — Implementation Plan

Derived from `SECURITY_PHASE_0_FOUNDATION.md` with amendments from the architect-critic pass. Safe to execute. No Phase 1 / canonical-migration work here.

---

## Context

IDMT plugin at `/home/iuri/code/idmt-plugin`. Two Critical findings ship in Phase 0:
- **N2** — `TenantOperationService.ExecuteInTenantScopeAsync` mutates AsyncLocal-backed ambient tenant context without restoring on exit. Latent cross-tenant write corruption. Blocks Phase 1 rewrite of `GrantTenantAccess`, `ConfirmEmail`, `ResetPassword` (all route through this service).
- **C2** — Admin endpoints guarded by `RequireSysUserPolicy` (SysAdmin OR SysSupport). SysSupport can create/delete tenants and grant self tenant access → active privilege escalation today.

Critic amendments applied below:
1. Fix snippet in Phase 0 doc uses wrong signature — actual `TenantOperationService` returns `ErrorOr<T>`, takes `string tenantIdentifier`, has `requireActive` param, constructs `MultiTenantContext<IdmtTenantInfo>` positionally.
2. Endpoint-level auth survey: only `CreateTenant` lacks `.RequireAuthorization` at endpoint level; others already have `RequireSysUserPolicy` endpoint-level.
3. AND-semantics trap: minimal-API `MapGroup(...).RequireAuthorization(A)` plus per-endpoint `.RequireAuthorization(B)` accumulates — caller must satisfy both. Strategy: keep group on `RequireSysUser`, override mutation endpoints to `RequireSysAdmin`, keep listing endpoints on `RequireSysUser`.
4. Self-grant guard must run before any DB lookup to avoid timing oracle.
5. Verification must cover nested delegates, concurrent delegates, both auth schemes (cookie + bearer).

Finbuckle premise confirmed: `IMultiTenantContextAccessor<T>` is Singleton backed by `AsyncLocalMultiTenantContextAccessor<T>` (AsyncLocal<T>). `IMultiTenantContextSetter` resolves to the same instance. Mutation from any scope mutates ambient flow.

---

## Prerequisites

- Branch: `v1-improvements` (current).
- No migrations or DB changes in Phase 0.
- Consumers unaffected by Phase 0 API changes (signature of `TenantOperationService` unchanged; policy/error additions are backward-compatible for non-SysSupport callers).

---

## Tasks

### Task 1 — N2: `TenantOperationService` try/finally context restore

**File**: `Idmt.Plugin/Services/TenantOperationService.cs`

**Change** (only the generic overload — the non-generic overload at line 39-45 delegates to the generic, so one edit covers both):

Replace the body of `ExecuteInTenantScopeAsync<T>` (lines 11-37) with:

```csharp
public async Task<ErrorOr<T>> ExecuteInTenantScopeAsync<T>(
    string tenantIdentifier,
    Func<IServiceProvider, Task<ErrorOr<T>>> operation,
    bool requireActive = true)
{
    using var scope = serviceProvider.CreateScope();
    var provider = scope.ServiceProvider;

    var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
    var tenantInfo = await tenantStore.GetByIdentifierAsync(tenantIdentifier);

    if (tenantInfo is null)
    {
        return IdmtErrors.Tenant.NotFound;
    }

    if (requireActive && !tenantInfo.IsActive)
    {
        return IdmtErrors.Tenant.Inactive;
    }

    var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
    var accessor = provider.GetRequiredService<IMultiTenantContextAccessor>();
    var previous = accessor.MultiTenantContext;
    try
    {
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
        return await operation(provider);
    }
    finally
    {
        setter.MultiTenantContext = previous;
    }
}
```

Key points:
- `using` statement on scope retained (unchanged).
- `IMultiTenantContextAccessor` resolved from the same child scope as the setter — both are Singletons, so they point to the same AsyncLocal slot.
- `previous` captured *after* successful tenant resolution (if the tenant doesn't exist or is inactive, no mutation happens, no restore needed).
- Positional ctor `new MultiTenantContext<IdmtTenantInfo>(tenantInfo)` matches existing code (line 34 pre-fix).
- `finally` runs on both normal return and throw; restores ambient state.
- Non-generic overload at lines 39-45 untouched — it delegates to this one.

**Add XML doc on the method** documenting invariants:
- The ambient `IMultiTenantContextAccessor.MultiTenantContext` is transiently set to `tenantIdentifier`'s context during the delegate; it is restored to its pre-call value before this task completes.
- AsyncLocal is flow-scoped, not per-task. Do **not** invoke concurrent `ExecuteInTenantScopeAsync` calls on the same async flow (e.g., `Task.WhenAll(ExecuteInTenantScopeAsync(a, ...), ExecuteInTenantScopeAsync(b, ...))`) — the two calls race on the AsyncLocal slot and the "previous" capture becomes undefined. Only nested (sequential) calls are safe.

### Task 2 — N2 unit tests

**New file**: `tests/Idmt.UnitTests/Services/TenantOperationServiceTests.cs` (or extend if exists).

Tests to add:
1. **Sequential restore on normal return**: pre-populate accessor with tenant X context; call `ExecuteInTenantScopeAsync("tenant-y", _ => Ok)`; assert post-call accessor is tenant X.
2. **Sequential restore on throw**: same setup; delegate throws; outer catch; assert post-call accessor is tenant X.
3. **Restore from null pre-context**: accessor starts null/empty; call the method; delegate observes tenant Y; assert post-call accessor is null/empty.
4. **Nested calls unwind correctly**: outer tenant X → call method with tenant Y → delegate calls method again with tenant Z → assert delegate-inside-delegate observes Z, return to outer-delegate observes Y, return to test observes X.
5. **Delegate observes inner tenant**: delegate reads `IMultiTenantContextAccessor.MultiTenantContext.TenantInfo?.Identifier` and asserts it equals `"tenant-y"`.
6. **Tenant-not-found short-circuit doesn't mutate context**: pre-context X; call with nonexistent tenant; delegate never runs; post-context still X.
7. **Tenant-inactive + requireActive=true short-circuit doesn't mutate context**: similar.
8. **Concurrent-delegate limitation is documented, not tested**: deliberately do NOT add a concurrent-`Task.WhenAll` test — AsyncLocal race behavior under `WhenAll` is implementation-defined and flaky in CI. The XML-doc invariant (Task 1) forbids this usage; a test that locks in racy behavior would create false confidence. Instead, add a short unit test asserting that the XML doc exists (via reflection on the method's `[EditorBrowsable]` or a string grep in a build-time test) — optional, low value.

Use `Finbuckle.MultiTenant.InMemoryStore` or a minimal fake `IMultiTenantStore<IdmtTenantInfo>`. Resolve `IMultiTenantContextAccessor`, `IMultiTenantContextSetter` via a `ServiceCollection` with `services.AddMultiTenant<IdmtTenantInfo>()` to ensure Singleton/AsyncLocal behavior is realistic.

### Task 3 — C2 policy matrix comment

**File**: `Idmt.Plugin/Features/AdminEndpoints.cs`

**Change**: leave the group `.RequireAuthorization(IdmtAuthOptions.RequireSysUserPolicy)` as-is. Add a comment block above it documenting the AND-semantics policy design:

```csharp
// Group policy: RequireSysUser (SysAdmin OR SysSupport) — minimum bar for /admin/*.
// Per-endpoint policies further restrict mutations to SysAdmin only.
// Due to ASP.NET Core minimal-API AND-semantics on .RequireAuthorization,
// an endpoint with both group=SysUser + endpoint=SysAdmin requires SysAdmin (stricter wins).
```

### Task 4 — C2: `CreateTenant` add endpoint-level SysAdmin auth

**File**: `Idmt.Plugin/Features/Admin/CreateTenant.cs`

**Change** at the `MapCreateTenantEndpoint` method (~line 132-159):

Add (position at the end of the endpoint builder chain, matching the pattern in `DeleteTenant.cs:74`):

```csharp
.RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)
```

### Task 5 — C2: promote mutation endpoints from SysUser → SysAdmin

Three endpoints currently have endpoint-level `.RequireAuthorization(IdmtAuthOptions.RequireSysUserPolicy)`; change each to `RequireSysAdminPolicy`:

- `Idmt.Plugin/Features/Admin/DeleteTenant.cs:74`
- `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs:239`
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs:116`

Leave these two on `RequireSysUserPolicy` (listing, SysSupport has legitimate read access):

- `Idmt.Plugin/Features/Admin/GetAllTenants.cs:91`
- `Idmt.Plugin/Features/Admin/GetUserTenants.cs:102`

### Task 6 — C2 self-grant guard

**File**: `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs`

**Actual handler signature** (verified):
```csharp
public async Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, DateTimeOffset? expiresAt = null, CancellationToken cancellationToken = default)
```
Ctor at line 33-40 does **not** inject `ICurrentUserService`. Must add it.

**Ctor change** — add `ICurrentUserService currentUserService` parameter:
```csharp
internal sealed class GrantTenantAccessHandler(
    IdmtDbContext dbContext,
    UserManager<IdmtUser> userManager,
    IMultiTenantStore<IdmtTenantInfo> tenantStore,
    ITenantOperationService tenantOps,
    TimeProvider timeProvider,
    ICurrentUserService currentUserService,    // <-- ADD
    ILogger<GrantTenantAccessHandler> logger
) : IGrantTenantAccessHandler
```

**Guard placement** — top of `HandleAsync`, before any DB/tenant-store lookup (current body starts at line 44 with `expiresAt` validation; place guard before that):

```csharp
public async Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, DateTimeOffset? expiresAt = null, CancellationToken cancellationToken = default)
{
    // Fail closed: unauthenticated context must not reach this handler. If it does, refuse.
    if (currentUserService.UserId is not Guid callerId)
    {
        return IdmtErrors.Auth.Unauthorized;
    }
    if (callerId == userId)
    {
        return IdmtErrors.General.SelfTarget;
    }

    if (expiresAt.HasValue && expiresAt.Value <= timeProvider.GetUtcNow())
    {
        return Error.Validation("ExpiresAt", "Expiration date must be in the future");
    }

    // ... existing DB / tenant-scope execution
}
```

Null-branch fails closed (401) — don't silently fall through. Self-match returns 403 `General.SelfTarget`. Guard executes before any DB or tenant lookup → no timing oracle.

### Task 7 — C2 error code + endpoint-delegate mapping

**File**: `Idmt.Plugin/Errors/IdmtErrors.cs`

`General` nested class already exists (holds `Unexpected`). Add alongside:

```csharp
public static Error SelfTarget => Error.Forbidden(
    code: "General.SelfTarget",
    description: "This operation cannot target the caller.");
```

**File**: `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs:218-240`

Current delegate signature: `Task<Results<Ok, BadRequest, NotFound, InternalServerError>>`. Switch at line 230 maps only `Validation` and `NotFound`. `Forbidden` falls through to `InternalServerError`. Must update:

```csharp
public static RouteHandlerBuilder MapGrantTenantAccessEndpoint(this IEndpointRouteBuilder endpoints)
{
    return endpoints.MapPost("/users/{userId:guid}/tenants/{tenantIdentifier}",
        async Task<Results<Ok, BadRequest, NotFound, ForbidHttpResult, UnauthorizedHttpResult, InternalServerError>> (
            Guid userId,
            string tenantIdentifier,
            [FromBody] GrantAccessRequest request,
            IGrantTenantAccessHandler handler,
            CancellationToken cancellationToken) =>
    {
        var result = await handler.HandleAsync(userId, tenantIdentifier, request.ExpiresAt, cancellationToken);
        if (result.IsError)
        {
            return result.FirstError.Type switch
            {
                ErrorType.Validation => TypedResults.BadRequest(),
                ErrorType.NotFound => TypedResults.NotFound(),
                ErrorType.Forbidden => TypedResults.Forbid(),
                ErrorType.Unauthorized => TypedResults.Unauthorized(),
                _ => TypedResults.InternalServerError(),
            };
        }
        return TypedResults.Ok();
    })
    .RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)  // promoted per Task 5
    .WithSummary("Grant user access to a tenant");
}
```

`Forbidden` → 403 and `Unauthorized` → 401 (covers the null-`UserId` fail-closed branch in Task 6).

**Bonus — while in the file at `RevokeTenantAccess.cs:107-112`**: the delegate there also lacks a `Forbidden` branch. Add the same `Forbidden`/`Unauthorized` mappings + union entries for consistency. Not strictly required for Phase 0 exploit closure, but avoids a known-stale mapping for future handlers.

`Forbidden` is correct for self-target (authenticated, syntactically valid, policy-denied); `Unauthorized` is correct when the caller's `UserId` cannot be resolved.

### Task 8 — C2 integration tests

**New or existing**: `tests/Idmt.BasicSample.Tests/AdminEndpointsTests.cs` (or split per endpoint).

Seed: test tenant store with two tenants (`tenant-a`, `tenant-b`); users: one SysAdmin, one SysSupport, one regular user.

Cases:
1. **SysSupport blocked from mutations (cookie auth)**:
   - `POST /admin/tenants` (create) → 403.
   - `DELETE /admin/tenants/{id}` → 403.
   - `POST /admin/tenant-access/grant` → 403.
   - `POST /admin/tenant-access/revoke` → 403.
2. **SysSupport allowed on listings (cookie auth)**:
   - `GET /admin/tenants` → 200.
   - `GET /admin/tenants/{tenantId}/users` (or equivalent `GetUserTenants` path) → 200.
3. **SysAdmin allowed on everything (cookie auth)**:
   - All six endpoints → 2xx with valid payload.
4. **Bearer path parity** — re-run 1-3 using bearer tokens to verify `CookieOrBearerScheme` selector doesn't bypass the policy.
5. **Self-grant** — SysAdmin calls `POST /admin/tenant-access/grant` with `userId == caller.userId` → 403 with body error code `General.SelfTarget`. Assert via mocked `ITenantOperationService` that `ExecuteInTenantScopeAsync` was **never called** — proves the guard fires before any tenant-scope entry (no timing oracle via DB latency).
5a. **Unauthenticated handler call** (unit test, not integration) — mock `ICurrentUserService.UserId` returning `null`; call `HandleAsync` directly → returns `IdmtErrors.Auth.Unauthorized`. Asserts fail-closed on null caller.
6. **Cross-grant still works** — SysAdmin grants a different user → 200.
7. **Listing regression** — SysAdmin gets `GetAllTenants` → 200 (confirms the stricter mutation policy didn't accidentally demote the listing).

---

## Implementation order

1. **Task 1** (N2 code).
2. **Task 2** (N2 tests).
3. **Task 7** (error code — prerequisite for Tasks 5/6/8).
4. **Task 6** (self-grant guard) + **Task 4** (CreateTenant endpoint-level auth) + **Task 5** (policy promotion). These three can land together.
5. **Task 3** (comment on AdminEndpoints).
6. **Task 8** (integration tests).

One PR per cluster: PR1 = Tasks 1+2 (N2). PR2 = Tasks 3+4+5+6+7+8 (C2 with tests).

---

## Files to modify

- `Idmt.Plugin/Services/TenantOperationService.cs` — try/finally wrapper (Task 1).
- `Idmt.Plugin/Features/AdminEndpoints.cs` — doc comment (Task 3).
- `Idmt.Plugin/Features/Admin/CreateTenant.cs` — add endpoint-level SysAdmin auth (Task 4).
- `Idmt.Plugin/Features/Admin/DeleteTenant.cs` — promote to SysAdmin (Task 5).
- `Idmt.Plugin/Features/Admin/GrantTenantAccess.cs` — promote to SysAdmin + self-grant guard (Tasks 5, 6).
- `Idmt.Plugin/Features/Admin/RevokeTenantAccess.cs` — promote to SysAdmin (Task 5).
- `Idmt.Plugin/Errors/IdmtErrors.cs` — `General.SelfTarget` error (Task 7).
- `tests/Idmt.UnitTests/Services/TenantOperationServiceTests.cs` — N2 tests (Task 2).
- `tests/Idmt.BasicSample.Tests/AdminEndpointsTests.cs` — C2 integration tests (Task 8).

---

## Verification

### Commands

```bash
dotnet build Idmt.slnx
dotnet test Idmt.slnx
dotnet format Idmt.slnx --verify-no-changes
```

All must pass with warnings-as-errors.

### Acceptance criteria

- `TenantOperationService.ExecuteInTenantScopeAsync` restores ambient `IMultiTenantContextAccessor.MultiTenantContext` on normal return and on throw (sequential + nested).
- `CreateTenant`, `DeleteTenant`, `GrantTenantAccess`, `RevokeTenantAccess` reject SysSupport callers with 403 via both cookie and bearer auth.
- `GetAllTenants`, `GetUserTenants` continue to accept SysSupport callers.
- `GrantTenantAccess` with `request.UserId == caller.UserId` returns 403 `General.SelfTarget` before any DB lookup (assert via mocked `ITenantOperationService` — ensure it was never called).
- Full suite green: `dotnet test` + format + warnings-as-errors build.

---

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| `IMultiTenantContextSetter` / `IMultiTenantContextAccessor` behaviour changes in a future Finbuckle major | Tests cover concrete behaviour (Task 2 #4, #5) — would detect regression. |
| `currentUserService.UserId` is `Guid?` vs `Guid`; null-coalescing trap | Use `is Guid callerId &&` pattern (see Task 6 snippet) — implicitly guards null. |
| Consumers depend on `RequireSysUserPolicy` at mutation endpoints (breaking change) | Branch `v1-improvements` signals v1 cut. Tag this as a breaking change in CHANGELOG / release notes. Consumers who legitimately granted SysSupport mutation rights must re-provision those accounts as SysAdmin. If an opt-out escape hatch is required for gradual rollout, expose an `IdmtOptions.Admin.AllowSysSupportMutations = false` flag (default false, opt-in to legacy behavior, deprecated). Not implementing the flag in Phase 0 unless the product owner requests it. |
| Self-grant guard's error type mismatch (Forbidden vs Validation) | Explicit choice of `Error.Forbidden` in Task 7; document the rationale in the error XML doc. |
| Phase 0 ships before N3 / partial-failure window is fixed | Intentional — N3 is resolved in Phase 1 (rewrite of `GrantTenantAccess`). Phase 0 does not regress N3; the compensating call at `GrantTenantAccess.cs:181` continues to work, and under N2's fix its context is correctly scoped. |

---

## Out of scope for Phase 0

Do **not** include in this implementation:
- Canonical-user migration (Phase 1).
- `GrantTenantAccess` handler rewrite beyond the self-grant guard (Phase 1).
- Any token / revocation work (Phase 2).
- Middleware reordering (Phase 3).
- Rate limiting or default changes (Phase 3).
- Any additional Lows / Mediums that don't appear above (Phase 4).
