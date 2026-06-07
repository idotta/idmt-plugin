# Plan: rectify IdmtDbContext base class and confirm IdmtRole tenancy

Status: proposed
Date: 2026-06-06
Owner: persistence (task 03 follow-up)
Scope: `Idmt.AspNetCore/Persistence/IdmtDbContext.cs`, its tests, and the docs/ADRs that describe the persistence base class and `IdmtRole` tenancy.

## TL;DR

`IdmtDbContext` currently derives from Finbuckle's `MultiTenantIdentityDbContext<IdmtUser, IdmtRole, Guid>`, which stamps every Identity entity multi-tenant, and then manually rips that stamping back out for the whole identity set via a private `DeTenant()` method. The de-tenanting outcome is correct, but the mechanism is wrong: it depends on undocumented Finbuckle internals (the `"Finbuckle:MultiTenant"` annotation string, the shadow `TenantId` property name, index-removal ordering) and inverts the model (stamp everything, then subtract).

Replace the base with `IdentityDbContext<IdmtUser, IdmtRole, Guid>` and implement `IMultiTenantDbContext` directly. Identity tables are then global by construction (nothing to undo), `IdmtRole` stays a plain entity with an explicit `TenantId` scoped by explicit query, and consumers can still add their own `[MultiTenant]` application entities that Finbuckle stamps and filters. The existing model tests stay green.

`IdmtRole` stays manual-scoped (not Finbuckle-managed). This is not a preference; it is forced by the issuance flow (see Evidence).

## Evidence

The investigation that produced this plan traced every role read/write in the v2 tree and in the consumer repo (`preditor-cloud`), and read the locked issuance design.

1. The token endpoint has no ambient Finbuckle tenant. `docs/v2/06-tenant-access-gate.md:124-129`: "the token endpoint runs in a pipeline scope where the ambient tenant is often unset, so the gate must take the tenant as an explicit argument rather than read it from `IMultiTenantContextAccessor`." Confirmed also by `docs/v2/05-multitenancy-audience.md` (the audience handler skips the OpenIddict protocol endpoints because no tenant is resolved there) and gate 4 in the spike.

2. Issuance reads `IdmtRole` at that no-tenant endpoint. `docs/v2/06-tenant-access-gate.md:197-209` ("Claims and second-factor state at issuance"): "The same `ProcessSignInContext` handler that runs the gate is where IDMT projects its issuance claims ... For the resolved tenant the handler projects the user's `IdmtRole` assignments as role claims on the principal." `docs/v2/02-core-domain.md:252-257` says the same: "At issuance the resolved user's `IdmtRole` assignments for the resolved tenant are written into the token as role claims."

3. Therefore a Finbuckle query filter on `IdmtRole` (`EF.Property<string>(r, "TenantId") == TenantInfo.Id`) would evaluate against a null `TenantInfo` at issuance and return zero rows. Every issued token would carry empty tenant-role claims, and `RequireTenantManager` / `RequireTenantMember` would always fail. Finbuckle-auto on `IdmtRole` is unsafe. Manual scoping (`.Where(r => r.TenantId == tenantIdentifier)`, the same explicit-argument pattern the `ITenantAccessGate` already uses) is required.

4. The base class itself is not mandated anywhere. ADR-0001 and ADR-0002 lock the canonical-identity outcome (global `IdmtUser`, per-tenant `IdmtRole`) but never require `MultiTenantIdentityDbContext`. `docs/v2/03-persistence-and-contexts.md` describes the app context as extending `MultiTenantDbContext` (not the Identity variant) and never describes the stamp-then-undo approach the current code uses. The base-class choice is open implementation surface.

5. Finbuckle v10.0.3 source confirms the clean path. `MultiTenantIdentityDbContext` hard-calls `.IsMultiTenant().AdjustUniqueIndexes()` on all Identity entities in its `OnModelCreating` with no opt-out, which is why the current code must rip it out. Enforcement is not tied to that base: the read filter comes from per-entity `.IsMultiTenant()`, and the write stamping comes from the extension `this.EnforceMultiTenant()` called inside a `SaveChanges` override. Both are constrained on the `IMultiTenantDbContext` interface, not on any concrete base class. Finbuckle's own docs state implementing the interface is "more flexible than deriving from `MultiTenantDbContext`."

6. Consumers depend on the base providing Finbuckle enforcement for their own entities. `preditor-cloud/src/Persistence/AppDbContext.cs` derives from `IdmtDbContext` and marks its own entities (`Asset`, `Measurement`, etc.) `IsMultiTenant()`. So the base must keep providing `ConfigureMultiTenant()` + `EnforceMultiTenant()` for consumer-added `[MultiTenant]` entities, even though IDMT marks none of its own.

### Note on a rejected alternative

An earlier draft of this analysis proposed making `IdmtRole` Finbuckle-managed, partly because `preditor-cloud`'s one role read (`GetTenantUsers.cs`) has no explicit `TenantId` filter and relies on ambient filtering under v1. That was wrong: it weighted the minimal spike (which never projects roles) and a v1 consumer over the v2 locked issuance design (point 2), where role reads happen with no ambient tenant. The v1 consumer concern is a migration footnote (see Migration caveat), not a design driver.

## The design

`IdmtDbContext` derives from `IdentityDbContext<IdmtUser, IdmtRole, Guid>` and implements `IMultiTenantDbContext`. This gives Identity's schema for free, leaves all Identity tables unstamped (global by construction), keeps `IdmtRole`'s tenant scoping as an explicit column scoped by explicit queries, and provides Finbuckle stamping and filtering for any `[MultiTenant]` application entity a consumer adds by extending the context.

The coherent split this produces:

- IDMT identity and gate tables (`IdmtUser`, `IdmtRole`, `TenantAccess`, `ClientTenantAccess`, the Identity join tables) are not Finbuckle-managed. They are read at the no-ambient-tenant token endpoint via explicit `(userId, tenant)` / `(role.TenantId == tenant)` queries.
- Consumer application tables marked `[MultiTenant]` / `IsMultiTenant()` are Finbuckle-managed. They are read in tenant-resolved HTTP requests, never at the token endpoint, so the ambient-tenant filter is correct for them.

### Target IdmtDbContext

```csharp
using Finbuckle.MultiTenant.Abstractions;                    // ITenantInfo, IMultiTenantContextAccessor
using Finbuckle.MultiTenant.EntityFrameworkCore;            // IMultiTenantDbContext, TenantMismatchMode, TenantNotSetMode
using Finbuckle.MultiTenant.EntityFrameworkCore.Extensions; // EnforceMultiTenant, ConfigureMultiTenant, IsMultiTenant
using Idmt.Core.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;     // IdentityDbContext
using Microsoft.EntityFrameworkCore;

namespace Idmt.AspNetCore.Persistence;

/// <summary>
/// The application and identity context. Derives from <see cref="IdentityDbContext{TUser, TRole, TKey}"/>
/// and implements <see cref="IMultiTenantDbContext"/> so it keeps the IDMT identity model global while
/// still giving consumers Finbuckle stamping and filtering for their own <c>[MultiTenant]</c> entities.
/// </summary>
/// <remarks>
/// The IDMT identity model is global by construction: the base is the plain Identity context, so no
/// Identity table is Finbuckle-stamped and there is nothing to undo. <see cref="IdmtUser"/> is the
/// global canonical identity. <see cref="IdmtRole"/> is per-tenant via an explicit, declared
/// <c>TenantId</c> column scoped by explicit query, NOT by a Finbuckle filter: issuance projects a
/// user's role assignments into the token at the OpenIddict token endpoint, which runs with no ambient
/// tenant (see 06-tenant-access-gate.md). A Finbuckle filter there would compare against a null tenant
/// and return no rows. Consumers extend this context and mark their own tenant-scoped tables
/// <c>[MultiTenant]</c> / <c>IsMultiTenant()</c>; those are stamped on save by the
/// <see cref="EnforceMultiTenant"/> call below and filtered on read by their own marking. Not sealed.
/// </remarks>
public class IdmtDbContext : IdentityDbContext<IdmtUser, IdmtRole, Guid>, IMultiTenantDbContext
{
    /// <summary>Used by AddDbContext&lt;IdmtDbContext&gt;.</summary>
    public IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions<IdmtDbContext> options)
        : this(multiTenantContextAccessor, (DbContextOptions)options)
    {
    }

    /// <summary>
    /// Used by derived consumer contexts: AddDbContext&lt;TConsumer&gt; yields
    /// DbContextOptions&lt;TConsumer&gt;, which only a non-generic base constructor accepts.
    /// </summary>
    protected IdmtDbContext(
        IMultiTenantContextAccessor multiTenantContextAccessor,
        DbContextOptions options)
        : base(options)
    {
        TenantInfo = multiTenantContextAccessor.MultiTenantContext.TenantInfo;
    }

    public ITenantInfo? TenantInfo { get; }
    public TenantMismatchMode TenantMismatchMode => TenantMismatchMode.Throw;
    public TenantNotSetMode TenantNotSetMode => TenantNotSetMode.Throw;

    /// <summary>The user-to-tenant edge the issuance gate queries by (UserId, TenantId).</summary>
    public DbSet<TenantAccess> TenantAccess => Set<TenantAccess>();

    /// <summary>The machine-client-to-tenant edge the client-credentials gate queries.</summary>
    public DbSet<ClientTenantAccess> ClientTenantAccess => Set<ClientTenantAccess>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder); // Identity schema. No Identity table is stamped multi-tenant.

        builder.Entity<IdmtUser>(entity =>
        {
            entity.HasIndex(u => u.IsActive);
            entity.HasIndex(u => u.NormalizedEmail).IsUnique(); // globally unique, no TenantId
        });

        builder.Entity<IdmtRole>(entity =>
        {
            // Per-tenant uniqueness on the explicit TenantId column. NOT Finbuckle-managed:
            // no IsMultiTenant(), so no query filter is applied (issuance reads roles with
            // no ambient tenant; callers scope by explicit .Where(r => r.TenantId == tenant)).
            entity.HasIndex(r => new { r.TenantId, r.Name }).IsUnique();
        });

        builder.Entity<TenantAccess>(entity =>
        {
            entity.HasKey(ta => ta.Id);
            entity.HasIndex(ta => new { ta.UserId, ta.TenantId }).IsUnique();
            entity.HasIndex(ta => ta.TenantId);
            entity.HasIndex(ta => ta.IsActive);
            // ExpiresAt stays DateTimeOffset?; the gate evaluates expiry in memory (SQLite).
        });

        builder.Entity<ClientTenantAccess>(entity =>
        {
            entity.HasKey(ca => ca.Id);
            entity.HasIndex(ca => new { ca.ClientId, ca.TenantId }).IsUnique();
            entity.HasIndex(ca => ca.TenantId);
            entity.HasIndex(ca => ca.IsActive);
        });

        // Configure any [MultiTenant]-attributed entities a consumer adds. Consumers that mark
        // entities with IsMultiTenant() directly in their own configuration do not depend on this;
        // it covers the attribute-based path and matches Finbuckle's own base-context behavior.
        builder.ConfigureMultiTenant();
    }

    // Finbuckle write-side enforcement for consumer [MultiTenant] entities. EF calls the bool
    // overloads internally, so the enforcement belongs there. IDMT marks none of its own entities
    // multi-tenant, so EnforceMultiTenant is a no-op for IDMT's tables and never throws at the
    // no-ambient-tenant token endpoint.
    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        this.EnforceMultiTenant();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override async Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess,
        CancellationToken cancellationToken = default)
    {
        this.EnforceMultiTenant();
        return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken)
            .ConfigureAwait(false);
    }
}
```

Net code change: delete the `DeTenant()` method, the identity-type de-tenant loop, and the `MultiTenantIdentityDbContext` base; add the `IMultiTenantDbContext` members, the protected non-generic `DbContextOptions` constructor (for consumer derivation), the `ConfigureMultiTenant()` call, and the two `SaveChanges` overrides. The per-entity configuration blocks are unchanged.

Confirmed namespaces (Finbuckle 10.0.3): `ITenantInfo` and `IMultiTenantContextAccessor` are in `Finbuckle.MultiTenant.Abstractions`; `IMultiTenantDbContext`, `TenantMismatchMode`, and `TenantNotSetMode` are in `Finbuckle.MultiTenant.EntityFrameworkCore`; the extension methods `IsMultiTenant`, `ConfigureMultiTenant`, and `EnforceMultiTenant` are in `Finbuckle.MultiTenant.EntityFrameworkCore.Extensions`.

### Why join tables can stay global

`IdentityUserRole<Guid>` links a global `IdmtUser` to a per-tenant `IdmtRole`. The join row needs no `TenantId`: each role has a globally unique `Id` (Guid), so `UserRole(UserId, RoleId)` is unambiguous, and the `(TenantId, Name)` unique index distinguishes same-named roles across tenants. Issuance projects roles by joining user-roles to roles and filtering `role.TenantId == requestedTenant` explicitly.

## Test impact

The existing assertions in `tests/Idmt.AspNetCore.Tests/PersistenceModelTests.cs` stay green unchanged, because the new design produces the same model shape the current rip-out produces:

- `Identity_entities_are_de_tenanted` (IdmtUser, IdentityUserRole, IdentityUserClaim, IdentityUserToken have no `"Finbuckle:MultiTenant"` annotation and no `TenantId`): passes, since the base never stamps them.
- `Role_keeps_its_explicit_tenant_id_but_is_not_finbuckle_managed`: passes, since `IdmtRole` is not marked and keeps its declared `TenantId`.
- `OpenIddict_token_entity_has_no_TenantId`, `App_context_exposes_the_access_edges`: unaffected.

Add two tests to lock the consumer-extension contract that the base swap must preserve:

- A test double context deriving from `IdmtDbContext` that marks a sample entity `[MultiTenant]` (or `IsMultiTenant()`): assert the entity carries the `"Finbuckle:MultiTenant"` annotation and a `TenantId` property after model build (proves `ConfigureMultiTenant` / the marking still applies under the new base).
- A save test: with a resolved `TenantInfo`, adding that sample entity and saving stamps `TenantId` from the ambient tenant (proves `EnforceMultiTenant` is wired through the `SaveChanges` overrides).

The behavioral gate-4 assertions (issuance with no ambient tenant; role projection returns the tenant's roles) remain covered by the integration suite (`docs/v2/14-test-suite.md`).

## Documentation and ADR rectifications

The role-tenancy decision in the docs is correct; the base-class mechanism and one stale ADR list need fixing.

1. `Idmt.AspNetCore/Persistence/IdmtDbContext.cs` (code + XML doc). Replace per the design above. The current XML doc's gate-4 reasoning ("token endpoint issues in a pipeline scope with no ambient tenant, so those filters would hide the rows the gate and claims projection must read") is correct and should be kept; only the mechanism description changes (from "derive from `MultiTenantIdentityDbContext` and de-tenant" to "derive from `IdentityDbContext` and implement `IMultiTenantDbContext`; nothing is stamped, nothing is undone").

2. `docs/v2/03-persistence-and-contexts.md`. This is the main correction. It currently says the application context "extends Finbuckle's `MultiTenantDbContext`" (around lines 8-11, 42, 100-103) and leaves the product `OnModelCreating` unspecified. Update it to state the application context derives from `IdentityDbContext<IdmtUser, IdmtRole, Guid>` and implements `IMultiTenantDbContext` (Identity schema for free; no Identity table stamped; Finbuckle stamping/filtering available to consumer `[MultiTenant]` entities via `ConfigureMultiTenant` + `EnforceMultiTenant`). State explicitly that there is no de-tenant / rip-out step, and that `IdmtRole` is per-tenant via an explicit `TenantId` scoped by explicit query, not by a Finbuckle filter, because issuance reads roles with no ambient tenant. Keep the three-context split, the migration-history-table guidance, and the separate plain OpenIddict context as-is (all correct).

3. `docs/v2/02-core-domain.md`. Lines 91-97 (IdmtRole per-tenant, explicit `TenantId`, system authority from `SysRole` not per-tenant roles) are correct; no change to the entity description. Resolve the dangling "(Base class nuance is discussed below.)" on line 132 by ensuring `03` now actually specifies the base class, and optionally add a one-line cross-reference that role scoping is explicit (manual) because of issuance-time projection at the no-ambient-tenant endpoint.

4. `adr/0001-canonical-identity-and-tenant-access.md`.
   - §2.1 line 34 ("Drop `TenantId` from **all** Identity tables: `IdmtUser`, `IdmtRole`, ...") and §3 line 265 ("Drop `TenantId` from Identity tables ...") are superseded for `IdmtRole` by ADR-0002 §2.7. Add a note that `IdmtRole` keeps an explicit, declared `TenantId` column (not a Finbuckle shadow column), scoped by explicit query.
   - §8 line 330 ("`IsMultiTenant()` is **not** applied to Identity tables under this design") stays correct and should be kept. Optionally clarify it: `IsMultiTenant()` is applied to no IDMT Identity table; `IdmtRole`'s tenant scoping is an explicit column, and `IsMultiTenant()` remains available to consumers for their own application entities through the `IMultiTenantDbContext` base.

5. `adr/0002-idmt-v2-openiddict-authorization-layer.md`. §2.7 line 273-274 ("`IdmtRole` remains per-tenant") is correct. Optionally extend it to record the mechanism and its reason: per-tenant via an explicit `TenantId` scoped explicitly, not Finbuckle-managed, because issuance projects role claims at the no-ambient-tenant token endpoint (cross-ref `docs/v2/06-tenant-access-gate.md` "Claims and second-factor state at issuance").

## Migration caveat (consumers upgrading v1 to v2)

In v1, `IdmtRole` is Finbuckle-managed (only `IdmtUser` was de-tenanted), so role queries are auto-filtered by the ambient tenant. `preditor-cloud/src/Application/Admin/GetTenantUsers.cs:24-34` relies on this: it joins `db.Roles` with no explicit `TenantId` filter. v2 does not change this (v2 roles were already manual-scoped in the shipped v2 code), but it is worth recording in the v1-to-v2 migration notes: any consumer query against roles must carry an explicit `.Where(r => r.TenantId == currentTenantId)`, because IDMT no longer applies a Finbuckle filter to `IdmtRole`. Seeding paths that set the ambient tenant explicitly are unaffected.

## Guardrail to keep

Do not project per-tenant `IdmtRole` rows into a token anywhere that lacks a tenant argument; always read roles by explicit tenant identifier, the same way `ITenantAccessGate` takes its tenant explicitly. The issuance handler already follows this. If a future feature reads roles, it must pass the tenant explicitly rather than rely on an ambient tenant.

## Execution checklist

1. Rewrite `Idmt.AspNetCore/Persistence/IdmtDbContext.cs` per the design (delete `DeTenant()` and the loop; new base + interface + `SaveChanges` overrides). Fix the `using` directives per the build.
2. Build; confirm no reference to `MultiTenantIdentityDbContext` remains and the helper extensions resolve.
3. Run `tests/Idmt.AspNetCore.Tests/PersistenceModelTests.cs`; confirm the four existing tests stay green.
4. Add the two consumer-extension tests (model marking + save stamping). These assert the model shape directly (no EF migration is generated in this library; consumers generate their own).
5. Apply the documentation and ADR edits in the section above.
6. `dotnet format` and the analyzer/warning-as-error gate.

## Open questions

- Confirm the exact namespaces for `IsMultiTenant`, `ConfigureMultiTenant`, and `EnforceMultiTenant` in Finbuckle 10.0.3 against the compiler (noted inline).
- Confirm whether `AspNetUserRoles` is retained in v2 (ADR-0001 §2.1 said retire it; the current de-tenant list and `preditor-cloud` both reference `UserRoles`). This is orthogonal to the base-class swap but should be settled before the migration is generated.
