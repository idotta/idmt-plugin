# Core domain layer (`Idmt.Core`)

`Idmt.Core` holds the IDMT v2 domain: the canonical identity entities, the
authorization policy names, the support-capability rule, and the repository and
service ports that infrastructure implements. It is the one package that
references zero infrastructure. No OpenIddict, no Entity Framework Core, no
Finbuckle, and no ASP.NET Core types appear here. You build the domain once,
prove it stays infrastructure-free with a fitness test, and let `Idmt.AspNetCore`
adapt it to the engines. This is the layer that encodes what IDMT owns: the
multi-tenant authorization model, projected later into tokens by the composition
root.

The identity model is carried forward unchanged from the shipped 2.0.0
canonical-identity model in
[ADR-0001](../../adr/0001-canonical-identity-and-tenant-access.md), and it is
strengthened by the uniform access gate in
[ADR-0002 §2.7](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#27-canonical-identity-carried-from-adr-0001).
You change none of the field names or types. You move them into a package that
the architecture test guards.

## What you build

This section lists the concrete deliverables of `Idmt.Core` so you can scope the
work before reading the detail. Each item below has its own section later in this
document.

You build four things in `Idmt.Core`:

- The canonical identity entities: `IdmtUser`, `IdmtRole`, `SysRoleKind`, and
  `TenantAccess`.
- The authorization policy name constants: `RequireSysAdmin`, `RequireSysUser`,
  `RequireTenantManager`, `RequireTenantMember`, and `SupportSession`.
- The support-capability rule: the domain logic that decides whether a system
  user may mint a support token for a tenant.
- The repository and service ports: small interfaces that infrastructure
  satisfies, including the access-gate port, user and tenant-access repository
  ports, and a clock port.

## Source of truth

Read the source artifacts before you implement, so field names, types, and gate
semantics match the shipped model and the proven spike exactly. The documents
below are authoritative, and this page summarizes them rather than restating
them.

- [ADR-0001 Canonical Identity and Tenant Access](../../adr/0001-canonical-identity-and-tenant-access.md):
  the canonical identity model, the `TenantAccess` aggregate, the `SysRole`
  capability, and per-(user, tenant) lockout.
- [ADR-0002 §2.7 Canonical identity, carried from ADR-0001](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#27-canonical-identity-carried-from-adr-0001):
  the model v2 keeps, and the gate that now runs at every grant and every mint.
- [ADR-0002 §2.1 Thesis: own the policy, rent the protocol](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#21-thesis-own-the-policy-rent-the-protocol):
  why the domain is the part IDMT owns.
- [ADR-0002 §2.10 Endpoint scaffolding](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#210-endpoint-scaffolding):
  the five public policy-name constants.
- The spike domain types in `spike/src/Idmt.Spike.Host/Domain/Domain.cs`: the
  gate-proven shape of `IdmtUser`, `IdmtRole`, `SysRoleKind`, and `TenantAccess`.
- The spike auth types in `spike/src/Idmt.Spike.Host/Auth/Auth.cs`: the proven
  `ITenantAccessGate` port, `TenantAccessGate` reference implementation, and
  `TenantUrns`.

## Canonical identity entities

The domain carries four identity types forward from 2.0.0 with no field changes.
You match the shipped names and types exactly: a rename here is a breaking change
to the persistence schema and to the claims the tokens project. The prose below
describes each type, and the C# sketch that follows is a compact reference, not
the full file.

`IdmtUser` is the global canonical identity: one row per human, with a globally
unique normalized email and no `TenantId`. It extends ASP.NET Core Identity's
`IdentityUser<Guid>` (see
[Keeping Core infrastructure-free](#keeping-core-infrastructure-free) for the
nuance this introduces). On top of the base, it carries `SysRole` (a
`SysRoleKind`, defaulting to `None`), `PendingEmail` (the out-of-band email
change staging slot, null when no change is pending), `IsActive` (the soft-delete
flag), and `LastLoginAt`. There is exactly one row per human regardless of how
many tenants that human can reach.

`IdmtRole` is the per-tenant role. It extends `IdentityRole<Guid>` and adds a
`TenantId` string, so a role name scopes to a tenant. System authority does not
live here: post-canonicalization, `SysAdmin` and `SysSupport` are not seeded as
per-tenant role rows. They come from `IdmtUser.SysRole` and the uniform gate.

`SysRoleKind` is the global system-role flag: `None = 0`, `SysAdmin = 1`,
`SysSupport = 2`. Its string values match the policy names, so the enum projects
cleanly as a role claim. A `SysAdmin` user emits a `SysAdmin` role claim, which
the `RequireSysAdmin` policy matches without a translation table.

`TenantAccess` is the user-to-tenant edge: the pair `(UserId, TenantId)` with an
`IsActive` flag and an optional `ExpiresAt` (always UTC). This is the gate. No
user, not even a system administrator, gets a token for a tenant without an
active, unexpired `TenantAccess` row. The entity is deliberately not multi-tenant:
the issuance gate queries it by `(userId, tenantId)` at the token endpoint, where
no ambient tenant exists to filter on.

```csharp
namespace Idmt.Core;

// Global system-role flag. String values match the policy names so the
// enum projects cleanly as a role claim.
public enum SysRoleKind
{
    None = 0,
    SysAdmin = 1,
    SysSupport = 2,
}

// Global canonical identity: one row per human, globally unique normalized
// email, no TenantId. (Base class nuance is discussed below.)
public class IdmtUser : IdentityUser<Guid>
{
    public override Guid Id { get; set; } = Guid.CreateVersion7();
    public override string? SecurityStamp { get; set; } = Guid.NewGuid().ToString();

    public SysRoleKind SysRole { get; set; } = SysRoleKind.None;
    public string? PendingEmail { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset? LastLoginAt { get; set; }
}

// Per-tenant role. Carries TenantId.
public class IdmtRole : IdentityRole<Guid>
{
    public IdmtRole() { }
    public IdmtRole(string name) : base(name) { }

    public override Guid Id { get; set; } = Guid.CreateVersion7();
    public string TenantId { get; set; } = null!;
}

// The user-to-tenant edge. This is the gate.
public sealed class TenantAccess
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid UserId { get; set; }
    public string TenantId { get; set; } = null!;
    public bool IsActive { get; set; } = true;
    public DateTimeOffset? ExpiresAt { get; set; }
}
```

## The TenantAccess gate as a domain rule

`TenantAccess` is the heart of the model, so the rule that reads it lives in the
domain, not in a handler that a consumer could bypass. The gate answers one
question: may this user receive a token scoped to this tenant right now? The
answer is yes only when an active, unexpired `TenantAccess` row exists for the
`(UserId, TenantId)` pair.

A row passes the gate when `IsActive` is true and `ExpiresAt` is either null
(no expiry) or in the future relative to the current UTC time. A missing row
fails. An inactive row fails. An expired row fails. The rule is uniform: it
applies to every user identically, including a system administrator, because v2
expresses system access explicitly through the gate rather than through an
ambient bypass that ADR-0001 alternative 3 rejected.

In v2 the gate runs in more places than it did in 2.0.0. It runs not only at
login but at token issuance across every grant type, and at every server-side
support-token mint. That uniformity is what lets support, revocation, expiry, and
audience all share one code path. The mechanism that invokes the gate inside the
OpenIddict issuance pipeline is infrastructure. The
[tenant access gate](06-tenant-access-gate.md) doc covers that wiring. The
domain owns only the decision rule and the port that exposes it.

## Authorization policy constants

The policy names are public constants in `Idmt.Core` so both the scaffolding in
`Idmt.AspNetCore` and consumer code reference one spelling. They are part of the
domain because they name the authorization model IDMT owns, and because the
scaffolding in
[ADR-0002 §2.10](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#210-endpoint-scaffolding)
attaches them to the route groups it hands consumers.

There are five constants:

- `RequireSysAdmin`: the caller holds the `SysAdmin` system role. The
  `MapIdmtSysAdminApi` scaffolding attaches this policy.
- `RequireSysUser`: the caller holds any active system role (`SysAdmin` or
  `SysSupport`).
- `RequireTenantManager`: the caller manages the resolved tenant.
- `RequireTenantMember`: the caller is a member of the resolved tenant.
- `SupportSession`: the caller is an impersonating system user, so a tenant
  endpoint can refuse destructive operations or surface a banner.

Where a policy name corresponds to a system role, it doubles as the
`SysRoleKind` string value. `RequireSysAdmin` keys on the same `SysAdmin` string
the `SysRoleKind.SysAdmin` enum member projects as a role claim, so the policy
matches the claim without a mapping layer.

```csharp
namespace Idmt.Core;

public static class IdmtPolicies
{
    public const string RequireSysAdmin = "RequireSysAdmin";
    public const string RequireSysUser = "RequireSysUser";
    public const string RequireTenantManager = "RequireTenantManager";
    public const string RequireTenantMember = "RequireTenantMember";
    public const string SupportSession = "SupportSession";
}
```

## Support-capability rules

The rule that decides whether a system user may mint a support token for a tenant
is domain logic, so it lives in `Idmt.Core`. The mint mechanism itself is
infrastructure. Keeping the decision in the domain means one place tests it and
no consumer customization can weaken it.

A system user may mint a support token for a target tenant only when both checks
pass:

- The user holds an active `SysRole` capability (a `SysRoleKind` other than
  `None`).
- The user passes the uniform `TenantAccess` gate for the target tenant.

Both checks run inside the mint, before any token is created. The capability is
necessary but not sufficient: a system role grants the ability to be granted
tenant access, not ambient access to every tenant. The gate still applies, which
is the §2.7 strengthening over ADR-0001. The mint mechanism, the RFC 8693 `act`
claim, the TTL ceiling, and the audit row that commits in the same transaction as
the token are infrastructure concerns covered in
[support token mint](08-support-token-mint.md). The domain contributes the
predicate those mechanics enforce.

## Ports

`Idmt.Core` declares ports as small interfaces and lets `Idmt.AspNetCore`
implement them. The domain depends on abstractions; infrastructure depends on the
domain. This inversion is what keeps the engines out of `Idmt.Core` while still
letting the domain rule reach the database. Keep each port small and named for
its single responsibility.

The ports the domain declares:

- `ITenantAccessGate`: the access-gate port, the proven shape from the spike. It
  exposes one method, `CanAccessAsync(Guid userId, string tenantIdentifier,
  CancellationToken ct)`, returning whether an active, unexpired `TenantAccess`
  row exists. The spike's `TenantAccessGate` is the reference implementation, and
  it lives in infrastructure because it reads a `DbContext`.
- A user repository port: load and persist `IdmtUser` by id and by normalized
  email, surfacing the canonical identity to domain operations without naming a
  store.
- A tenant-access repository port: read and write `TenantAccess` rows for a
  `(UserId, TenantId)` pair, which is what `RevokeTenantAccess` and the gate
  operate against.
- A clock port: the current UTC time, abstracted so the gate's expiry comparison
  and the support-token TTL are deterministic under test. The spike injects
  `TimeProvider` directly. You can adopt `TimeProvider` as the clock port, since
  it ships in the base class library and pulls in no infrastructure.

```csharp
namespace Idmt.Core;

// The uniform TenantAccess gate. Queried at token issuance for every grant,
// with no reliance on an ambient tenant (the token endpoint has none).
public interface ITenantAccessGate
{
    Task<bool> CanAccessAsync(Guid userId, string tenantIdentifier, CancellationToken ct);
}
```

## Keeping Core infrastructure-free

`Idmt.Core` references zero infrastructure, and a fitness test enforces it rather
than a code-review habit. No OpenIddict, Entity Framework Core, Finbuckle, or
ASP.NET Core type appears in the domain. This is the §2.2 "zero infrastructure"
rule, and the
[architecture fitness function](01-solution-and-packages.md) makes it a
compile-and-test guarantee.

One nuance needs a recorded decision. The canonical entities extend ASP.NET Core
Identity base classes (`IdentityUser<Guid>` and `IdentityRole<Guid>`), as the
shipped 2.0.0 models and the spike both do. Those base classes live in
`Microsoft.AspNetCore.Identity`. If `Idmt.Core` must stay free of even that
package, you model the entities as POCOs that `Idmt.AspNetCore` adapts to the
Identity types. Otherwise, the Identity abstractions package is the single
allowed identity dependency in `Idmt.Core`.

We recommend keeping `Idmt.Core` POCO-pure and placing the Identity adapters in
`Idmt.AspNetCore`. This honors the fitness test as written: the domain names no
ASP.NET Core type, and the architecture fitness function in
[the solution and packages doc](01-solution-and-packages.md) passes without an
exception carved out for an identity package. The implementer records the choice
explicitly, citing
[ADR-0002 §2.2](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#22-module-boundaries-three-packages),
because the POCO-versus-`IdentityUser` line determines whether the fitness
function needs a documented allow-list entry at all. If you instead allow the
Identity abstractions package, the test must whitelist it, and you record that the
firewall has one sanctioned hole.

## Dependencies

`Idmt.Core` sits at the bottom of the dependency graph: everything depends on it
and it depends on nothing in the solution. The package layout, the fitness
function, and the allowed base-class-library surface are defined alongside the
solution structure.

For the package boundaries, the three-package split, and the architecture test
that enforces this layer's purity, see
[the solution and packages doc](01-solution-and-packages.md).

## Acceptance criteria

This layer is done when the rules below hold. Each is a check you can run, not a
judgment call, so the domain's invariants are verifiable before you build on top
of them.

- The architecture fitness function passes: `Idmt.Core` references no
  infrastructure assembly, with the POCO-versus-Identity decision from
  [Keeping Core infrastructure-free](#keeping-core-infrastructure-free) recorded
  and reflected in the test's allow-list.
- Unit tests cover the gate logic across all three outcomes: an active, unexpired
  `TenantAccess` row passes; an expired row fails; a missing row fails. An
  inactive row fails.
- Unit tests cover the support-capability rule: a user with an active `SysRole`
  and a passing gate may mint; a user with the role but no tenant access may not;
  a user with tenant access but no `SysRole` may not.
- The four entity types match the shipped 2.0.0 field names and types, and the
  five policy-name constants are public.

## Next steps

With the domain in place, the next docs wire it to the persistence layer and to
the issuance pipeline that invokes the gate. Read them in order: persistence
first, then the gate's runtime mechanism.

- [Persistence and contexts](03-persistence-and-contexts.md): how the two
  Entity Framework Core contexts store the canonical identity tables and the
  OpenIddict tables.
- [Tenant access gate](06-tenant-access-gate.md): how the domain gate rule is
  invoked at token issuance and at the support-token mint.
