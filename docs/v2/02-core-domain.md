# Core domain layer (`Idmt.Core`)

`Idmt.Core` holds the IDMT v2 domain: the canonical identity entities, the
authorization policy names, the support-capability rule, and the gate service
ports that infrastructure implements. It is the one project that references zero
engine infrastructure. No OpenIddict, no Entity Framework Core, and no Finbuckle
types appear here. It declares no repository ports: data access is not abstracted
here, because `DbContext` and `UserManager` are already the persistence
abstractions and those queries live in `Idmt.AspNetCore`. The one sanctioned dependency is the ASP.NET
Core Identity abstractions package, because the canonical entities extend
`IdentityUser<Guid>` and `IdentityRole<Guid>` (see
[Keeping Core infrastructure-free](#keeping-core-infrastructure-free)). You build
the domain once, prove it stays free of the engines with a fitness test, and let
`Idmt.AspNetCore` adapt it to those engines. This is the layer that encodes what
IDMT owns: the
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

You build five things in `Idmt.Core`:

- The canonical identity entities: `IdmtUser`, `IdmtRole`, `SysRoleKind`,
  `TenantAccess`, and `ClientTenantAccess`.
- The four gating authorization policy name constants: `RequireSysAdmin`,
  `RequireSysUser`, `RequireTenantManager`, and `RequireTenantMember`.
  `SupportSession` ships alongside them but is a claims-inspection helper, not a
  gating policy (see [Authorization policy constants](#authorization-policy-constants)).
- The support-capability rule: the pure domain predicate
  (`SupportCapability.CanMint`) that decides whether a system user may mint a
  support token for a tenant.
- The error taxonomy: the `IdmtErrors` members the v2 flows surface (see
  [Error taxonomy for v2 flows](#error-taxonomy-for-v2-flows)).
- The gate service ports: small interfaces that infrastructure satisfies, namely
  the user and client access-gate ports (`ITenantAccessGate`,
  `IClientTenantAccessGate`) and a clock port. No repository ports: persistence is
  not abstracted in the domain.

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
`IdentityUser<Guid>` (the sanctioned dependency described in
[Keeping Core infrastructure-free](#keeping-core-infrastructure-free)). On top of
the base, it carries `SysRole` (a
`SysRoleKind`, defaulting to `None`), `PendingEmail` (the out-of-band email
change staging slot, null when no change is pending), `IsActive` (the soft-delete
flag), and `LastLoginAt`. There is exactly one row per human regardless of how
many tenants that human can reach.

`IdmtRole` is the per-tenant role. It extends `IdentityRole<Guid>` and adds a
`TenantId` string, so a role name scopes to a tenant. The scoping is explicit
(callers query by `TenantId`), not a Finbuckle filter, because issuance projects
role claims at the no-ambient-tenant token endpoint (see
[03-persistence-and-contexts.md](03-persistence-and-contexts.md) and
[06-tenant-access-gate.md](06-tenant-access-gate.md)). System authority does not
live here: post-canonicalization, `SysAdmin` and `SysSupport` are not seeded as
per-tenant role rows. They come from `IdmtUser.SysRole` and the uniform gate. The
default role catalog (`IdmtDefaultRoleTypes.DefaultRoles`) gains a designated
manager role with the default name `Manager`, which `RequireTenantManager` keys
on; the per-tenant rows for it are seeded the same way the rest of the catalog is.

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

`ClientTenantAccess` is the client-to-tenant edge, mirroring `TenantAccess` for
machine clients. It pairs `(ClientId, TenantId)` with the same `IsActive` flag and
optional `ExpiresAt` (always UTC). A pure client-credentials grant has no user
subject, so the user gate cannot decide it. `ClientTenantAccess` is the gate for
that path: no client gets a token for a tenant without an active, unexpired row.
Both `TenantId` columns store the same value (see
[TenantId stores the Finbuckle identifier](#tenantid-stores-the-finbuckle-identifier)).

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
// email, no TenantId. It is global by construction: IdmtDbContext derives from
// the plain IdentityDbContext (not Finbuckle's identity context), so no Identity
// table is tenant-stamped. See 03-persistence-and-contexts.md.
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
    public required string TenantId { get; set; }
}

// The user-to-tenant edge. This is the gate.
// TenantId stores the Finbuckle tenant IDENTIFIER string, not the
// Finbuckle internal Id (see "TenantId stores the Finbuckle identifier").
public sealed class TenantAccess
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid UserId { get; set; }
    public required string TenantId { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset? ExpiresAt { get; set; }
}

// The client-to-tenant edge, mirroring TenantAccess. Gates pure
// client-credentials grants that have no user subject. TenantId is the
// Finbuckle identifier string, as on TenantAccess.
public sealed class ClientTenantAccess
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public required string ClientId { get; set; }
    public required string TenantId { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset? ExpiresAt { get; set; }
}
```

The `= null!;` initializer that the shipped models used for non-null string
members is replaced by `required` in v2: `TenantId` on `IdmtRole`, `TenantId` and
`ClientId` on the access edges, and `UserName` / `Email` where the entities
override them. `required` is the C# 14 idiom that enforces the invariant at
construction instead of deferring a null-forgiving promise the compiler cannot
check.

## The TenantAccess gate as a domain rule

`TenantAccess` is the heart of the model, so the rule that reads it lives in the
domain, not in a handler that a consumer could bypass. The gate answers one
question: may this user receive a token scoped to this tenant right now? The
answer is yes only when an active, unexpired `TenantAccess` row exists for the
`(UserId, TenantId)` pair.

A row passes the gate when the explicit predicate
`isActive && (expiresAt is null || expiresAt > now)` holds, where `now` is the
current UTC time. A missing row fails. An inactive row fails. An expired row
fails. The predicate is stated inline rather than wrapped in a dedicated
`TenantAccessRule` type: it is a three-condition boolean, and a wrapper type would
be ceremony around it. It is tested through the gate port, not as a separate unit.
The rule is uniform: it applies to every user identically, including a system
administrator, because v2 expresses system access explicitly through the gate
rather than through an ambient bypass that ADR-0001 alternative 3 rejected.

In v2 the gate runs in more places than it did in 2.0.0. It runs not only at
login but at token issuance across every grant type, and at every server-side
support-token mint. That uniformity is what lets support, revocation, expiry, and
audience all share one code path. The mechanism that invokes the gate inside the
OpenIddict issuance pipeline is infrastructure. The
[tenant access gate](06-tenant-access-gate.md) doc covers that wiring. The
domain owns only the decision rule and the port that exposes it.

## TenantId stores the Finbuckle identifier

`TenantAccess.TenantId` and `ClientTenantAccess.TenantId` store the Finbuckle
tenant IDENTIFIER string, not the Finbuckle internal `Id`. This is the value the
gate is called with: both gate ports take a `tenantIdentifier` parameter, and the
issuance pipeline resolves the requested tenant to its identifier before calling
the gate. Storing the identifier means the gate query is a direct equality match
with no join through the tenant store, and it matches how the
[seeder](13-seeding-bootstrap.md) writes access rows. Keep the two columns
consistent: a row written with the internal `Id` would never match a gate call
keyed on the identifier, and the user (or client) would be silently denied.

## Authorization policy constants

The policy names are public constants in `Idmt.Core` so both the scaffolding in
`Idmt.AspNetCore` and consumer code reference one spelling. They are part of the
domain because they name the authorization model IDMT owns, and because the
scaffolding in
[ADR-0002 §2.10](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#210-endpoint-scaffolding)
attaches them to the route groups it hands consumers.

Four of the constants are gating authorization policies (`Build()` registers them,
the scaffolding attaches them, and a failed check returns 403):

- `RequireSysAdmin`: the caller holds the `SysAdmin` system role. The
  `MapIdmtSysAdminApi` scaffolding attaches this policy.
- `RequireSysUser`: the caller holds any active system role (`SysAdmin` or
  `SysSupport`).
- `RequireTenantManager`: the caller holds the designated manager role for the
  resolved tenant. The policy is defined as `RequireRole(<manager role>)`, where
  the manager role is the `Manager` entry added to
  `IdmtDefaultRoleTypes.DefaultRoles`. It is satisfied by the projected
  tenant-role claim for that role.
- `RequireTenantMember`: the caller holds at least one projected tenant-role claim
  for the resolved tenant. This is deliberately not defined as merely
  "authenticated and audience-bound": the audience handler already enforces that a
  presented token's `aud` matches the resolved tenant, so a member policy that
  added nothing would be redundant. Membership means the user has at least one
  `IdmtRole` assignment in the tenant, projected as a role claim.

These policies consume role claims that issuance projects. At issuance the
resolved user's `IdmtRole` assignments for the resolved tenant are written into
the token as role claims with access-token destinations
(see [the tenant access gate doc](06-tenant-access-gate.md)). `RequireTenantManager`
and `RequireTenantMember` read those claims; they do not query the database at
request time.

Where a policy name corresponds to a system role, it doubles as the
`SysRoleKind` string value. `RequireSysAdmin` keys on the same `SysAdmin` string
the `SysRoleKind.SysAdmin` enum member projects as a role claim, so the policy
matches the claim without a mapping layer.

`SupportSession` is the fifth constant, and it is not a gating policy. It is a
claims-inspection helper read inside a handler: when an impersonating system user
calls a tenant endpoint, the handler inspects the support claims (the RFC 8693
`act` claim) to refuse a destructive operation or surface a banner. It does not
gate the route the way the four policies above do, so it is not interchangeable
with them and `Build()` does not register it as an authorization policy.

```csharp
namespace Idmt.Core;

public static class IdmtPolicies
{
    // Gating authorization policies. Build() registers each as a policy.
    public const string RequireSysAdmin = "RequireSysAdmin";
    public const string RequireSysUser = "RequireSysUser";
    public const string RequireTenantManager = "RequireTenantManager";
    public const string RequireTenantMember = "RequireTenantMember";

    // Not a gating policy: a name used by the handler-side claims-inspection
    // helper that detects an impersonating support session.
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

The domain expresses the rule as a pure static predicate, not a service. The gate
result is computed by the caller (it calls `ITenantAccessGate.CanAccessAsync`)
and passed in, so the predicate itself touches no port and is trivially testable:

```csharp
namespace Idmt.Core;

public static class SupportCapability
{
    // sysRole: the minting user's SysRole.
    // tenantAccessGranted: the gate result the caller already computed for
    // (userId, targetTenant). Passed in so this stays pure.
    public static bool CanMint(SysRoleKind sysRole, bool tenantAccessGranted) =>
        sysRole != SysRoleKind.None && tenantAccessGranted;
}
```

The audit write that records a mint is transaction-coupled to the token insert by
design, so the domain declares no `ISupportAuditPort`. The mint service in
`Idmt.AspNetCore` owns that write inside the same owned transaction, where the
ambient `DbContext` and OpenIddict store live.

## Error taxonomy for v2 flows

The v2 flows add denial outcomes that the shipped `IdmtErrors` catalog does not
yet name. Add these members so handlers return one canonical `Error` per outcome
rather than ad hoc strings. The existing organization by domain (`Auth`,
`Tenant`, `Token`, and so on) carries forward; the new members slot into it.

- Tenant-access denial: the uniform gate failed for `(user, tenant)`. A
  `Tenant.AccessDenied` forbidden error.
- Audience mismatch: a presented token's `aud` does not match the resolved tenant.
  A `Token.AudienceMismatch` unauthorized error.
- Support-mint denial: `SupportCapability.CanMint` returned false. A
  `Auth.SupportMintDenied` forbidden error.
- Support-mint required reason: a mint request arrived with no `Reason`. A
  `Auth.SupportReasonRequired` validation error (paired with the FluentValidation
  `NotEmpty` rule on the request record).
- MFA required at issuance: a user grant reached issuance without the recorded
  second factor. A `Auth.MfaRequired` error.
- Client-tenant denial: the client gate failed for `(client, tenant)` on a
  client-credentials grant. A `Auth.ClientTenantAccessDenied` forbidden error.

These denials surface through two different mechanisms, and the doc keeps them
distinct because they are not interchangeable:

- Handler path (`ErrorOr`): denials raised inside a feature handler (for example
  the support-mint endpoint, or a `RevokeTenantAccess` operation) return the
  matching `IdmtErrors` member as an `Error`, which the endpoint delegate maps to
  an HTTP status. This is the same `ErrorOr<T>` flow the shipped features use.
- Pipeline path (`context.Reject`): denials raised inside the OpenIddict server
  pipeline (the public-grant gate handler, the audience check at issuance) do NOT
  return `ErrorOr`. They call `context.Reject(...)` with an OAuth error code so
  the response is protocol-compliant. The gate decision is the same; the surfacing
  mechanism differs because the pipeline owns the response shape, not a handler.

The `IdmtErrors` members above are the vocabulary for the handler path and for the
diagnostics the pipeline path logs; the `context.Reject` calls carry OAuth error
codes, not `ErrorOr` values.

## Ports

`Idmt.Core` declares only the gate service ports as small interfaces and lets
`Idmt.AspNetCore` implement them. These ports exist because the gate is a domain
decision (a locked invariant) that infrastructure executes, so the domain names
the contract and the composition root supplies the query. The domain declares no
repository ports. Wrapping Entity Framework Core in a repository would be a
redundant abstraction: `DbContext` is already the unit of work, `DbSet<T>` is
already a repository, and `UserManager<IdmtUser>` is already the user store. v2
commits to those engines with no second backend in view, so the data-access code
lives directly in `Idmt.AspNetCore` (the gate implementations, the
`RevokeTenantAccess` handler, the seeder) against `DbContext` and `UserManager`.
Keep each port small and named for its single responsibility.

The ports the domain declares:

- `ITenantAccessGate`: the user access-gate port, the proven shape from the spike.
  It exposes one method, `CanAccessAsync(Guid userId, string tenantIdentifier,
  CancellationToken ct)`, returning whether an active, unexpired `TenantAccess`
  row exists. The spike's `TenantAccessGate` is the reference implementation, and
  it lives in infrastructure because it reads a `DbContext`.
- `IClientTenantAccessGate`: the client access-gate port for the pure
  client-credentials grant. It mirrors `ITenantAccessGate` but keys on the OAuth
  `client_id` instead of a user id, reading `ClientTenantAccess` with the same
  active-and-unexpired predicate.
- A clock port: the current UTC time, abstracted so the gate's expiry comparison
  and the support-token TTL are deterministic under test. The spike injects
  `TimeProvider` directly. Adopt `TimeProvider` as the clock port, since it ships
  in the base class library and pulls in no infrastructure.

Every port signature names only base-class-library and `Idmt.Core` types. No
`DbContext`, no OpenIddict descriptor, and no Finbuckle type appears on a port
surface, so the fitness function keeps the engines out.

```csharp
namespace Idmt.Core;

// The uniform user TenantAccess gate. Queried at token issuance for every
// user grant, with no reliance on an ambient tenant (the token endpoint has
// none). tenantIdentifier is the Finbuckle identifier string.
public interface ITenantAccessGate
{
    Task<bool> CanAccessAsync(Guid userId, string tenantIdentifier, CancellationToken ct);
}

// The client gate for pure client-credentials grants (no user subject).
// clientId is the OAuth client_id; tenantIdentifier is the Finbuckle
// identifier string.
public interface IClientTenantAccessGate
{
    Task<bool> CanAccessAsync(string clientId, string tenantIdentifier, CancellationToken ct);
}
```

## Keeping Core infrastructure-free

`Idmt.Core` references zero engine infrastructure, and a fitness test enforces it
rather than a code-review habit. No OpenIddict, Entity Framework Core, or
Finbuckle type appears in the domain. This is the §2.2 "zero infrastructure" rule
applied to the engines, and the
[architecture fitness function](01-solution-and-packages.md) makes it a
compile-and-test guarantee.

The canonical entities extend ASP.NET Core Identity base classes
(`IdentityUser<Guid>` and `IdentityRole<Guid>`), as the shipped 2.0.0 models and
the spike both do. Those base classes live in `Microsoft.AspNetCore.Identity`, so
`Idmt.Core` openly depends on the ASP.NET Core Identity abstractions. This is a
made decision, not an open choice: depending on the abstractions is what unblocks
every `UserManager` and `SignInManager` flow (the seeder, the revocation hooks)
without an adapter layer that would have to mirror the entities.

The fitness function reflects this. Its deny-list allows the Identity abstraction
assemblies (`Microsoft.Extensions.Identity.Stores` and
`Microsoft.AspNetCore.Identity`) while still denying the engine packages:
`Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore`,
`OpenIddict*`, and `Finbuckle*`. The allowed Identity surface is the one
sanctioned dependency, recorded against
[ADR-0002 §2.2](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#22-module-boundaries-three-packages);
the firewall keeps every other engine out.

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

- The architecture fitness function passes: `Idmt.Core` references no engine
  assembly (OpenIddict, Entity Framework Core, Finbuckle), with the allowed
  ASP.NET Core Identity abstractions from
  [Keeping Core infrastructure-free](#keeping-core-infrastructure-free) reflected
  in the test's allow-list.
- Unit tests cover the gate logic across all three outcomes: an active, unexpired
  `TenantAccess` row passes; an expired row fails; a missing row fails. An
  inactive row fails.
- Unit tests cover `SupportCapability.CanMint`: an active `SysRole` with a passing
  gate result returns true; the role with a false gate result returns false; a
  `None` role with a passing gate result returns false.
- The carried-forward entity types (`IdmtUser`, `IdmtRole`, `TenantAccess`) match
  the shipped 2.0.0 field names and types, `ClientTenantAccess` mirrors
  `TenantAccess`, the four gating policy-name constants and `SupportSession` are
  public, and `Manager` is present in `IdmtDefaultRoleTypes.DefaultRoles`.

## Next steps

With the domain in place, the next docs wire it to the persistence layer and to
the issuance pipeline that invokes the gate. Read them in order: persistence
first, then the gate's runtime mechanism.

- [Persistence and contexts](03-persistence-and-contexts.md): how the two
  Entity Framework Core contexts store the canonical identity tables and the
  OpenIddict tables.
- [Tenant access gate](06-tenant-access-gate.md): how the domain gate rule is
  invoked at token issuance and at the support-token mint.
