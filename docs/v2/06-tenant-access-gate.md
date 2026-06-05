# The uniform TenantAccess gate

One rule governs every token IDMT issues: a user gets a token for tenant `T`
only when an active, unexpired `TenantAccess(UserId, T)` row exists. There is no
exception, not for a system administrator, not for a support mint, not for a
refresh. The gate runs at every place a token is born: every public grant on
`/connect/token`, and every server-side support-token mint. This is the
`TenantAccess` gate, and it is locked invariant 1 of the v2 design.

This rule matters because v2's canonical identity concentrates blast radius. One
human is one `IdmtUser` row, and that one credential can reach every tenant the
user belongs to. The gate is the containment: it is the single, uniform check
that decides which tenants a credential can actually mint a token for, applied
uniformly so no grant path can quietly skip it. v1 gated only at login, so a
revoked grant kept working until the user logged in again. v2 re-runs the gate
at issuance and at refresh, so a revoked `TenantAccess` stops new and refreshed
tokens promptly.

## What you build

This section names the concrete deliverables so you can scope the work before
reading the detail. The user gate and the client gate are two small ports, and
the public grants share a single call site (a server event handler); the work is
making sure the right gate is called at every issuance point and nowhere is
missed.

You build four things:

- The `ITenantAccessGate` port, declared in `Idmt.Core` and implemented in
  `Idmt.AspNetCore`, with a single `CanAccessAsync(userId, tenantIdentifier, ct)`
  method that matches the proven spike shape.
- The `IClientTenantAccessGate` port, the client analog declared in `Idmt.Core`
  and implemented in `Idmt.AspNetCore`, with a single
  `CanAccessAsync(clientId, tenantIdentifier, ct)` method. It gates pure
  machine-to-machine tokens that have no user subject (defined in
  [02-core-domain.md](02-core-domain.md) and persisted per
  [03-persistence-and-contexts.md](03-persistence-and-contexts.md)).
- The per-grant enforcement: a single `IOpenIddictServerHandler<ProcessSignInContext>`
  that fires once a principal is established, calls the right gate for the grant,
  and rejects denials with `context.Reject(...)`.
- The mint enforcement: a gate call inside the server-side support-token mint,
  run before the token is created, in addition to the system-role capability
  check.

## Source of truth

Read these artifacts before you implement, so the gate's semantics, its call
sites, and its locked status match the ADRs and the proven spike exactly. The
documents below are authoritative; this page summarizes them rather than
restating them.

- [ADR-0002 §2.7 Canonical identity, carried from ADR-0001](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#27-canonical-identity-carried-from-adr-0001):
  the uniform gate, strengthened from login-only to per-grant and per-mint
  enforcement.
- [ADR-0002 §2.9 The opinionated and customizable seam](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#29-the-opinionated-and-customizable-seam):
  locked invariant 1, the gate applied at token issuance for every grant and at
  every server-side support-token mint, which a consumer cannot configure away.
- [ADR-0001 Canonical Identity and Tenant Access](../../adr/0001-canonical-identity-and-tenant-access.md):
  the `TenantAccess` model with `IsActive` and optional `ExpiresAt`, and its
  login-time gate in the shipped 2.0.0 release.
- The spike gate in `spike/src/Idmt.Spike.Host/Auth/Auth.cs`: the proven
  `ITenantAccessGate` port and `TenantAccessGate` implementation, which query
  `TenantAccess` by `(userId, tenantId)`, filter on `IsActive`, and evaluate
  expiry.
- The spike support mint in `spike/src/Idmt.Spike.Host/Server/SupportTokenService.cs`
  (gate 2): the gate re-runs inside the mint, before `CreateAsync`.
- The spike user mint in `spike/src/Idmt.Spike.Host/Server/UserTokenMint.cs`
  (gate 6): tokens minted per `(user, tenant)`, the unit the gate protects.

## The rule

The gate is a single boolean decision with no special cases. You read it as one
sentence and you apply it identically everywhere.

A token for tenant `T` issues only when all of these hold:

- A `TenantAccess` row exists for the exact pair `(UserId, T)`.
- That row's `IsActive` is `true`.
- That row's `ExpiresAt` is unset (`null`) or in the future relative to the
  current clock.

Stated as one predicate over the matched row, the decision is
`isActive && (expiresAt is null || expiresAt > now)`. There is no separate rule
type for this; it is a three-condition boolean evaluated inline by the gate
implementation. SQLite evaluates the `expiresAt > now` comparison in memory
because the spike's provider cannot translate the `DateTimeOffset` comparison
(see [the gate port](#the-gate-port)).

There is no system-admin bypass. A system administrator holds a `SysRole`
capability, which is orthogonal to tenant access: it lets the administrator mint
a support token, but it does not grant ambient access to any tenant. To act in
tenant `T`, a system administrator still needs an active, unexpired
`TenantAccess(UserId, T)` row, and the support mint checks both the `SysRole`
capability and the `TenantAccess` gate before it creates a token. The capability
says "this user may support a tenant"; the gate says "this user may act in this
specific tenant." Both must pass.

The expiry check runs against the injected clock (`TimeProvider`), not
`DateTimeOffset.Now`, so tests can advance time deterministically. The spike
filters the translatable predicate (`UserId`, `TenantId`, `IsActive`) in the
database and evaluates the `ExpiresAt` comparison in memory, because the spike's
SQLite provider cannot translate the `DateTimeOffset` comparison; the candidate
set is at most a handful of rows per `(user, tenant)`, so the in-memory step is
cheap. A production provider that can translate the comparison may push it into
the query.

## The gate port

The gate is a port so the domain owns the rule while infrastructure owns the
query. `Idmt.Core` declares the interface and references no Entity Framework
Core; `Idmt.AspNetCore` implements it against the canonical-identity
`DbContext`.

The port mirrors the spike's `ITenantAccessGate` in
`spike/src/Idmt.Spike.Host/Auth/Auth.cs`:

```csharp
public interface ITenantAccessGate
{
    Task<bool> CanAccessAsync(Guid userId, string tenantIdentifier, CancellationToken ct);
}
```

The method takes the canonical user id and the tenant *identifier* (the
Finbuckle identifier string, the same value the audience URN carries as
`urn:idmt:tenant:{identifier}`), not an ambient tenant. This is deliberate: the
token endpoint runs in a pipeline scope where the ambient tenant is often unset,
so the gate must take the tenant as an explicit argument rather than read it from
`IMultiTenantContextAccessor`. The implementation queries `TenantAccess` by
`(userId, tenantIdentifier)`, keeps the rows where `IsActive` is `true`, and
returns `true` when any surviving row has `ExpiresAt` null or in the future,
which is the predicate `isActive && (expiresAt is null || expiresAt > now)`.

`TenantAccess.TenantId` stores the Finbuckle tenant *identifier* string (the
same value the audience URN carries as `urn:idmt:tenant:{identifier}`), not the
tenant's internal `Id`. The gate is called with that identifier, so the column it
matches against holds the identifier, and the seeder writes the same value (see
[13-seeding-bootstrap.md](13-seeding-bootstrap.md)).

The implementation lives in `Idmt.AspNetCore` because it depends on the
canonical-identity context. The seam in
[the locked seam](10-locked-seam.md) registers it and wires its call sites
unconditionally, so a consumer cannot replace it with a permissive stub or omit
a call site.

## Enforcement points

The gate's value is entirely in where it runs. A correct port called at one
public grant and missed at another is a hole, so the public grants share a single
enforcement point rather than a per-handler call that a new grant could forget.
The gate runs at every place a tenant-scoped token is born, before the token
exists. This section names that single handler, the per-grant detail it covers,
and the one server-side mint that runs the gate inline.

The public grants are gated by one `IOpenIddictServerHandler<ProcessSignInContext>`.
It fires after the grant-specific handling has run and a principal is
established, so it sees a settled subject for the authorization-code, refresh,
and client-credentials grants alike. It calls the gate for the resolved
`(subject, tenant)` and, on denial, calls `context.Reject(...)` with an OAuth
error so the response is protocol-compliant rather than a raw failure. Routing a
single handler across the three grants is what makes the "gate at every grant"
invariant structural: there is one call site, and a new grant inherits it.

What the handler reads differs by grant:

- **Authorization-code grant** (`/connect/token`, code exchange). The principal
  carries the canonical user and the tenant resolved at `/connect/authorize` and
  carried forward in the authorization. The handler calls the user gate
  (`ITenantAccessGate`) for that `(user, tenant)` pair. A denial rejects the
  exchange; no token is created.
- **Refresh grant** (`/connect/token`, refresh). The tenant is authoritative
  from the presented refresh token's original `aud`, read out of the decrypted
  presented token, not from the `resource` parameter. The handler re-runs the
  user gate against that tenant on every refresh, before the rotated token is
  issued, so access revoked between the original issuance and the refresh is
  honored. This is the single most important difference from v1: a `TenantAccess`
  revoked after login stops the next refresh.
- **Client-credentials grant** (`/connect/token`). A pure machine-to-machine
  token has no user subject, so the handler uses the client-to-tenant gate
  (`IClientTenantAccessGate`) for the `(clientId, tenant)` pair, not the user
  gate. This is the issuance gate for the client-credentials grant; the machine
  path is gated, not out of scope. See
  [16-machine-client-auth.md](16-machine-client-auth.md) for the client gate and
  its `ClientTenantAccess` backing.

The server-side support-token mint runs the gate inline, not through the
ProcessSignIn handler, because it has no public grant:

- **Server-side support-token mint** (`SupportTokenService`). The gate runs
  inside the mint, before `CreateAsync`, in the same transaction as the
  token-store insert and the audit write. The mint first checks that the actor
  holds an active `SysRole` capability, then calls the user gate for the target
  tenant; both must pass before the token is created. See gate 2 in
  `spike/src/Idmt.Spike.Host/Server/SupportTokenService.cs`, where the gate
  returns `no_tenant_access` and the mint denies the token.

## Claims and second-factor state at issuance

The same `ProcessSignInContext` handler that runs the gate is where IDMT
projects its issuance claims, after the gate passes and before the token is
written. Two reads happen here, both keyed on the resolved `(user, tenant)` and
both distinct from the gate decision itself.

First, role projection. For the resolved tenant the handler projects the user's
`IdmtRole` assignments as role claims on the principal, with access-token
destinations, so the tenant policies (`RequireTenantManager`,
`RequireTenantMember`) have a claim source on the issued token. The projection is
snapshot-at-issuance for reference tokens, the same as every other claim IDMT
writes.

Second, the second-factor read. For user grants the handler reads the recorded
second-factor state for the authorization (the satisfaction recorded at
interactive `/connect/authorize`, see [12-mfa.md](12-mfa.md)) and enforces the
MFA requirement at issuance. Pure client-credentials tokens have no user
subject and are exempt from this read. The MFA check is a separate read at this
handler, not a parameter on the gate: the `TenantAccess` gate stays a synchronous
`(userId, tenant)` decision, and the factor state is read alongside it, not
folded into `CanAccessAsync`.

The per-`(user, tenant)` minting unit in
`spike/src/Idmt.Spike.Host/Server/UserTokenMint.cs` (gate 6) is the object the
gate protects: every tenant-scoped token a user holds is grouped under one
`(user, tenant)` authorization, which is also how single-tenant revocation works
(see [revocation hooks](07-revocation-hooks.md)). The gate decides whether that
grouping gets a new token at all.

## What changed from v1

v1 and v2 share the same rule and the same `TenantAccess` model. The change is
purely *when* the rule runs, and that timing is the whole security improvement.

v1 gated at login only. Once a user logged in, their tokens kept working until
they expired or the user logged in again, even after an administrator revoked
their `TenantAccess`. A revoked grant was not enforced promptly; it was enforced
"next login," which could be hours or days away.

v2 re-runs the gate at every issuance and at every refresh. A `TenantAccess` row
flipped to `IsActive = false`, or given a past `ExpiresAt`, stops the next token
issuance and the next refresh for that `(user, tenant)` pair. This buys you
prompt enforcement of access changes without depending on token lifetime: a
revoked grant stops minting new tokens immediately, and stops extending existing
sessions at the next refresh.

The gate does not, on its own, revoke tokens already in flight. A token issued
one minute before the grant was revoked stays valid until its short TTL expires
or until something explicitly revokes it. Instant revocation of already-issued
tokens is a separate mechanism, the `SecurityStamp` propagation hook documented
in [revocation hooks](07-revocation-hooks.md). The gate governs *issuance*; the
hook governs *already-issued* tokens. Together they close the window the gate
alone leaves open.

## Dependencies

The gate sits between the domain model and the server grants, so it depends on
both. Read these before you wire it.

- [Core domain layer](02-core-domain.md): the `TenantAccess` entity (with
  `IsActive` and `ExpiresAt`), the canonical `IdmtUser`, and the
  `ITenantAccessGate` port declaration. The gate is one of the service ports the
  core domain exposes.
- [OpenIddict server](04-openiddict-server.md): the `/connect/token` pipeline and
  the `ProcessSignInContext` event handler where the single public-grant call
  site lives across the authorization-code, refresh, and client-credentials
  grants, and the RFC 8707 `resource`-parameter tenant convention the refresh
  grant reconciles against the token's `aud`.

## Acceptance criteria

The gate is real only if a test proves it denies a token at every issuance
point. The locked decision maps to one parametric test in the ADR, and that test
gates merges.

The [ADR §4 test strategy](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#4-test-strategy)
names the `TenantAccess` gate test directly: for every grant type, including
refresh, and for every server-side support-token mint, a user with no
`TenantAccess` or an expired `TenantAccess` is denied a token. To satisfy it, the
suite must assert each of these:

- The authorization-code grant denies a token to a user with no active,
  unexpired `TenantAccess` for the requested tenant.
- The refresh grant denies a rotated token when the original tenant's
  `TenantAccess` has been revoked or expired since the first issuance.
- The client-credentials grant denies a token to a machine client with no
  active, unexpired `ClientTenantAccess` for the tenant, through the client gate
  (`IClientTenantAccessGate`).
- The support-token mint denies a token (gate 2, `no_tenant_access`) to a system
  user who holds the `SysRole` capability but has no active, unexpired
  `TenantAccess` for the target tenant.

Each case must run as a true grant-type or mint denial, parameterized over the
"no row" and "expired row" conditions, tied to gate 2 (the support mint) and
gate 6 (the per-`(user, tenant)` mint unit). The full matrix lives in the
[test suite](14-test-suite.md).

## Next steps

The gate is one half of the access story. Read these next to see the other half
and the mint that depends on the gate.

- [Revocation hooks](07-revocation-hooks.md): how already-issued tokens are
  dropped when a credential or a grant changes, the mechanism the gate
  deliberately does not cover.
- [Support-token mint](08-support-token-mint.md): the full server-side mint flow
  that runs the gate inside its transaction, alongside the `SysRole` capability
  check and the atomic audit write.
