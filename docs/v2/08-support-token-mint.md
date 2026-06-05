# The server-side support-token mint

A system user supports a tenant by having IDMT mint a tenant-scoped,
time-bounded, audited support token on their behalf, server-side, inside a
transaction IDMT owns. IDMT does not expose this as a public RFC 8693
token-exchange grant on `/connect/token`. The mint creates the token through
`IOpenIddictTokenManager.CreateAsync` and writes the audit row in the same
transaction as the token-store insert, so the token and its audit row commit or
roll back together. There is no window where a support token exists without its
audit row, and a forced audit-write failure rolls back the already-persisted
token. This is the property the prototype's gate 2 proves.

This page is the build guide for that mint. It tells you what a support token
is, why a server-side mint is the only shape that gives you audit atomicity, and
which properties are locked. The mint is the v2 replacement for v1's shadow-row
support and ADR-0001's `/sys-switch` design, and it introduces no account
duplication: a support token is an ordinary reference token wearing one extra
scope and one extra claim.

## What you build

This section names the concrete deliverables so you can scope the work before
reading the detail. The mint is one server-side service plus a small amount of
projection and policy wiring; it reuses the existing token store, the existing
revocation path, and the existing audience handler rather than adding parallel
machinery.

You build four things:

- The mint service, modeled on the proven spike `SupportTokenService`. It opens
  an explicit transaction on the OpenIddict context, runs the system-role and
  `TenantAccess` checks, calls `IOpenIddictTokenManager.CreateAsync`, stages a
  `SupportAudit` row in the same context, and commits both writes together.
- The `support` scope and the actor projection. A support token carries the
  `support` scope and an RFC 8693 `act` (actor) claim that names the system
  user. IDMT surfaces the actor as a `support_of` alias so implementers project
  the standard claim rather than inventing a second one.
- The `SupportSession` authorization policy, exposed as a public policy-name
  constant, so a tenant endpoint can detect an impersonating system user and
  refuse destructive operations or surface a banner.
- The `SupportAudit` table, placed in the OpenIddict context so it shares the
  token store's transaction, with a required reason column.

## Source of truth

Read these artifacts before you implement, so the mint's shape, its locked
properties, and its atomicity rationale match the ADR and the proven spike
exactly. The documents below are authoritative; this page summarizes them rather
than restating them.

- [ADR 0002 §2.8, system support through a server-side token mint](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#28-system-support-through-a-server-side-token-mint).
  Read it in full: it is the decision that fixes the mint shape and the
  atomicity rationale.
- [ADR 0002 §2.9, the opinionated and customizable seam](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#29-the-opinionated-and-customizable-seam).
  Locked invariant 6 (the support-token TTL ceiling) and locked invariant 7
  (audited support with a required reason) both live in the locked set enforced
  in `Build()`.
- [ADR 0002 §2.10, endpoint scaffolding](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#210-endpoint-scaffolding).
  The `SupportSession` policy name is one of the public policy constants.
- `spike/src/Idmt.Spike.Host/Server/SupportTokenService.cs`, the proven mint.
  Read the class comment: it explains why minting through the token manager
  inside an owned transaction beats the deferred sign-in passthrough.
- `spike/tests/Idmt.Spike.Tests/Gate2_TokenExchangeAuditAtomicityTests.cs`, the
  gate 2 assertions: success persists both the token and the audit row, and a
  forced audit failure rolls back both.

## What a support token is

A support token is an ordinary tenant-audienced reference token. It is not a new
token type, and it does not travel a separate validation path. Everything that
makes it a support token is additive: one scope and one claim on top of a normal
reference token, projected at mint time.

A support token is defined by three things:

- It is a **reference (opaque) token** audienced to the target tenant, exactly
  like every other access token v2 issues. The wire value is a handle; the token
  data lives in the OpenIddict server-side store.
- It carries the `support` scope. The seeder registers `support` in the scope
  catalog (see [persistence and contexts](03-persistence-and-contexts.md)), and
  every minted support token carries it.
- It carries an RFC 8693 `act` (actor) claim that names the system user doing
  the supporting. IDMT surfaces that actor as a `support_of` alias. The standard
  claim is the source of truth; the alias is the friendly projection.

Because it is a normal reference token, a support token shares one revocation,
one expiry, and one audience code path with every other token. There is no
second session table, and no `IsSysSession` branch threaded through
authorization. A support-token revocation is the same single row update as any
other token revocation, and the same per-request audience handler binds it to
its tenant. One code path means one set of invariants to test.

## Why a server-side mint, not a public grant

The mint shape is the central decision of ADR §2.8, and it is driven entirely by
audit atomicity. You want the support token and its audit row to be a single
atomic fact: either both exist or neither does. Whether you get that property
depends on whether the audit write can enlist in the transaction that persists
the token. On a public grant it cannot; on a server-side mint it can.

On the public-grant path, OpenIddict's grant pipeline creates the token through
its **sign-in passthrough**, which runs after the request handler returns. The
token-store insert therefore happens outside any transaction the handler could
open, so an audit write the handler stages cannot share the token's transaction.
You would be left writing the audit row in a separate transaction, which
reintroduces exactly the window the mint exists to close: a token that exists
without its audit row, or an audit row without its token.

On the server-side mint path, you call `IOpenIddictTokenManager.CreateAsync`
yourself, inside a transaction you open on the OpenIddict context. The prototype
proved that the OpenIddict Entity Framework Core store resolves the **same
scoped `DbContext`** instance, so its insert enlists in your transaction. You
then stage the `SupportAudit` row in that same context, and one
`SaveChangesAsync` and one `CommitAsync` persist both writes atomically.
This is the only shape that satisfies the atomicity property, and it is a
promoted spike finding, not a paper claim.

For this reason the wire-level RFC 8693 grant is not registered. IDMT keeps the
`act`-claim semantics and drops the public grant. The
[OpenIddict server configuration](04-openiddict-server.md) does not add a
token-exchange grant type, and the mint is invoked only from the server-side
support service.

## Audit atomicity

Audit atomicity is the gate that this mint exists to pass. The audit row is
written in the same transaction as the token-store insert, before the token is
returned, with a required reason. The result is a hard guarantee: no support
token ever exists without its audit row, and no partial mint survives a failure.

The mint follows the proven spike sequence:

1. Open an explicit transaction on the OpenIddict context with
   `BeginTransactionAsync`.
2. Call `IOpenIddictTokenManager.CreateAsync`, which persists the token entry to
   that same context inside the open transaction. The token is now written but
   uncommitted.
3. Stage the `SupportAudit` row in the same context. The reason column is `NOT
   NULL`, so a missing reason fails at the database.
4. Call `SaveChangesAsync`, then `CommitAsync`. Both the token and the audit row
   commit together.

Gate 2's forced-failure case proves the rollback half of this. The test injects
an audit-write failure (a null reason that violates the `NOT NULL` column) after
the token has already been persisted in the transaction. Because the audit
`SaveChangesAsync` throws, the transaction never commits, and the
already-written token rolls back with it. A fresh scope reads the committed
state and finds neither a new token nor a new audit row. The success case proves
the other half: a clean mint increases both the token count and the audit count
by exactly one. A real audit-write failure drops the token, which is the
property the mint guarantees.

## Fixed properties

These properties are locked by ADR §2.8 and the §2.9 locked set. A consumer can
add behavior around the mint but cannot subtract any of these. They make
support a safe, audited capability rather than an unbounded back door.

The mint enforces all of the following:

- **System role plus the `TenantAccess` gate, both before the token exists.**
  The system user must hold an active `SysRole` capability, and the uniform
  [`TenantAccess` gate](06-tenant-access-gate.md) must still pass for the target
  tenant. Both checks run inside the mint, before `CreateAsync`. A system
  administrator with no active `TenantAccess` to the target tenant is denied,
  exactly as gate 2's `Gate_DeniesTenant_WithoutAccess` case asserts.
- **A required reason, audited atomically.** The audit row carries a required
  reason and is written in the same transaction as the token, before the token
  is returned. This is locked invariant 7.
- **No refresh token.** The mint issues no refresh token. When the support token
  expires, the system user must mint again, and every mint is audited. There is
  no silent extension of a support session.
- **A TTL ceiling.** The token's lifetime is bounded by a TTL ceiling. A
  consumer can lower the ceiling but cannot raise it. This is locked
  invariant 6, enforced in `Build()`.
- **The `SupportSession` policy.** The `SupportSession` authorization policy
  lets a tenant endpoint detect that the caller is an impersonating system user,
  so it can refuse destructive operations or surface a banner to its users.

## Dependencies

The mint reuses the same persistence, server, and gate machinery the rest of v2
builds, which is what keeps support on a single code path. Build or review these
before wiring the mint.

- [Persistence and contexts](03-persistence-and-contexts.md). The `SupportAudit`
  table lives in the OpenIddict context (`IdmtOpenIddictDbContext`) precisely so
  it shares the token store's transaction. Placing it in the multi-tenant
  identity context would break atomicity, because the audit write would then run
  against a different `DbContext` and could not enlist in the token's
  transaction.
- [OpenIddict server configuration](04-openiddict-server.md). The mint depends
  on reference tokens, the `support` scope being seeded, and the token-exchange
  grant staying unregistered.
- [The uniform TenantAccess gate](06-tenant-access-gate.md). The mint calls the
  same `ITenantAccessGate` port that every public grant calls, so support
  is gated by the same rule as every other issuance point.

## Acceptance criteria

These criteria are the contract the mint must meet before it ships. They map
directly to the gate 2 tests and the support TTL-cap test in the §4 test
strategy, and they are the proof that the locked properties hold against real
infrastructure rather than in description.

The mint is correct when:

- **Atomic success.** A clean mint persists both the token and the audit row,
  together, after the gate passes. The token count and the audit count each
  increase by exactly one.
- **Atomic failure.** A forced audit-write failure during a mint leaves neither
  the token nor the audit row. The shared transaction rolls back the
  already-persisted token, so a fresh read finds no new token and no new audit
  row.
- **Gate denial.** A system user with no active `TenantAccess` to the target
  tenant is denied, with no token created and no audit row written.
- **TTL cap.** A request for a lifetime above the ceiling produces a token that
  expires at or below the ceiling, never above it.

These checks land in the support-token suite. See the
[test suite](14-test-suite.md) for the full set, including the support audit
atomicity test and the support TTL cap test called out in the ADR's test
strategy.

## Next steps

With the server-side mint in place, the remaining support and endpoint work
builds on it. Continue with the browser session and the route scaffolding that
expose IDMT's surfaces to consumers.

- [Browser login and the backend-for-frontend session](09-browser-login-bff.md),
  for how a first-party browser client signs in without holding a token.
- [Endpoint scaffolding](11-endpoint-scaffolding.md), for the pre-authorized
  route groups, including the system-admin surface that invokes the support
  mint and the `SupportSession` policy a tenant endpoint reads.
