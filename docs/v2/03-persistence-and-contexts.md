# Persistence and contexts

The v2 persistence layer is a physical split into three Entity Framework Core
contexts, each with its own independent migration history. This is a real
context split, not a single context presented as "conceptually consolidated":
the product ships the three contexts named below and the spike proved the split,
not a merge. `IdmtDbContext` is the multi-tenant application and identity
context: it holds the canonical identity tables and lets Finbuckle stamp
`TenantId` on save. `IdmtOpenIddictDbContext` is a separate, tenant-agnostic
context that hosts the OpenIddict stores and never derives from Finbuckle's
`MultiTenantDbContext`. `IdmtTenantStoreDbContext` is the dedicated tenant-store
context that persists the tenant metadata Finbuckle resolves against. You split
persistence this way because the token endpoint issues tokens in a pipeline
scope where the ambient tenant is often unset, and a Finbuckle-derived context
would try to stamp and filter on `TenantId` there, which throws or mis-stamps.

This split is the sharpest integration risk in v2, the reconciliation of
Finbuckle's tenant stamping with OpenIddict's token stores, and the spike's
gate 4 proved it composes. Gate 4 asserts that the token endpoint reads and
writes tokens with no ambient tenant, that a multi-tenant application entity
saved under a tenant carries that tenant's `TenantId`, and that the OpenIddict
token entity has no `TenantId` column at all.

## What you build

You build three contexts and three migration histories, one history per context.
The contexts may share a database, but they never share a migration history, so
each evolves on its own schedule and neither stamps the other's tables. Each
context names its own `MigrationsHistoryTable` so the histories cannot collide in
a shared database (see [Migrations](#migrations)).

- `IdmtDbContext`: the multi-tenant application and identity context. It holds
  `IdmtUser`, `IdmtRole`, `TenantAccess`, `ClientTenantAccess`, the system-role
  assignment, and the email-change staging. Finbuckle stamps `TenantId` on the
  multi-tenant entities at `SaveChanges` and fixes the context's tenant for its
  lifetime.
- `IdmtOpenIddictDbContext`: the tenant-agnostic OpenIddict context. It hosts
  the OpenIddict application, authorization, scope, and token stores through
  `builder.UseOpenIddict()`, plus the support-audit table (owned here for
  transaction atomicity, see [the tenant-agnostic OpenIddict
  context](#the-tenant-agnostic-openiddict-context)). It does not derive from
  `MultiTenantDbContext`, so Finbuckle never stamps or filters its tables.
- `IdmtTenantStoreDbContext`: the dedicated tenant-store context that persists
  the tenant metadata Finbuckle resolves against.
- Three migration histories, generated and applied with the `dotnet ef` commands
  in [Migrations](#migrations).

## Source of truth

The authoritative design lives in the ADR, and the proven shape lives in the
spike. Read both before you implement, because the spike is the executable
contract for what the ADR fixes in prose.

- [ADR 0002 §2.6 multi-tenancy
  integration](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#26-multi-tenancy-integration):
  the paragraph that mandates a separate, tenant-agnostic OpenIddict context.
- [ADR 0002 §3 bring-up
  plan](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#3-bring-up-plan):
  the two migration histories and the exact `dotnet ef` commands.
- `spike/src/Idmt.Spike.Host/Persistence/Contexts.cs`: the proven shape.
  `IdmtOpenIddictDbContext` is a plain `DbContext` whose `OnModelCreating`
  calls `builder.UseOpenIddict()`, and the multi-tenant context extends
  Finbuckle's `MultiTenantDbContext`.
- `spike/tests/Idmt.Spike.Tests/Gate4_DualContextCompositionTests.cs`: what
  gate 4 asserts, mapped into the [acceptance
  criteria](#acceptance-criteria) below.

## The multi-tenant application context

`IdmtDbContext` is the application and identity context. It holds the canonical
identity model and the tenant-scoped application tables, and it lets Finbuckle
do its full job: stamp `TenantId` on save and apply read-side query filters per
the ambient tenant.

The tables it owns are the application side of v2:

- `IdmtUser`: the global canonical identity, one row per human.
- `IdmtRole`: the per-tenant role.
- `TenantAccess`: the user-to-tenant edge the issuance gate queries.
- `ClientTenantAccess`: the machine-client-to-tenant edge the client-credentials
  gate queries (the client analog of `TenantAccess`, defined in
  [02-core-domain.md](02-core-domain.md)). It belongs with the multi-tenant
  application and identity data, so it lives in this context and this context's
  migration history.
- the system-role assignment.
- the email-change staging table.

The support-audit table is not owned here. It lives in the OpenIddict context so
the audit row and the token-store insert commit or roll back together. See [the
tenant-agnostic OpenIddict context](#the-tenant-agnostic-openiddict-context),
with [08-support-token-mint.md](08-support-token-mint.md) authoritative for the
atomicity guarantee that drives the placement.

Finbuckle stamps `TenantId` onto tracked multi-tenant entities on `SaveChanges`
and treats the context's tenant as fixed for its lifetime. The spike split the
application side across two contexts to isolate each half of gate 4:
`IdmtIdentityDbContext` holds the global identity rows plus `TenantAccess` as a
plain (non-multi-tenant) context, because the gate must query `TenantAccess` by
`(userId, tenantId)` at the token endpoint where there is no ambient tenant,
and `IdmtTenantDbContext` extends `MultiTenantDbContext` and holds the
`[MultiTenant]` entity whose `TenantId` is stamped on save. The product keeps
this as a real physical split rather than collapsing it into one
`MultiTenantDbContext`, because the gate's no-ambient-tenant query is exactly
what the split proves works. The names above are the spike's; the product's
application-side context is `IdmtDbContext`, and where the gate must read
`TenantAccess` with no ambient tenant it does so through the plain (non-Finbuckle)
half of that split.

## The tenant-agnostic OpenIddict context

`IdmtOpenIddictDbContext` is a separate, tenant-agnostic context. It is a plain
`DbContext` that never derives from Finbuckle's `MultiTenantDbContext`, so
Finbuckle never stamps or filters its tables. It hosts the OpenIddict
application, authorization, scope, and token stores, and the spike registers
them in `OnModelCreating` with one call:

```csharp
protected override void OnModelCreating(ModelBuilder builder)
{
    base.OnModelCreating(builder);
    builder.UseOpenIddict();
}
```

The OpenIddict token entity has no `TenantId` column. There is no per-request
tenant on these tables, because the token endpoint runs in a scope where the
ambient tenant is often unset. Tenant binding lives in the token's `aud` claim
and the IDMT-owned audience validation handler, not in a database column on the
token entry. Gate 4 asserts this directly: it resolves the model's
`OpenIddictEntityFrameworkCoreToken` entity type and asserts
`FindProperty("TenantId")` returns null.

This context must not derive from `MultiTenantDbContext`. A Finbuckle-derived
context does two things that break the token endpoint: it stamps `TenantId` on
tracked entities at `SaveChanges`, and it applies a read-side query filter
keyed on the ambient tenant. At the token endpoint there is no ambient tenant,
so the stamp throws or writes a wrong value and the filter hides rows the
endpoint must read. A plain context avoids both the save-side stamping and the
read-side filtering, which is why the split is mandatory and not a tuning
choice.

The support-audit table lives in this context, not in `IdmtDbContext`. The
support audit must share OpenIddict's transaction so the audit row and the
token-store insert commit or roll back together, so `SupportAudit` is owned by
this context's migration history. The spike places `SupportAudit` in
`IdmtOpenIddictDbContext` for exactly this reason: the OpenIddict store resolves
the same scoped `DbContext`, so the token insert enlists in IDMT's transaction,
and a forced audit-write failure rolls back the already-persisted token. See
[08-support-token-mint.md](08-support-token-mint.md) for the mint flow and the
atomicity guarantee that drives this placement; 08 is authoritative for the
support-audit ownership.

## Why two contexts

The token endpoint has no ambient tenant, and that single fact forces the
split. The authorization-code flow resolves a tenant at `/connect/authorize`,
but the refresh grant reaches `/connect/token` with no tenant route segment,
and the support-token mint runs server-side with no public grant at all. In
those scopes the ambient tenant is unset.

A Finbuckle-derived context assumes an ambient tenant on every save and every
read. On save it stamps `TenantId` onto tracked multi-tenant entities, so an
OpenIddict token insert at the token endpoint either throws because no tenant
is resolved or stamps a wrong value if a stale one is. On read it filters rows
by the ambient tenant, so a token lookup at the endpoint that resolves no
tenant hides the rows it must find. Both failures are silent in the sense that
they pass a naive smoke test and only surface under the real grant flows, which
is exactly why the spike had to prove the composition end to end before the ADR
was ratified.

A dedicated, tenant-agnostic context sidesteps both. OpenIddict's tables carry
no tenant column, the context never stamps and never filters, and tenant
isolation is enforced where it belongs: in the token's `aud` claim and the
per-request audience handler that compares `aud` to the Finbuckle-resolved
tenant. The application tables keep Finbuckle's stamping and filtering, the
OAuth tables opt out of it, and the two coexist in one database.

## Migrations

Each context owns an independent migration history. You generate and apply each
history with its own `dotnet ef` command targeting the context by name, so the
three schemas evolve and deploy without colliding.

Generate the initial schema, one migration per context, then apply each:

```bash
dotnet ef migrations add InitialCreate --context IdmtDbContext
dotnet ef migrations add InitialCreate --context IdmtOpenIddictDbContext
dotnet ef migrations add InitialCreate --context IdmtTenantStoreDbContext
dotnet ef database update --context IdmtDbContext
dotnet ef database update --context IdmtOpenIddictDbContext
dotnet ef database update --context IdmtTenantStoreDbContext
```

When the three contexts share a database, give each its own history table so the
default `__EFMigrationsHistory` table does not collide. Each context sets a
distinct `MigrationsHistoryTable` (or a distinct schema) on its provider
configuration, for example:

```csharp
options.UseSqlite(
    connectionString,
    sql => sql.MigrationsHistoryTable("__IdmtMigrationsHistory"));
// IdmtOpenIddictDbContext -> "__IdmtOpenIddictMigrationsHistory"
// IdmtTenantStoreDbContext -> "__IdmtTenantStoreMigrationsHistory"
```

The spike ran the contexts on separate in-memory SQLite connections, so it never
exercised the shared-database case. The per-context history table is the
provision that makes a single shared database safe for the three histories.

There is no `RevokedToken` table in v2. The OpenIddict token store is
authoritative for revocation, so a revocation is a row update in the OpenIddict
token entry, not an insert into a separate revocation table. This is a
deliberate contrast with v1, which hand-rolled a `RevokedToken` table and a
`TokenRevocationService`; v2 deletes both and rents revocation from the engine.

The provider differs by environment. Production uses a real relational
provider. Development and tests use SQLite, and the spike used in-memory SQLite
connections held open for the host lifetime so the ephemeral database survives
across requests within a test run.

## Dependencies

This doc sits on top of the domain model and the package layout, and it assumes
both are in place before you stand up the contexts.

- [02-core-domain.md](02-core-domain.md): the `IdmtUser`, `IdmtRole`,
  `TenantAccess`, system-role, and support-audit entities the contexts map.
- [01-solution-and-packages.md](01-solution-and-packages.md): the package
  layout that places these contexts in `Idmt.AspNetCore` and keeps Entity
  Framework Core types out of `Idmt.Core`.

## Acceptance criteria

These criteria are the gate 4 equivalents, lifted from
`spike/tests/Idmt.Spike.Tests/Gate4_DualContextCompositionTests.cs`. You meet
the persistence-layer bar when all three hold against real infrastructure, not
a mocked store.

- The token endpoint reads and writes tokens with no `X-Tenant` resolved. A
  token request that carries no tenant header still issues a token and persists
  a token entry to `IdmtOpenIddictDbContext`.
- A multi-tenant application entity saved under tenant A carries tenant A's
  `TenantId`. Finbuckle stamps the entity's `TenantId` to the resolved tenant's
  id on save.
- The OpenIddict token entity exposes no `TenantId`. The
  `OpenIddictEntityFrameworkCoreToken` entity type in the model has no
  `TenantId` property.

## Next steps

With the three contexts and their migration histories in place, you wire the
OpenIddict server on top of `IdmtOpenIddictDbContext`. That configuration locks
reference tokens, token-entry validation, refresh rotation, and the audience
handler.

- [04-openiddict-server.md](04-openiddict-server.md): the OpenIddict server
  configuration that consumes the tenant-agnostic context.
