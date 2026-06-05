# Seeding and bootstrap

A running authorization server cannot start usefully without its OpenIddict
registrations in place, so IDMT supplies an `IIdmtApplicationSeeder` that
provisions them idempotently on every boot. The seeder registers the first-party
client applications, fills the scope catalog, and bootstraps the first system
administrator. That last step is the one you cannot skip: the sys-admin surface
is gated by `RequireSysAdmin`, so without a seeded first admin nobody can grant
`SysRole` to anyone, and the system locks itself out of its own administration.
This document tells you what the seeder builds, why the first-admin bootstrap is
mandatory, and how the same seeder gives integration tests a working system on
ephemeral SQLite.

## What you build

You build `IIdmtApplicationSeeder`, a startup component that brings the
authorization server from a freshly migrated, empty database up to a state where
clients can authenticate and an administrator can sign in. It does three things
on every run, each idempotently.

- Client registration through the OpenIddict application manager: the default
  first-party clients, including a confidential machine client and a public PKCE
  client for the single-page app.
- The scope catalog: the scopes the server issues, including the `support` scope
  that minted support tokens carry.
- The first system administrator: an initial `IdmtUser` with a system-role
  assignment, sourced from configuration on the first run.

## Source of truth

The shape of the seeder is fixed by the ADR and proven by the spike. Read both
before you implement so your registrations match the validated composition
rather than a fresh guess.

The bring-up plan in
[ADR 0002 §3](../../adr/0002-idmt-v2-openiddict-authorization-layer.md) records
the `IIdmtApplicationSeeder` responsibilities and the first-admin bootstrap
rationale. The proven seeding shape lives in the spike at
`spike/src/Idmt.Spike.Host/Seeding/IdmtSpikeSeeder.cs`: a confidential
`spike-client` with client credentials and the `api` and `support` scopes, a
public PKCE `spike-spa` client, seeded tenants, and a seeded sys admin with a
`SysRole` and a `TenantAccess` row.

## Idempotent startup seeding

The seeder runs on every startup and creates only what is missing. You make each
registration conditional on a lookup, so a second boot against an already-seeded
database is a sequence of no-ops, not a duplicate-key failure.

The pattern is a find-then-create guard around each item. For OpenIddict
clients, you query `IOpenIddictApplicationManager.FindByClientIdAsync` and create
the application only when it returns null. For the first admin, you query
`UserManager<IdmtUser>.FindByEmailAsync` and create the user only when it returns
null. This idempotency is what lets the seeder run unconditionally at startup:
you never branch on "is this the first boot," you branch on "does this specific
registration already exist." The spike seeder follows exactly this shape, which
is why it can run on every test-host startup without accumulating duplicates.

## Client registration

You register the default first-party clients through the OpenIddict application
manager. Two shapes from the spike are representative, and a consumer adds their
own clients through the same seeder.

The first is a confidential client for machine and back-channel use. It carries a
client id and a secret, the client-credentials grant, the token endpoint
permission, and the `api` and `support` scopes. This is the
non-interactive caller: it authenticates with its secret and receives a token
directly from `/connect/token`.

```csharp
await apps.CreateAsync(new OpenIddictApplicationDescriptor
{
    ClientId = ClientId,
    ClientSecret = ClientSecret,
    ClientType = ClientTypes.Confidential,
    Permissions =
    {
        Permissions.Endpoints.Token,
        Permissions.GrantTypes.ClientCredentials,
        Permissions.Prefixes.Scope + "api",
        Permissions.Prefixes.Scope + "support",
    },
}, ct);
```

The second is a public PKCE client for the single-page app. It has no secret
(`ClientType` is `Public`), and it carries the authorization-code and
refresh-token grants, `ResponseTypes.Code`, a registered redirect URI (the
backend-for-frontend callback), and the
`Requirements.Features.ProofKeyForCodeExchange` requirement. That requirement is
the load-bearing one: with it set, OpenIddict rejects any authorize request that
does not present a PKCE code challenge, so a non-PKCE authorize never succeeds
against this client.

```csharp
await apps.CreateAsync(new OpenIddictApplicationDescriptor
{
    ClientId = SpaClientId,
    ClientType = ClientTypes.Public,
    RedirectUris = { new Uri(SpaRedirectUri) },
    Permissions =
    {
        Permissions.Endpoints.Authorization,
        Permissions.Endpoints.Token,
        Permissions.GrantTypes.AuthorizationCode,
        Permissions.GrantTypes.RefreshToken,
        Permissions.ResponseTypes.Code,
        Permissions.Prefixes.Scope + "api",
    },
    Requirements =
    {
        Requirements.Features.ProofKeyForCodeExchange,
    },
}, ct);
```

The redirect URI here is the backend-for-frontend callback, and the public
client is the entry point for the browser login flow. See
[browser login through a backend-for-frontend](09-browser-login-bff.md) for how
the single-page app drives this client and how the host exchanges the code
server-side.

## Scope catalog

You provision the scopes the server issues so the clients above can request them
and the validation layer recognizes them. The catalog includes the application
scopes the deployment uses and the `support` scope.

The `support` scope is the one to call out. The server-side support-token mint
stamps it onto every support token so a tenant endpoint can detect an
impersonating system caller and react. That scope must exist in the catalog for
the mint to issue it and for validation to accept it. See
[the support-token mint](08-support-token-mint.md) for how the mint uses the
scope. You register application scopes the same conditional way you register
clients: look the scope up by name through `IOpenIddictScopeManager`, and create
it only when it is missing.

## First system administrator

You bootstrap the first system administrator by creating an initial `IdmtUser`
with a system-role assignment, sourced from configuration on the first run. This
is the step that keeps the system openable, and it is mandatory rather than
optional.

The reason is the gate on the sys-admin surface. `MapIdmtSysAdminApi` mounts
tenant lifecycle, `TenantAccess` grant and revoke, and system-role assignment
behind `RequireSysAdmin`. Granting `SysRole` is itself a sys-admin operation, so
on a fresh database with no system administrator, no caller can pass
`RequireSysAdmin`, which means no caller can grant `SysRole`, which means the
system can never get its first administrator through the API. That is a
locked-out bootstrap. The seeder breaks the deadlock by writing the first
administrator directly, from configuration, before any request arrives.

The first admin is not exempt from the uniform `TenantAccess` gate. The gate has
no exception for system users: a system administrator still needs an active,
unexpired `TenantAccess` row to receive a token for any tenant. So the seeder
both assigns the system role and writes a `TenantAccess` row, exactly as the
spike does when it creates `sysadmin@example.com` with `SysRoleKind.SysAdmin` and
a `TenantAccess` to tenant A. The system role lets the admin reach the sys-admin
surface; the `TenantAccess` row lets the admin act inside a tenant.

```csharp
admin = new IdmtUser
{
    UserName = SysAdminEmail,
    Email = SysAdminEmail,
    SysRole = SysRoleKind.SysAdmin,
};
await users.CreateAsync(admin, /* password from configuration */);

idDb.TenantAccess.Add(new TenantAccess { UserId = admin.Id, TenantId = TenantA });
await idDb.SaveChangesAsync(ct);
```

You source the admin's email and initial credential from configuration so they
are not hard-coded, and you create the row only when the user does not already
exist, which keeps the bootstrap idempotent alongside everything else.

## Development and testing

The same seeder gives the integration-test stack a working system. It runs
against the ephemeral SQLite database the tests already use, seeding a test
client, test tenants, and a seeded system administrator, so a test host comes up
fully provisioned.

This is how the spike and the existing integration tests bootstrap. The seeder
ensures the contexts exist, registers the `spike-client` and `spike-spa`
clients, seeds the `acme` and `globex` tenants, and creates the seeded sys admin
plus a plain backend-for-frontend user, each behind an idempotency guard. Because
every step is create-only-missing, the seeder runs on every test-host startup
without duplicating registrations, so each test run starts from the same known
state.

## Dependencies

Seeding sits late in the build even though it is conceptually setup work, because
it depends on infrastructure that earlier tasks stand up. You cannot seed into a
database that does not exist or write tokens against a server that is not wired.

- [Persistence and contexts](03-persistence-and-contexts.md): both the
  multi-tenant application context and the tenant-agnostic OpenIddict context must
  exist and be migrated before the seeder writes the admin row or the client
  registrations.
- [The OpenIddict server](04-openiddict-server.md): the application, scope, and
  token managers the seeder calls come from the wired OpenIddict server, so the
  server registration runs first.
- [Browser login through a backend-for-frontend](09-browser-login-bff.md): the
  public PKCE client and its redirect URI that the seeder registers are what the
  browser login flow consumes.

## Acceptance criteria

You know the seeder is correct when a freshly migrated database comes up
provisioned and stays provisioned across reboots. The criteria below are the
checks that prove it.

- After seeding, the configured clients exist in the OpenIddict application
  store, and the public client rejects a non-PKCE authorize request (the
  `ProofKeyForCodeExchange` requirement is enforced, not decorative).
- The `support` scope exists in the scope catalog, so the support-token mint can
  issue it and validation accepts it.
- The first administrator can authenticate and reach the sys-admin surface behind
  `RequireSysAdmin`, and holds a `TenantAccess` row that lets the admin act in a
  tenant.
- Re-running the seeder against an already-seeded database creates no duplicate
  clients, scopes, tenants, or users.

## Next steps

With the system seeded, you have a host that integration tests can exercise end
to end. Continue with [the test suite](14-test-suite.md), which gates every
locked invariant and uses this seeded bootstrap to stand up its host.
