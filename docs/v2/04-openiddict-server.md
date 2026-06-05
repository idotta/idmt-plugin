# OpenIddict server engine wiring

OpenIddict is the protocol engine for IDMT v2. It issues and validates every
token, and IDMT owns only the policy that wraps it. This task stands OpenIddict
up inside `Idmt.AspNetCore`: reference (opaque) access tokens with per-request
revocation, the three supported grants, and the standard `/connect/*` protocol
endpoints. The reason this wiring is worth a dedicated task is gate 1 of the
spike, which proved instant reference-token revocation against real
infrastructure: mint a token, revoke its entry server-side, and the next bearer
request returns 401 before the token's natural time-to-live (TTL) expires. That
closes audit finding C1, the v1 gap where access tokens were never checked for
revocation.

This document describes what you wire and why. It does not restate the builder
lock mechanism (that is the seam in ADR §2.9 and a later task), the audience
binding ([`05-multitenancy-audience.md`](05-multitenancy-audience.md)), or the
`TenantAccess` gate ([`06-tenant-access-gate.md`](06-tenant-access-gate.md)).
It focuses on the OpenIddict registration itself.

## What you build

You build two OpenIddict registrations and the ASP.NET Core glue that connects
them to the request pipeline. The server side issues tokens and exposes the
protocol endpoints. The validation side reads tokens on every resource request
and enforces revocation. Both come from a single `AddOpenIddict()` call chain,
proven verbatim in the spike.

Concretely, this task delivers:

- The **server registration** (`AddServer(...)`): reference access tokens, the
  three grants, the scope catalog, the endpoint URIs, and the ASP.NET Core
  passthrough.
- The **validation registration** (`AddValidation(...)`): the co-hosted local
  validation handler with token-entry validation, so revocation is enforced per
  request.
- The **core registration** (`AddCore(...)`): the Entity Framework Core store
  bound to the dedicated OpenIddict `DbContext` from
  [`03-persistence-and-contexts.md`](03-persistence-and-contexts.md).

The bearer-only authentication scheme that resource APIs default to is
`OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme`. APIs accept a
reference token and nothing else; v1's cookie-or-bearer hybrid is gone (ADR
§2.4).

## Source of truth

The decisions this task implements are recorded in ADR 0002, and the exact API
calls are proven in the spike. When this document and the code disagree, the
spike wins, because it ran on the locked engine versions.

- ADR
  [§2.3 OpenIddict as the protocol engine](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#23-openiddict-as-the-protocol-engine)
  locks reference tokens and per-request revocation.
- ADR
  [§2.4 Authentication model: bearer-only APIs](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#24-authentication-model-bearer-only-apis)
  removes the cookie-or-bearer hybrid.
- ADR
  [§2.5 Login grant: authorization code with PKCE](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#25-login-grant-authorization-code-with-pkce)
  fixes the login grant and rejects the password grant.
- Spike wiring: `spike/src/Idmt.Spike.Host/Wiring/SpikeWiring.cs` is the exact,
  proven `AddOpenIddict().AddServer(...).AddValidation(...)` registration.
- Gate 1: `spike/tests/Idmt.Spike.Tests/Gate1_ReferenceTokenRevocationTests.cs`
  asserts the next-request 401 after a server-side revoke.

## Reference access tokens

Access tokens are reference (opaque) tokens, and this is a locked engine choice,
not a default you can flip. The reason is revocation latency. A reference token
is a handle: the wire value the client carries is an opaque identifier, and the
token data (claims, audience, expiry, status) lives in the server-side token
store. Revoking a token is a single row status update, and because validation
reads the store, that update takes effect on the very next request. A
self-contained JWT carries its claims on the wire, so it stays valid until it
expires no matter what the server does, which reintroduces the C1 revocation gap.
IDMT does not offer self-contained access tokens as an option.

You configure this on the server with `UseReferenceAccessTokens()` and
`DisableAccessTokenEncryption()`. The first makes the access token a reference
handle backed by a store entry. The second keeps the opaque handle from being an
encrypted self-contained payload, so the value is a reference to server-side data
rather than a sealed envelope the client carries. ID tokens for OpenID Connect
clients remain signed JWTs, which is protocol-correct and not a revocation
concern.

```csharp
services.AddOpenIddict()
    .AddCore(o => o.UseEntityFrameworkCore()
        .UseDbContext<IdmtOpenIddictDbContext>())
    .AddServer(o =>
    {
        // Reference (opaque) access tokens: the locked engine choice.
        o.UseReferenceAccessTokens();
        o.DisableAccessTokenEncryption();
        // ... grants, scopes, endpoints, certificates below.
    });
```

The cost of reference tokens is a store read per request, which is the deliberate
trade for instant revocation. At scale-out, instant revocation degrades to
cache-lifetime revocation without a revocation backplane; that is a near-term
hardening concern, not part of this task (see
[`15-hardening-and-open-questions.md`](15-hardening-and-open-questions.md)).

## Per-request revocation

Reference tokens give you a store to revoke against, but OpenIddict does not
check that store on every request by default. You opt into per-request revocation
on the validation side, and you must use the co-hosted local validation handler
for it to work. This is the half of the wiring that gate 1 exercises.

Two calls do the work:

- `UseLocalServer()` selects the co-hosted local validation handler. The
  resource API shares the OpenIddict server's token store in the same process,
  so validation reads the live store directly with no remote introspection hop.
- `EnableTokenEntryValidation()` makes every request check the token entry's
  status in that store. This call is mandatory whenever you use reference tokens;
  without it, revocation silently regresses to expiry-only, which is exactly the
  C1 gap this design closes.

```csharp
    .AddValidation(o =>
    {
        o.UseLocalServer();
        // Per-request revocation: read the token entry every request.
        o.EnableTokenEntryValidation();
        o.UseAspNetCore();
        // IDMT-owned per-request audience binding is added here too
        // (see 05-multitenancy-audience.md).
    });
```

Co-hosting is non-negotiable for per-request revocation. The resource API and the
OpenIddict server run in one deployable, so `UseLocalServer()` reads the shared
store. An out-of-process resource server cannot use the local handler and falls
back to remote introspection, which does not enforce per-request revocation and
so reopens C1. Distributed resource servers are out of scope for v2; the
split-deployment question lives in
[`15-hardening-and-open-questions.md`](15-hardening-and-open-questions.md).

## Supported grants

The server allows exactly three grants, and one common grant is deliberately
absent. Each grant maps to a caller type, and each is enabled with a single
`Allow...Flow()` call on the server.

- `AllowAuthorizationCodeFlow()` is the interactive browser login, with PKCE
  enforced. A user signs in at the authorization endpoint before a code is
  issued, and the backend-for-frontend exchanges that code server-side. The full
  flow is detailed in [`09-browser-login-bff.md`](09-browser-login-bff.md).
- `AllowClientCredentialsFlow()` is machine-to-machine and back-channel
  authentication, where a confidential client authenticates as itself with no
  user present.
- `AllowRefreshTokenFlow()` enables refresh tokens, which OpenIddict rotates on
  every use with reuse detection built in. A replayed (already-consumed) refresh
  token is rejected and its family revoked; that behavior is the engine's, and it
  closes audit finding N5.

```csharp
        o.AllowClientCredentialsFlow();
        o.AllowRefreshTokenFlow();
        o.AllowAuthorizationCodeFlow();
```

The **resource-owner password grant is not configured and not exposed**. OAuth
2.1 removes it, and building login on a grant the spec is deleting is a known
dead end (ADR §2.5). Trusted first-party and machine callers use the
client-credentials flow or the interactive code flow, never by posting user
credentials to the token endpoint. There is also no public RFC 8693
token-exchange grant: support tokens are minted server-side through the token
manager so the audit write shares the token-store transaction, which the public
grant pipeline cannot offer (see
[`08-support-token-mint.md`](08-support-token-mint.md)).

## Protocol endpoints

The server exposes the standard OpenIddict endpoint set, and you point the two
interactive ones at explicit URIs. The remaining endpoints follow OpenIddict's
`/connect/*` conventions. Passthrough flags let IDMT's own handlers run inside
the OpenIddict pipeline rather than have the engine answer the request alone.

You set the two endpoint URIs the flows use directly:

- `SetTokenEndpointUris("/connect/token")` is where all grants exchange for
  tokens.
- `SetAuthorizationEndpointUris("/connect/authorize")` is where the
  authorization-code flow runs the interactive sign-in.

The introspection (`/connect/introspect`), revocation (`/connect/revoke`), and
userinfo (`/connect/userinfo`) endpoints follow OpenIddict's standard
conventions.

ASP.NET Core integration comes from `UseAspNetCore()` on the server, with two
passthrough flags so IDMT handlers process the request:

- `EnableTokenEndpointPassthrough()` lets an IDMT handler run at the token
  endpoint (for example, to apply the `TenantAccess` gate and stamp the
  audience).
- `EnableAuthorizationEndpointPassthrough()` lets an IDMT handler run at the
  authorization endpoint for the interactive login.

```csharp
        o.SetTokenEndpointUris("/connect/token");
        o.SetAuthorizationEndpointUris("/connect/authorize");

        o.UseAspNetCore()
            .EnableTokenEndpointPassthrough()
            .EnableAuthorizationEndpointPassthrough()
            .DisableTransportSecurityRequirement(); // spike only: HTTP
```

The spike also called `DisableTransportSecurityRequirement()` because it runs
in-process over plain HTTP for testing. Production keeps HTTPS required and does
not call this (see the certificates section below).

## Scopes

The server declares the scopes it can issue, and a client may only request a
scope the server knows. You register the catalog with `RegisterScopes(...)`.

The spike registers two scopes:

```csharp
        o.RegisterScopes("api", "support");
```

The `api` scope is the ordinary resource scope. The `support` scope marks a
support token: a tenant-audienced reference token an IDMT system user mints
server-side to act on a tenant's behalf, carrying the RFC 8693 `act` claim. The
mint path and the `support` scope's role are detailed in
[`08-support-token-mint.md`](08-support-token-mint.md). Consumers extend this
catalog through the seeder rather than by editing the server registration.

## Certificates and production notes

OpenIddict signs and encrypts tokens with certificates, and the development
certificates the spike uses are not acceptable in production. This is a
deployment concern you must resolve before going live, called out here so it is
not forgotten.

The spike registers ephemeral development certificates:

```csharp
        o.AddDevelopmentEncryptionCertificate();
        o.AddDevelopmentSigningCertificate();
```

These generate self-signed certificates on startup, which is fine for tests and
local development but unsuitable for production: they are not persisted, not
rotated, and not shared across instances. Production must supply real signing and
encryption keys from a managed source (a certificate store, a key vault, or
configuration), and production must keep HTTPS required, so it does not call
`DisableTransportSecurityRequirement()`. Treat both as required production
configuration, not optional polish.

## Dependencies

This task depends on the persistence layer being in place first, and it composes
with the solution and package layout. The OpenIddict store has nowhere to write
without its context.

- [`03-persistence-and-contexts.md`](03-persistence-and-contexts.md) must land
  first: the dedicated, tenant-agnostic `IdmtOpenIddictDbContext` (with
  `UseOpenIddict()` applied in `OnModelCreating` or the options callback) is what
  `AddCore(...).UseDbContext<IdmtOpenIddictDbContext>()` binds to. That context
  must not derive from Finbuckle's multi-tenant context, for the reasons in ADR
  §2.6.
- [`01-solution-and-packages.md`](01-solution-and-packages.md) places this wiring
  in `Idmt.AspNetCore` and pulls the OpenIddict packages. The vendor types stay
  isolated in that package's `Server/` folder.

## Acceptance criteria

This task is done when gate 1 passes against the real handler, not a mock, and
the OAuth 2.1 posture holds. The criteria below map directly to spike tests.

- **Instant reference-token revocation (gate 1).** Mint a reference access token,
  revoke its entry server-side with
  `IOpenIddictTokenManager.TryRevokeAsync` (a single row status update), and
  assert the next bearer request returns 401 before the token's natural TTL
  expires. A request that ran fine just before the revoke must fail right after
  it. This is
  `spike/tests/Idmt.Spike.Tests/Gate1_ReferenceTokenRevocationTests.cs`.
- **No password grant.** Assert the resource-owner password grant is neither
  configured nor exposed at the token endpoint, per the OAuth 2.1 posture check
  in ADR §4.

Refresh-token reuse rejection (rotate a token, replay the consumed one, assert
rejection and family revocation) is part of the broader suite and is covered in
[`14-test-suite.md`](14-test-suite.md), not this task's gate.

## Next steps

With the engine wired and revocation proven, the next two tasks add the IDMT
policy that binds tokens to tenants. They build directly on the validation
registration above.

- [`05-multitenancy-audience.md`](05-multitenancy-audience.md) adds the
  IDMT-owned per-request audience validation handler that binds a token's `aud`
  to the Finbuckle-resolved tenant, registered on the same validation pipeline
  you wired here.
- [`06-tenant-access-gate.md`](06-tenant-access-gate.md) adds the uniform
  `TenantAccess` gate at token issuance, running through the token endpoint
  passthrough this task enabled.
