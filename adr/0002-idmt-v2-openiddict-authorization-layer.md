# ADR 0002 — IDMT v2: OpenIddict-based multi-tenant authorization layer

- **Status:** Accepted — prototype gate passed (see [§7](#7-prototype-gate-and-open-questions))
- **Date:** June 4, 2026 (accepted June 5, 2026)
- **Deciders:** @idotta
- **Affects:** `idmt-plugin` (v2 greenfield rewrite), downstream .NET products that consume it
- **Supersedes:** ADR-0001 §2.3–2.4 (`ServerSession`, `/sys-switch`, step-up) — in part

## 1. Context

This ADR records the target architecture for a greenfield v2 rewrite of IDMT.
It commits to a single design so implementation proceeds against one source of
truth. The design itself was produced by three parallel architect sketches and
a scored evaluation; this document is the decision, and those artifacts are the
research behind it (see [References](#8-references)).

IDMT v1 hand-rolls its own bearer-token machinery on top of ASP.NET Core
Identity and Finbuckle.MultiTenant. A multi-agent security audit
(`SECURITY_AUDIT.md`) found that the remaining work is not "harden our auth" but
"build an identity provider." The open backlog — access-token revocation
enforcement (C1), refresh-token rotation (N5), opaque server-side sessions,
a sys-switch flow, step-up authentication, and multi-factor authentication — is
all commodity identity-provider machinery. ADR-0001 proposed to build a large
part of it by hand (a `ServerSession` table, a `/sys-switch` endpoint, step-up
tracking).

The v2 insight is that you must stop competing with mature identity engines on
commodity machinery and instead own only the part that is genuinely yours: the
multi-tenant authorization model and the endpoint scaffolding. **OpenIddict**
provides the protocol engine; IDMT provides the policy.

OpenIddict closes the audit backlog structurally rather than line by line:

| Audit / ADR-0001 item | How v2 closes it |
|---|---|
| C1 — access tokens never checked for revocation | Reference (opaque) access tokens, validated server-side on every request |
| N5 — no refresh-token rotation | OpenIddict refresh-token rotation with reuse detection |
| M2 — `IssuedUtc` drift | Handled by the engine's token store |
| `TokenRevocationService` / `RevokedToken` | The OpenIddict token store is authoritative |
| ADR-0001 `ServerSession` + 30s cache + opaque cookie | Reference tokens — token data lives server-side, the wire value is a handle |
| ADR-0001 `/sys-switch` | Server-side support-token mint with the RFC 8693 `act` claim |

v2 retains ASP.NET Core Identity as the user store, Finbuckle for tenant
resolution, and the canonical identity model from ADR-0001 as design choices. It
does not build the bearer-token and session machinery OpenIddict now owns.

## 2. Decision

This section records the committed architecture. Each subsection is a decision,
not an option.

### 2.1 Thesis: own the policy, rent the protocol

IDMT v2 is a thin, opinionated multi-tenant authorization layer wrapped around
OpenIddict. The division of responsibility is fixed.

OpenIddict owns every commodity OAuth 2.0 and OpenID Connect concern: the
authorize, token, introspection, revocation, and userinfo endpoints; refresh
rotation; and reference tokens. ASP.NET Core Identity remains
the user and credential store. Finbuckle.MultiTenant remains the tenant
resolver. IDMT contributes exactly three things of its own: the canonical
identity and `TenantAccess` and `SysRole` authorization model projected into
tokens, the opinionated wiring that composes these engines correctly for
multi-tenancy, and the endpoint scaffolding that hands consumers pre-authorized
route groups for both the tenant side and the system-admin side.

### 2.2 Module boundaries: three packages

v2 ships as three NuGet packages. The boundary that matters is the one that
keeps infrastructure types out of the domain, and you enforce it with a test,
not a convention.

- `Idmt.Core` — the domain. Canonical `IdmtUser`, `IdmtRole`, `TenantAccess`,
  `SysRole`, the authorization policies, the support-capability rule, and the
  repository and service ports. This package references no infrastructure: no
  OpenIddict, no Finbuckle, no Entity Framework Core, no ASP.NET Core.
- `Idmt.AspNetCore` — the composition root and the only package most consumers
  add. It pulls `Idmt.Core` and hosts the OpenIddict, Finbuckle, Entity
  Framework Core, endpoint, and email integrations in dedicated folders
  (`Server/`, `MultiTenancy/`, `Persistence/`, `Endpoints/`). Vendor types live
  here, isolated by folder.
- `Idmt.Mfa` — opt-in multi-factor support (TOTP now, WebAuthn through
  `fido2-net-lib` later). It is a separate package so the WebAuthn dependency
  stays off the main package for consumers who do not need it.

An `Idmt.Architecture.Tests` project enforces the dependency rule as a fitness
function: `Idmt.Core` must not reference any infrastructure assembly. This makes
the firewall a compile-and-test guarantee rather than a code-review habit. v1
conflated "feature folder" with "layer," which is how `GrantTenantAccess.cs`
ended up performing shadow-row surgery; the architecture test prevents the
recurrence regardless of how few packages you ship.

The architecture test recovers the domain-isolation benefit of a finer split, but
not all of it. With OpenIddict, Finbuckle, and Entity Framework Core all hosted in
`Idmt.AspNetCore`, a major-version bump in any one of them touches the same
assembly. We consciously accept that vendor-version blast radius as the cost of
shipping three packages instead of five.

### 2.3 OpenIddict as the protocol engine

OpenIddict issues and validates all tokens. Two engine choices are locked
because reversing them would reopen the gaps this ADR exists to close.

Access tokens are **reference (opaque) tokens**. The wire value is a handle, and
the token data lives in the server-side store. Per-request revocation checking is
not OpenIddict's default; it requires `EnableTokenEntryValidation()`, which is
mandatory whenever reference tokens are used and which enforces revocation only
when the API uses the co-hosted local validation handler (`UseLocalServer()`),
not remote introspection. With that call in place, validation reads the token
entry, and a revocation is a single row update that takes effect on the next
request for any instance whose view of the token store is not stale. When the
local handler caches token-entry lookups and the deployment runs more than one
instance, that staleness window is bounded by the cache lifetime, which is the
scale-out concern that [§5.2](#52-risk-and-mitigation) treats as a near-term
backplane requirement, not by any property of the wire token. We lock both
`EnableTokenEntryValidation()` and the local
validation handler in [§2.9](#29-the-opinionated-and-customizable-seam); without
them, instant revocation silently regresses to expiry-only, which is the exact v1
gap (audit finding C1) this design closes. Self-contained JWT access tokens are
not offered as an option, because that choice would reintroduce the same latency.
ID tokens for OpenID Connect clients remain signed JWTs, which is
protocol-correct and not a revocation concern.

Refresh tokens rotate on every use, with reuse detection. The protocol endpoints
follow OpenIddict conventions (`/connect/token`, `/connect/authorize`,
`/connect/introspect`, `/connect/revoke`, `/connect/userinfo`).

Per-request revocation through the local validation handler assumes the resource
API is co-hosted with the OpenIddict server in one deployable. v2 commits to that
topology: the consuming product hosts both, so `UseLocalServer()` is available and
revocation is enforced against the shared token store. An out-of-process resource
server cannot use the local handler and falls back to remote introspection, which
does not enforce per-request revocation and so reopens the C1 gap. Distributed
resource servers are out of scope for v2; the split-deployment story, including
whether introspection without response caching is acceptable, is an open question
(see [§7.1](#71-open-questions)).

### 2.4 Authentication model: bearer-only APIs

API traffic authenticates with bearer reference tokens only. This removes v1's
hybrid cookie-or-bearer model and the bug class that came with it.

v1 ran a `CookieOrBearer` policy scheme that selected cookie or bearer
authentication per request, and a `ValidateBearerTokenTenantMiddleware` that
re-checked the tenant. The two paths diverged in subtle ways. In v2, every
**resource** request carries a reference token, and v2 does not build a
`CookieOrBearer` resource-layer scheme at all.

This does not remove cookies entirely; it confines them to two roles, neither of
which is a resource-layer credential. First, the authorization-code flow in
[§2.5](#25-login-grant-authorization-code-with-pkce) requires an interactive,
cookie-backed session at `/connect/authorize`, where the user signs in before a
code is issued. Second, a first-party single-page application authenticates
through a backend-for-frontend session cookie
([§2.5.1](#251-browser-clients-use-a-backend-for-frontend-session)) that the host
resolves to a server-side reference token before any resource logic runs. Both
cookies must stay tenant-aware, so they use per-tenant naming, the same approach
v1 took, and §4 tests that neither can be replayed across tenants. The cookie
complexity moves from the resource layer to the authorize endpoint and the
backend-for-frontend layer rather than disappearing. The resource API itself
accepts only a reference token. The tenant re-check that v1 did in
`ValidateBearerTokenTenantMiddleware` is replaced by an IDMT-owned validation
handler described in [§2.6](#26-multi-tenancy-integration), not by deleting the
check.

### 2.5 Login grant: authorization code with PKCE

Interactive login uses the authorization-code flow with PKCE. This is the
OAuth 2.1-aligned choice and it does not depend on a grant type that the spec is
removing.

The resource-owner password grant is not surfaced. OAuth 2.1 removes it, and
building login on it would create a known dead end. Trusted first-party and
machine clients authenticate through the client-credentials flow or a documented
code exchange rather than by posting user credentials to the token endpoint. The
exact shape of first-party machine authentication is an open question (see
[§7](#7-prototype-gate-and-open-questions)), but the decision to avoid the
password grant is fixed.

### 2.5.1 Browser clients use a backend-for-frontend session

A first-party single-page application authenticates through a
backend-for-frontend session, not by holding a token in the browser. This is the
one sanctioned way a cookie reaches a request that ends at a resource endpoint,
and it is deliberately not the v1 hybrid.

Storing an access or refresh token in JavaScript exposes it to exfiltration
through any cross-site-scripting flaw, so v2 never hands a token to the browser.
Instead, the single-page app runs the authorization-code flow with PKCE against
the co-hosted host, and the host keeps the resulting reference token server-side.
The browser holds only an `httpOnly`, `Secure`, `SameSite` session cookie. The
host maps that cookie to the server-side reference token on each request and
processes the request through the **same** reference-token path every other client
uses: the same `TenantAccess` gate, the same audience validation handler, and the
same revocation. The cookie is one more handle to the same server-side token
entry, exactly as the reference token is a handle to server-side token data.

This is why the backend-for-frontend session is not v1's cookie-or-bearer hybrid.
The v1 bug class came from the resource layer validating a cookie path
*independently* of the bearer path, so the two diverged. Here the resource layer
still validates exactly one thing — the reference token — and the cookie is
resolved to that token before any resource logic runs. The resource API never
accepts a cookie as a credential of its own.

Three properties are fixed. The session cookie reuses the per-tenant naming from
[§2.4](#24-authentication-model-bearer-only-apis), so a tenant-A session cannot
drive a tenant-B request. Because the browser now sends an ambient credential,
cross-site request forgery protection (a `SameSite` cookie plus an anti-forgery
token) is mandatory and is in the [§2.9](#29-the-opinionated-and-customizable-seam)
locked set. The cookie-to-token resolution is the only place a cookie touches a
resource request, and the [§7.0](#70-prototype-gate-precondition-to-ratification)
gate must prove it runs the same audience handler as a raw bearer request.

The co-hosting commitment from [§2.3](#23-openiddict-as-the-protocol-engine) is
what makes this cheap: the backend that holds the session is the same process that
hosts the authorization server and the resource endpoints, so the
backend-for-frontend layer is not a new deployable. A consumer that does not ship
a browser client ignores this entirely; the session surface is opt-in.

### 2.6 Multi-tenancy integration

Finbuckle resolves the tenant from the request, and the token's audience binds
the token to that tenant. The token audience is the single source of truth at the
resource, but both stamping it and checking it are code IDMT owns; the engine
does neither dynamically on its own.

At issuance, the tenant is resolved and stamped into the access token's `aud`
claim. The authorization-code flow resolves the tenant at `/connect/authorize`.
The refresh grant reaches `/connect/token` with no tenant route segment, so the
client supplies the tenant through the RFC 8707 `resource` parameter as
`urn:idmt:tenant:{identifier}`. (Support tokens carry no public grant; IDMT mints
them server-side and sets their `aud` directly — see
[§2.8](#28-system-support-through-a-server-side-token-mint).) We lock the `resource`-parameter
convention rather than route-based resolution (`/{tenant}/connect/token`) so the
OpenID Connect discovery document stays single-issuer and conformant. The cost is
that clients must send the `resource` parameter, which is a documented
requirement.

For a refresh, the tenant is authoritative from the presented refresh token's
original `aud`, not from the `resource` parameter. If a client sends a `resource`
parameter on refresh, it must match the token's `aud`; a mismatch is rejected.
This precedence prevents a client from presenting a tenant-A refresh token with
`resource=urn:idmt:tenant:B` to mint a tenant-B access token. The §4 cross-grant
audience-isolation test asserts exactly this rejection.

At the resource, OpenIddict's built-in audience validation compares `aud` only
against a **static** configured audience set, not against a per-request resolved
tenant. Per-request enforcement is therefore an **IDMT-owned validation handler**
that compares the token's `aud` to the Finbuckle-resolved tenant through
`IMultiTenantContextAccessor` and rejects a mismatch. This handler is the
successor to v1's `ValidateBearerTokenTenantMiddleware`, relocated into the
OpenIddict validation pipeline and the correct layer, not deleted. It is in the
[§2.9](#29-the-opinionated-and-customizable-seam) locked set, and the §4
route-mutation fuzzer exercises the real handler.

The OpenIddict Entity Framework Core stores (application, authorization, scope,
and token) live in a **separate `DbContext` that does not derive from Finbuckle's
`MultiTenantDbContext`**. This is mandatory, not a tuning choice. Finbuckle does
not only add read-side query filters; it also stamps `TenantId` onto tracked
multi-tenant entities on `SaveChanges` and treats a context's tenant as fixed for
its lifetime. The token endpoint issues tokens in a pipeline scope where the
ambient tenant is often unset, so routing OpenIddict's writes through a
multi-tenant context would throw or mis-stamp. A dedicated, tenant-agnostic
context for the OAuth tables avoids both the save-side stamping and the read-side
filtering. Proving this composition end to end is the first item of the
[§7](#7-prototype-gate-and-open-questions) prototype gate.

### 2.7 Canonical identity, carried from ADR-0001

The identity model from ADR-0001 stays, and the access gate gets stronger. This
is the part of ADR-0001 that v2 keeps rather than supersedes.

`IdmtUser` remains the global canonical identity, one row per human, with a
globally unique normalized email. `IdmtRole` remains per-tenant via an explicit,
declared `TenantId` column scoped by explicit query, not a Finbuckle filter,
because issuance projects role claims at the no-ambient-tenant token endpoint
(see [docs/v2/06-tenant-access-gate.md](../docs/v2/06-tenant-access-gate.md) and
[docs/v2/03a](../docs/v2/03a-idmtdbcontext-base-class-rectification.md)). `SysRole`
remains the global system-role flag. `TenantAccess` remains the user-to-tenant
edge with `IsActive` and optional `ExpiresAt`. The uniform `TenantAccess` gate
remains: no user, including a system administrator, gets a token for a tenant
without an active, unexpired `TenantAccess` row. In v2 the gate runs not only at
login but at token issuance across every grant type, and at every server-side
support-token mint ([§2.8](#28-system-support-through-a-server-side-token-mint)).

Propagating credential changes to issued tokens is IDMT's responsibility, not an
automatic engine behavior. ASP.NET Core Identity's `SecurityStamp` rotation does
not revoke OpenIddict reference tokens on its own. IDMT registers a hook on the
credential-change paths (password change, email change, `UpdateSecurityStampAsync`,
deactivation, and compromise response). For a full credential change, the hook
drops every token the user holds in one call:
`IOpenIddictTokenManager.RevokeBySubjectAsync`. A token entry records no audience
to filter on — the audience lives only in the encrypted token payload — so
dropping a *single* tenant's tokens uses **authorization grouping** instead:
every tenant-scoped token a user holds is minted under one OpenIddict
authorization keyed to (user, tenant), and revoking that tenant calls
`RevokeByAuthorizationIdAsync`. The prototype proved both single calls against
real infrastructure, including a 100-token user, so cost does not scale with the
number of tokens held. The `SecurityStamp` remains the source-of-truth signal;
this hook is the enforcement, and it is in the
[§2.9](#29-the-opinionated-and-customizable-seam) locked set.

### 2.8 System support through a server-side token mint

A system user supports a tenant by having IDMT mint a tenant-scoped,
time-bounded, audited support token on their behalf. This replaces v1's
shadow-row approach and ADR-0001's `/sys-switch` design, and it introduces no
account duplication.

A support token is an ordinary tenant-audienced reference token with a `support`
scope and an actor claim that names the system user. The actor claim is the
standard RFC 8693 `act` claim; `support_of` is IDMT's surfaced alias for it, so
implementers project the standard claim rather than inventing a second one.
Because it is a normal reference token, it shares one revocation, expiry, and
audience code path with every other token; there is no second session table and
no `IsSysSession` branch threaded through authorization.

IDMT mints the support token server-side, through
`IOpenIddictTokenManager.CreateAsync` inside a transaction IDMT owns, rather than
exposing RFC 8693 as a public grant on `/connect/token`. This is a deliberate
constraint, and the prototype proved it is the only shape that satisfies the
audit-atomicity property below. OpenIddict's grant pipeline creates the token
through its sign-in passthrough after the request handler returns, outside any
transaction the handler could open, so an audit write cannot be enlisted with the
token-store insert on the public-grant path. Minting through the token manager in
an IDMT-owned transaction is what lets the audit row and the token row commit or
roll back together. The wire-level RFC 8693 grant is therefore not registered;
the `act`-claim semantics are kept, the public grant is not.

The flow has fixed properties:

- The system user must hold an active `SysRole` capability, and the uniform
  `TenantAccess` gate still applies to the target tenant. Both checks run inside
  the mint, before the token is created.
- The audit record is written in the same transaction as the token-store insert,
  before the token is returned, so there is no window where a support token
  exists without an audit row. The prototype proved this against real
  infrastructure: the OpenIddict Entity Framework Core store resolves the same
  scoped `DbContext`, so its insert enlists in IDMT's transaction, and a forced
  audit-write failure rolls back the already-persisted token.
- No refresh token is issued. When the support token expires, the system user
  must mint again, and each mint is audited.
- The token's lifetime is bounded by a TTL ceiling. A consumer can lower the
  ceiling but cannot raise it.
- A `SupportSession` authorization policy lets a tenant endpoint detect that the
  caller is an impersonating system user and refuse destructive operations or
  surface a banner.

### 2.9 The opinionated and customizable seam

This is the central design problem, and the rule is structural. Security
invariants are locked and applied unconditionally; shape and surface are open.

A customizable security library fails when a consumer customizes away a security
property without noticing. v2 prevents this by applying the locked behavior
inside the builder's `Build()` step regardless of what the consumer called, and
by making the locked set additive-only in the type system. A consumer can add
behavior; a consumer cannot subtract a security property.

The locked set, enforced in `Build()`:

- The uniform `TenantAccess` gate, applied at token issuance for every grant and
  at every server-side support-token mint.
- Reference access tokens **with `EnableTokenEntryValidation()` and the co-hosted
  local validation handler**, so revocation is enforced per request
  ([§2.3](#23-openiddict-as-the-protocol-engine)).
- Refresh-token rotation with reuse detection.
- The IDMT-owned per-request audience validation handler that binds a token to
  the Finbuckle-resolved tenant ([§2.6](#26-multi-tenancy-integration)).
- The `SecurityStamp`-change propagation hook that revokes a user's tokens —
  `RevokeBySubjectAsync` for a full credential change, `RevokeByAuthorizationIdAsync`
  on the per-tenant authorization for a single-tenant revoke
  ([§2.7](#27-canonical-identity-carried-from-adr-0001)).
- The support-token TTL ceiling.
- Audited support, with a required reason.
- A second authentication factor for system users and for users with access to
  more than one tenant (see the MFA rule below).
- Cross-site request forgery protection on the backend-for-frontend session
  (`SameSite` cookie plus an anti-forgery token), whenever the session surface is
  enabled ([§2.5.1](#251-browser-clients-use-a-backend-for-frontend-session)).

The open set, exposed as named extension points:

- Claims enrichment that adds claims after the gate has run.
- Tenant-resolution strategy (route, header, claim, base path, or custom).
- Multi-factor factor selection, subject to the locked rule that system users
  must hold a second factor.
- Email transport and link generation.
- Additional authorization policies layered on the built-ins.
- Consumer endpoints mounted under the pre-attached policy groups.
- The store backend, through the `Idmt.Core` repository ports.

The second-factor rule is a domain invariant in `Idmt.Core`, not a feature of the
opt-in `Idmt.Mfa` package. `Idmt.Mfa` supplies factor *implementations* (TOTP
now, WebAuthn later); the *requirement* that a system user or a multi-tenant user
must satisfy a second factor before a token issues lives in the core gate. The
fail-fast at `Build()` is scoped to deployments that can actually produce a
triggering user: when MFA enforcement is on (the default) and no factor provider
is registered, `Build()` throws only if the deployment maps the sys-admin surface
or permits multi-tenant membership. A purely single-tenant app with no sys-admin
surface never trips the check and does not pay the MFA-provider tax on day one. A
deployment that maps those surfaces and genuinely wants single-factor must opt out
explicitly, which makes the canonical-identity blast-radius risk a recorded choice
rather than an accident.

The requirement keys on a user's tenant count, which can change after tokens are
issued. Granting a second `TenantAccess` to a previously single-tenant user
crosses the one-to-many boundary and makes the second factor newly required.
Crossing that boundary fires the [§2.7](#27-canonical-identity-carried-from-adr-0001)
revocation hook for the affected user, so the user's existing single-factor tokens
are dropped and the next token issuance enforces the second factor.

One honesty caveat about enforcement: `Build()` applies the locked configuration
as the last-registered options post-configuration, so it overrides earlier
consumer configuration and stops *accidental* subtraction. C# dependency
injection cannot stop a consumer who *deliberately* re-registers options after
`AddIdmt` from disabling a locked property. To close that gap, IDMT registers an
`IStartupFilter` self-check that asserts the locked invariants at startup —
reference tokens on, `EnableTokenEntryValidation()` on, the audience handler and
the revocation hook registered, and an MFA provider present when required — and
throws if any is missing. The self-check reads the resolved options snapshot, so
it catches subtraction expressed as registration. It cannot catch a consumer who
mutates options at resolve time, for example through a custom
`IPostConfigureOptions` or an options decorator that runs after the snapshot. The
guarantee is therefore "inadvertent subtraction is impossible, and deliberate
subtraction of the registered options fails fast and is detectable," not
"subtraction is impossible." For defense in depth, the audience and revocation
invariants also self-verify inside their own handler execution rather than relying
on the startup snapshot alone. §4 tests the self-check with a hostile
post-`AddIdmt` override.

Registration uses a fluent `IIdmtBuilder` rather than v1's positional delegate
parameters, so each seam is named and discoverable and the locked-versus-open
line is visible in the type system.

### 2.10 Endpoint scaffolding

The scaffolding is the payoff for "opinionated but customizable." Two mapping
entry points hand the consumer route groups with the correct authorization
already attached.

`MapIdmtTenantApi` mounts the tenant-facing surface (account self-management,
email flows, tenant membership) with the tenant policy and rate limiter attached.
`MapIdmtSysAdminApi` mounts the system-admin surface (tenant lifecycle,
`TenantAccess` grant and revoke, system-role assignment, and the support
exchange) with `RequireSysAdmin` attached. Both return the route group so a
consumer adds their own endpoints under the same pre-authorized umbrella. The
policy names are public constants: `RequireSysAdmin`, `RequireSysUser`,
`RequireTenantManager`, `RequireTenantMember`, and `SupportSession`.

## 3. Bring-up plan

v2 is a greenfield rewrite. There is no production data to carry and no installed
base to cut over, so this is a bring-up plan, not a data-migration plan. v2 stands
up a new persistence layer from scratch and seeds the registrations a running
authorization server cannot start without.

The persistence layer is two Entity Framework Core contexts with two independent
migration histories. The multi-tenant application context holds the canonical
identity tables (`IdmtUser`, `IdmtRole`, `TenantAccess`, the system-role
assignment, the email-change staging, and the support-audit tables). A separate,
tenant-agnostic context holds the OpenIddict application, authorization, scope,
and token stores, for the reasons fixed in
[§2.6](#26-multi-tenancy-integration). v2 has no `RevokedToken` table; the
OpenIddict token store is authoritative for revocation.

You generate the initial schema with the Entity Framework Core tools, one
migration per context:

```bash
dotnet ef migrations add InitialCreate --context IdmtDbContext
dotnet ef migrations add InitialCreate --context IdmtOpenIddictDbContext
dotnet ef database update --context IdmtDbContext
dotnet ef database update --context IdmtOpenIddictDbContext
```

A running authorization server is non-functional without seeded OpenIddict
registrations, so IDMT supplies an `IIdmtApplicationSeeder` that provisions them
idempotently on startup. The seeder registers the default first-party client
applications, with their redirect URIs and PKCE enabled, and the scope catalog
the deployment uses, including the `support` scope that minted support tokens
carry. Consumers register their own clients, such as a single-page app's
redirect URIs, through the same seeder. The seeder also bootstraps the first
system administrator — an initial `IdmtUser` with a system-role assignment, sourced
from configuration on first run — because the sys-admin surface in
[§2.10](#210-endpoint-scaffolding) requires `RequireSysAdmin`, so without a seeded
first admin no one can grant `SysRole` to anyone and the system is locked out of
its own administration.

For development and testing, the seeder runs against the ephemeral SQLite database
the integration-test stack already uses, seeding a test client, test tenants, and
a seeded system administrator. Idempotency lets it run on every startup without
duplicating registrations.

## 4. Test strategy

The locked decisions in [§2.9](#29-the-opinionated-and-customizable-seam) are
only real if tests enforce them. CI must gate on the following, and every locked
invariant maps to an entry here.

- **Architecture fitness function.** `Idmt.Core` references no infrastructure
  assembly. Vendor types appear only in their owning folder.
- **Route-mutation fuzzer.** Authenticate for tenant A, mutate the tenant route
  segment to every other known tenant, and assert 403. This gates merges and
  exercises the real audience validation handler from §2.6.
- **`TenantAccess` gate, parametric.** For every grant type, including refresh,
  and for every server-side support-token mint, a user with no or expired
  `TenantAccess` is denied a token.
- **Reference-token instant revocation.** With `EnableTokenEntryValidation()` and
  the local validation handler configured, mint a token, revoke it, and assert
  the next request returns 401 before the token's TTL expires. The test runs
  against the configured handler, not a mocked store.
- **Refresh reuse detection.** Rotate a refresh token, replay the consumed one,
  and assert the request is rejected and the token family is revoked.
- **Cross-grant audience isolation.** Present a tenant-A refresh token at
  `/connect/token` resolving tenant B, and assert rejection.
- **Support audit atomicity.** Simulate an audit-write failure during a
  support-token mint and assert neither the token nor the audit row survives
  (the shared transaction rolls back the already-persisted token).
- **Support TTL cap.** Request a lifetime above the ceiling and assert the issued
  token expires at or below the ceiling.
- **Cross-tenant token rejection.** Use a tenant-A token against a tenant-B route
  and assert 401 from the audience handler.
- **`SecurityStamp` propagation.** Rotate a user's `SecurityStamp` and assert all
  of that user's reference tokens return 401 on the next request.
- **MFA-required issuance.** With enforcement on, assert no token issues for a
  system user or a multi-tenant user that has not satisfied a second factor.
- **Authorize-cookie tenant isolation.** Assert an authorize-endpoint sign-in
  cookie minted for tenant A cannot be replayed against tenant B.
- **Backend-for-frontend session isolation.** Assert a session cookie minted for
  tenant A cannot drive a tenant-B resource request, and that the session resolves
  to a reference token validated by the same audience handler a raw bearer request
  uses (no second validation path).
- **Backend-for-frontend CSRF.** With the session surface enabled, assert a
  cross-site request that carries the session cookie but no anti-forgery token is
  rejected.
- **No token in the browser.** Assert the single-page-app login response sets only
  the `httpOnly` session cookie and returns no access or refresh token to the
  client.
- **Configuration integrity.** Register a consumer post-configuration after
  `AddIdmt` that disables a locked property, and assert the startup self-check
  throws.
- **OAuth 2.1 posture.** Assert the password grant is not configured or exposed.

## 5. Consequences

This section records what you gain, what you take on, and how you contain the
new risks.

### 5.1 Positive

The audit backlog closes by construction rather than by a long checklist:
revocation, rotation, and session coherence come from the engine. The library
surface shrinks, because login, refresh, revocation, and token-revocation
bookkeeping are owned by OpenIddict, not IDMT. Support, revocation, expiry, and
audience all
run through one token code path, so there is one set of invariants to test.

### 5.2 Risk and mitigation

The canonical-identity model concentrates blast radius: one stolen credential
reaches every tenant the user belongs to. We mitigate by requiring a second
factor for system users and for multi-tenant users, enforced as a core domain
invariant with a fail-fast startup check
([§2.9](#29-the-opinionated-and-customizable-seam)), so the mitigation cannot be
silently absent. Reference tokens add a store read per request, and instant
revocation degrades to cache-lifetime revocation across scaled-out instances
without a revocation backplane (Redis publish-subscribe or database polling); we
treat the backplane as a near-term requirement, not a deferred nicety, because
support-token revocation latency is itself a security property. Coupling to
OpenIddict is contained because the engine is named in one package behind a port.
The Finbuckle and OpenIddict reconciliation is the sharpest risk and is addressed
by the dedicated tenant-agnostic store context
([§2.6](#26-multi-tenancy-integration)), the per-request audience handler, and
the route-mutation fuzzer, and it is proven by the
[§7](#7-prototype-gate-and-open-questions) prototype gate before ratification.

## 6. Alternatives considered

Each alternative below was rejected for a specific reason, recorded so the
decision is auditable later.

| Alternative | Why rejected |
|---|---|
| Keep hand-rolling auth | The remaining backlog is an identity provider; building it competes with hardened engines on commodity work. |
| Keycloak | A JVM service is a foreign runtime in an all-.NET foundation, and it adds a second tenancy model to reconcile. |
| Duende IdentityServer | Commercial license above a revenue threshold, which multiplies across many products. |
| Managed B2B identity provider | The owner requires owning the infrastructure; managed hosting is out. |
| ABP framework | A whole-application framework is the opposite of a thin plugin and imposes its architecture on every product. |
| Five-package split | Cleaner vendor-version blast radius, but more ceremony than a solo-owned "simple plugin" warrants. The architecture test recovers the domain-isolation benefit at three packages; the vendor blast radius is the consciously accepted cost (see [§2.2](#22-module-boundaries-three-packages)). |
| Single package | Simplest to ship, but relies on convention to keep vendor types out of the domain. |
| Keep the cookie-or-bearer hybrid | Retains the dual-path bug class for no greenfield benefit. |
| Single-page app holds the token in the browser | Auth-code with PKCE and a token in JavaScript memory is spec-legal, but the token stays cross-site-scripting-reachable. The backend-for-frontend session ([§2.5.1](#251-browser-clients-use-a-backend-for-frontend-session)) is strictly safer and, given the locked co-hosting, nearly free. |
| Resource-owner password grant | Removed by OAuth 2.1; building login on it is a dead end. |
| Expose RFC 8693 token exchange as a public grant for support tokens | The grant pipeline creates the token through sign-in passthrough after the request handler returns, so the support audit write cannot share the token-store transaction. Minting server-side through the token manager keeps the audit atomic; the prototype confirmed it ([§2.8](#28-system-support-through-a-server-side-token-mint)). |

## 7. Prototype gate and open questions

Two reviews — an adversarial critic and a validating architect — confirmed that
several load-bearing claims about how OpenIddict, Finbuckle, and Entity Framework
Core compose could not be settled on paper. A prototype spike was required before
this ADR moved from Proposed to Accepted; it passed (see the prototype outcome in
[§7.0](#70-prototype-gate-precondition-to-ratification)). The open questions in
§7.1 remain genuinely open and must not be settled silently during implementation.

### 7.0 Prototype gate (precondition to ratification)

A single spike must prove, end to end on .NET 10 with the applicable OpenIddict
version, that:

1. Reference tokens with `EnableTokenEntryValidation()` revoke on the next
   request through the configured local validation handler.
2. The server-side support-token mint — through `IOpenIddictTokenManager.CreateAsync`
   inside an IDMT-owned transaction, not a public token-exchange grant — re-runs
   the `TenantAccess` gate and writes the audit row in the **same transaction** as
   OpenIddict's token-store insert, so a token can never commit without its audit
   row. The prototype confirmed the OpenIddict Entity Framework Core store resolves
   the same scoped `DbContext`, so its insert enlists in the owned transaction, and
   a forced audit-write failure rolls back the already-persisted token. This was
   the unproven part; it is now proven.
3. A per-request handler rejects a token whose `aud` does not equal the
   Finbuckle-resolved tenant.
4. OpenIddict's stores in a separate, tenant-agnostic `DbContext` coexist with
   Finbuckle's save-side `TenantId` stamping, and the token endpoint reads and
   writes tokens with no ambient tenant.
5. A hostile consumer override registered after `AddIdmt(...)` fails the startup
   self-check.
6. The `SecurityStamp`-change hook revokes a user's tokens. The prototype showed
   the cleanest mechanism is two single store calls, not a manual enumeration:
   `RevokeBySubjectAsync` for a full credential change, and
   `RevokeByAuthorizationIdAsync` on a per-(user, tenant) authorization for a
   single-tenant revoke. A token entry records no audience to filter on (the
   audience lives only in the encrypted payload), which is why single-tenant
   revocation uses authorization grouping rather than an audience filter. Proven
   against a 100-token user; cost does not scale with tokens held.
7. A backend-for-frontend session cookie resolves to its **server-side** reference
   token and runs the same per-request audience handler a raw bearer request runs,
   so the cookie path and the bearer path share one validation, and a mutating
   request bearing the session cookie but no anti-forgery token is rejected.

If items 1 through 4 do not compose cleanly, the "own the policy, rent the
protocol" cost basis must be re-evaluated before the rewrite begins.

**Prototype outcome.** All seven items passed on .NET 10 with OpenIddict 7.5.0,
Finbuckle.MultiTenant 10.0.3, and SQLite, plus a follow-on gate 8 that proved the
real browser-login flow (19 tests total). Corrections and scoped stand-ins the
spike surfaced, folded into this ADR:

- §2.7 is corrected: OpenIddict 7.5.0 *does* expose `RevokeBySubjectAsync`, and a
  token entry has no audience column. Single-tenant revocation is by authorization
  grouping (item 6).
- Support tokens mint server-side, not through a public token-exchange grant
  ([§2.8](#28-system-support-through-a-server-side-token-mint), item 2).
- Gate 5 proves the two-layer lock plus detection of registration-expressed
  subtraction; resolve-time mutation remains uncatchable, as
  [§2.9](#29-the-opinionated-and-customizable-seam) already concedes.
- Gate 7 proves server-side session resolution, the shared validation path, and
  anti-forgery rejection.
- Gate 8 proves the real browser login: authorization code + PKCE (enforced, not
  decorative) through an interactive authorization-server session, the BFF
  exchanging the code server-side and storing the reference token in the session.
  The issued token's **subject is the authenticated user** — this supersedes gate
  7's client-credentials back-channel stand-in (subject = client) and resolves the
  §7.1 first-party-auth question. The remaining stand-in scope is small: the
  single-instance topology proves revocation correctness, not the bounded-staleness
  scale-out window (§7.1 backplane), and a real cross-site `SameSite` redirect was
  not exercised in-process.

### 7.1 Open questions

The following remain undecided and are tracked separately from the gate.

- **Machine-client authentication** without the password grant. **Decided in
  [ADR-0003](0003-machine-client-authentication.md):** non-interactive callers use
  the OAuth 2.0 client-credentials grant against the OpenIddict server, with each
  trusted gateway a confidential client whose secret is its durable credential.
  The browser flow was already settled: gate 8 proved **authorization code +
  PKCE** with a server-side BFF session.
- **Out-of-process resource servers.** v2 assumes the resource API is co-hosted
  with the OpenIddict server so the local validation handler enforces revocation
  ([§2.3](#23-openiddict-as-the-protocol-engine)). Decide whether to support a
  split deployment at all, and if so whether introspection without response
  caching is an acceptable revocation story.
- **Reference-token revocation backplane** transport at scale-out: Redis
  publish-subscribe versus database polling.
- **Per-tenant signing keys.** The default is a single issuer with tenant as
  audience. Revisit only if hard cryptographic tenant isolation becomes a
  requirement.
- **Multi-factor factors and timeline.** Decide TOTP versus WebAuthn and the
  rollout, given that the *requirement* for a second factor is already locked in
  [§2.9](#29-the-opinionated-and-customizable-seam).

## 8. References

The following artifacts informed this decision and contain the detailed design
and scoring behind it.

- `adr/0002-v2-sketch-dotnet-expert.md` — .NET specialist sketch (fluent builder,
  "own the policy, rent the protocol").
- `adr/0002-v2-sketch-architect-reviewer.md` — bounded-context decomposition and
  the locked-versus-open security seam.
- `adr/0002-v2-sketch-code-architect.md` — v1-to-v2 file migration map and a
  concrete support-exchange slice.
- `adr/0002-v2-evaluation.md` — the scored comparison and the chosen hybrid.
- `adr/0001-canonical-identity-and-tenant-access.md` — the identity model this
  ADR keeps and the `ServerSession` and sys-switch design it supersedes in part.
- `SECURITY_AUDIT.md` — the findings that motivated the rewrite.
- OpenIddict token-manager documentation — `IOpenIddictTokenManager.CreateAsync`
  for server-side token creation (the support-token mint path).
- OpenIddict token-storage documentation — reference tokens and
  `EnableTokenEntryValidation()` (per-request revocation is opt-in and required
  with reference tokens).
- OpenIddict token-validation guide — local validation handler versus
  introspection.
- RFC 8693 (token exchange), RFC 8707 (resource indicators), RFC 7009 (token
  revocation), RFC 6749 (OAuth 2.0).
- Finbuckle.MultiTenant documentation — tenant resolution and query filters.
