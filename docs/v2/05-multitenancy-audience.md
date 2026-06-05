# Multi-tenancy and per-request audience binding

In IDMT v2, the tenant a token belongs to is carried in the access token's
`aud` claim, and you enforce that binding on every request. Finbuckle resolves
the tenant from the incoming request, IDMT stamps the resolved tenant into the
`aud` claim at issuance, and an IDMT-owned validation handler checks that the
token's `aud` matches the resolved tenant before any resource logic runs. The
token audience is the single source of truth at the resource layer, but both
ends of that contract (stamping and checking) are code IDMT owns: OpenIddict
does neither dynamically on its own.

The spike proved this end to end. Gate 3 proved per-request audience rejection:
a tenant-A token presented on a tenant-B route returns 401, and the same token
on a tenant-A route returns 200. Gate 4 proved the underlying dual-context
composition that gate 3 runs on, where OpenIddict's stores live in a separate,
tenant-agnostic `DbContext` that coexists with Finbuckle's save-side `TenantId`
stamping, and the token endpoint reads and writes tokens with no ambient tenant.
This document tells you what to build and why each piece is shaped the way it is.

## What you build

You build four things that together bind a token to a tenant and keep that
binding enforced. None of them are optional, and three of them sit in IDMT's
locked security set rather than its customizable surface.

- The Finbuckle wiring: `AddMultiTenant<IdmtTenantInfo>()` with the tenant store
  and the resolution strategies that map an incoming request to a tenant.
- The `TenantUrns` encoder: the helper that turns a tenant identifier into the
  audience URN and parses it back, so the same string convention is used at
  issuance and at validation.
- The per-request audience validation handler: the OpenIddict validation event
  handler that reads the Finbuckle-resolved tenant and rejects any token whose
  `aud` does not match.
- The refresh audience precedence rule: on a refresh grant, the presented
  token's original `aud` is authoritative, and a supplied `resource` parameter
  must match it.

## Source of truth

The authoritative design lives in the ADR, and the proven reference
implementation lives in the spike. Read both before you implement, because the
ordering and the precedence rules below are load-bearing and easy to get subtly
wrong.

- [ADR 0002 §2.4 (bearer-only authentication
  model)](../../adr/0002-idmt-v2-openiddict-authorization-layer.md) fixes the
  resource layer to bearer reference tokens only.
- [ADR 0002 §2.6 (multi-tenancy
  integration)](../../adr/0002-idmt-v2-openiddict-authorization-layer.md) fixes
  the `resource`-parameter convention, the refresh `aud` precedence rule, and
  the per-request validation handler.
- `spike/src/Idmt.Spike.Host/Auth/Auth.cs` holds the proven `TenantUrns` URN
  encoder and the `TenantAudienceValidationHandler` validation event handler.
- `spike/src/Idmt.Spike.Host/Wiring/SpikeWiring.cs` holds the Finbuckle
  `AddMultiTenant<IdmtTenantInfo>()` registration and the
  `AddEventHandler(TenantAudienceValidationHandler.Descriptor)` call on the
  validation builder.
- `spike/tests/Idmt.Spike.Tests/Gate3_AudienceHandlerTests.cs` is what gate 3
  asserts: cross-tenant rejection and same-tenant acceptance.

## Stamping the tenant at issuance

At issuance, the resolved tenant is written into the access token's `aud` claim.
How the tenant is resolved depends on the grant, because the two grants that
matter here reach the server with different information available.

For the authorization-code flow, the tenant is resolved at `/connect/authorize`.
The user arrives at the authorize endpoint through a tenant-aware route, signs
in against an interactive session, and the resolved tenant is carried into the
issued token's audience. The route segment is present, so Finbuckle has what it
needs.

For the refresh grant, the request reaches `/connect/token` with no tenant route
segment, so the server cannot resolve the tenant from the route. The client
supplies the tenant explicitly through the RFC 8707 `resource` parameter, as the
URN `urn:idmt:tenant:{identifier}`. You lock this convention rather than
standing up per-tenant route endpoints (`/{tenant}/connect/token`) for a
specific reason: a single token endpoint keeps the OpenID Connect discovery
document single-issuer and conformant. Per-tenant route endpoints would
multiply the issuer surface and break that conformance. The cost of the
convention is that refresh clients must send the `resource` parameter, which is
a documented requirement, not a hidden one.

Support tokens take neither path. IDMT mints them server-side and sets their
`aud` directly, so they carry no public grant and do not go through `resource`
resolution. They are covered in [the OpenIddict server
guide](04-openiddict-server.md).

## The tenant audience URN

The audience value is a URN with a fixed prefix, and a single helper owns both
directions of the conversion so issuance and validation never disagree about the
string format. The helper is `TenantUrns`, proven in the spike at
`spike/src/Idmt.Spike.Host/Auth/Auth.cs`.

- The prefix is `urn:idmt:tenant:`, exposed as `TenantUrns.Prefix`.
- `TenantUrns.For(identifier)` builds the audience URN from a tenant identifier,
  so `TenantUrns.For("acme")` yields `urn:idmt:tenant:acme`.
- `TenantUrns.IdentifierFrom(urn)` parses the identifier back out of a URN, and
  returns `null` when the string does not carry the prefix, so a malformed or
  unrelated audience value never silently parses as a tenant.

Use `TenantUrns.For` everywhere you stamp an audience and everywhere you compute
the expected audience to compare against. Never hand-build the URN string,
because a single divergent format on one path defeats the binding on every
request that takes it.

## Refresh audience precedence

On a refresh grant the token's original `aud` wins, and the `resource` parameter
cannot override it. This is a security rule from ADR §2.6, not a convenience,
and it exists to block a specific cross-tenant attack.

The rule is precise. For a refresh, the tenant is authoritative from the
presented refresh token's original `aud`. If the client also sends a `resource`
parameter, that parameter must match the token's `aud`; a mismatch is rejected.
The `resource` parameter is allowed to restate the tenant, but it can never
substitute a different one.

The attack this blocks is direct. Without the rule, a client holding a tenant-A
refresh token could send `resource=urn:idmt:tenant:B` and mint a tenant-B access
token, escalating from one tenant to another with a token it already legitimately
holds. By making the original `aud` authoritative and rejecting any mismatched
`resource`, a tenant-A refresh token can only ever mint tenant-A access tokens.
The test suite's cross-grant audience-isolation test asserts exactly this
rejection (see [the test suite guide](14-test-suite.md)).

## The per-request audience validation handler

Per-request enforcement is an IDMT-owned OpenIddict validation event handler,
named `TenantAudienceValidationHandler` in the spike. It binds the presented
token to the tenant Finbuckle resolved for the current request, and it rejects
any token whose audience does not match. It is the successor to v1's
`ValidateBearerTokenTenantMiddleware`, relocated into the OpenIddict validation
pipeline rather than deleted.

The handler does a small, fixed amount of work. It reads the Finbuckle-resolved
tenant through `IMultiTenantContextAccessor<IdmtTenantInfo>`, taking the
tenant's `Identifier`. It computes the expected audience with
`TenantUrns.For(resolved)`. It reads the token principal's audiences through
`GetAudiences()` and checks the expected audience against them with an ordinal
comparison. On a mismatch it calls `context.Reject(...)`, which surfaces as a
401 to the caller. The handler is deliberately strict in two more places: it
skips non-access-token principals (only access tokens are tenant-bound), and it
refuses rather than guesses when no tenant was resolved at all, rejecting a
token-bound request that arrives with no resolved tenant instead of letting it
through.

Ordering matters. The handler runs late: the spike sets the descriptor order to
`int.MaxValue - 100_000`, after the built-in validation handlers have run and
populated the principal. The handler depends on the principal already being
established, so it must run after the engine's own authentication handlers, not
before them. For the accessor to be populated when the handler runs, Finbuckle's
`UseMultiTenant` must run before `UseAuthentication` in the request pipeline.

You need this handler because OpenIddict's built-in audience validation is not
enough. The built-in check compares `aud` only against a static configured
audience set, decided at startup. It has no notion of the per-request resolved
tenant, so it cannot tell a tenant-A token apart from a tenant-B token when both
audiences are in the static set. The per-request, resolved-tenant comparison is
the part that is genuinely IDMT's, and it is in the ADR's locked set for that
reason.

## Bearer-only resource layer

The resource layer accepts exactly one kind of credential: a bearer reference
token. There is no cookie-or-bearer hybrid at the resource layer, which removes
v1's dual-path scheme and the bug class that came with it.

ADR §2.4 fixes this. Every resource request carries a reference token, and v2
does not build a `CookieOrBearer` resource-layer scheme at all. Because there is
one credential path, there is one place the audience handler runs, and one
binding to test. This does not remove cookies from the system; it confines them
to two roles that are not resource-layer credentials: the interactive session at
the authorize endpoint, and the backend-for-frontend session a browser client
uses. Both of those cookies stay tenant-aware through per-tenant naming, and
both are detailed in [the browser login and BFF guide](09-browser-login-bff.md).
The resource API itself never accepts a cookie as a credential of its own.

## Dependencies

This document assumes the persistence split and the OpenIddict server wiring are
already in place, because the audience handler runs on top of both. Read these
two first if you have not.

- [Persistence and contexts](03-persistence-and-contexts.md) covers the
  dual-context split (the multi-tenant application context and the separate,
  tenant-agnostic OpenIddict store context) that gate 4 proved, which is what
  lets the token endpoint issue and validate tokens with no ambient tenant.
- [The OpenIddict server](04-openiddict-server.md) covers reference tokens,
  token-entry validation, and the validation builder this handler registers on.

## Acceptance criteria

You are done when the binding holds in both directions and the cross-tenant
refresh attack is blocked. These map directly to the proven gate 3 assertions
and the cross-grant isolation test.

- A tenant-A token presented on a tenant-B route returns 401 from the audience
  handler.
- A tenant-A token presented on a tenant-A route returns 200.
- A tenant-A refresh token sent to `/connect/token` with
  `resource=urn:idmt:tenant:B` is rejected, so it cannot mint a tenant-B access
  token.

The first two are gate 3
(`spike/tests/Idmt.Spike.Tests/Gate3_AudienceHandlerTests.cs`). The third is the
cross-grant audience-isolation test (forward-linked in [the test suite
guide](14-test-suite.md)).

## Next steps

The audience handler proves a token belongs to the resolved tenant, but it does
not prove the user still has the right to that tenant. That second check is the
`TenantAccess` gate, applied at issuance across every grant.

- [The tenant access gate](06-tenant-access-gate.md) covers the uniform
  `TenantAccess` gate that runs at token issuance, the complement to the
  per-request audience binding documented here.
