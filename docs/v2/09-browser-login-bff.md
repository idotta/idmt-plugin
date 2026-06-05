# Browser login and the backend-for-frontend session

A first-party single-page application never holds a token in the browser. It
runs the authorization-code flow with PKCE against the co-hosted host, and the
host keeps the resulting reference token server-side. The browser receives only
an opaque, `httpOnly` session cookie. The host resolves that cookie to the
server-side token on every request and runs the request through the exact same
reference-token validation path a raw bearer request uses. Two spike gates prove
this end to end: gate 7 proves a backend-for-frontend session resolves to a
server-side token and runs the same audience handler with anti-forgery enforced,
and gate 8 proves a real interactive authorization-code plus PKCE login where the
token subject is the authenticated user, not the client. This document tells you
what to build, where the proof lives, and the one hardening step you must apply
before this ships.

## What you build

You build five pieces that compose into one flow. None of them hands a resource
credential to the browser, and all of them stay tenant-aware so a tenant-A
session cannot drive a tenant-B request.

- Two confined cookies, neither a resource credential. The
  authorization-server login cookie (the spike's `AuthServerLogin` scheme) tells
  `/connect/authorize` that the user is signed in. The backend-for-frontend
  session cookie (the spike's `bff_session`) is an opaque `httpOnly` handle to a
  server-side token. Both use per-tenant naming.
- The authorization-code flow with PKCE. The single-page app generates a
  `code_verifier` and an S256 `code_challenge`, the authorize endpoint issues a
  code bound to that challenge, and the token endpoint validates the verifier on
  exchange.
- The server-side session store. It maps an opaque session id to the
  `{UserId, Tenant, ReferenceToken}` triple. The reference token lives here and
  nowhere else the browser can reach.
- The cookie-to-bearer resolver. Middleware that runs before authentication,
  looks up the session, and sets the `Authorization: Bearer <token>` header so
  the request flows through one shared validation path.
- Cross-site request forgery protection. A `SameSite` cookie plus an
  anti-forgery token, validated on every mutating request.

## Source of truth

This document is a reading guide, not the decision record. The decisions live in
the ADR, and the proof lives in the spike. Read these before you implement.

- [ADR 0002 §2.4](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#24-authentication-model-bearer-only-apis),
  bearer-only APIs and the two confined cookies.
- [ADR 0002 §2.5](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#25-login-grant-authorization-code-with-pkce),
  authorization code with PKCE as the login grant.
- [ADR 0002 §2.5.1](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#251-browser-clients-use-a-backend-for-frontend-session),
  the backend-for-frontend session in full.
- [ADR 0002 §2.9](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#29-the-opinionated-and-customizable-seam),
  the locked set, including cross-site request forgery protection (invariant 9).
- `spike/src/Idmt.Spike.Host/Bff/AuthCodeEndpoints.cs`, the authorization-code
  plus PKCE flow.
- `spike/src/Idmt.Spike.Host/Bff/BffEndpoints.cs`, the session store, the
  resolver, and the anti-forgery wiring.
- `spike/tests/Idmt.Spike.Tests/Gate7_BffSessionTests.cs` and
  `spike/tests/Idmt.Spike.Tests/Gate8_AuthCodePkceTests.cs`, the assertions.

## Authorization code with PKCE

Interactive login uses the authorization-code flow with PKCE, and PKCE is
enforced rather than decorative. The single-page app proves it initiated the
flow by holding a secret the authorize step never sees, so a stolen code is
useless without the matching verifier.

The flow runs in four steps. The backend-for-frontend initiation endpoint
(`/bff/login-pkce` in the spike) generates a random `code_verifier`, derives the
S256 `code_challenge`, stores the verifier server-side keyed by the OAuth
`state`, and redirects the browser to `/connect/authorize` with the challenge.
The authorize endpoint authenticates the user against the `AuthServerLogin`
cookie and issues an authorization code bound to that challenge. The
backend-for-frontend callback (`/bff/callback`) exchanges the code at
`/connect/token` over a server-side back channel, sending the stored
`code_verifier`. The token endpoint validates the verifier against the original
challenge and issues the reference token only on a match.

PKCE enforcement is a property of the client registration, not the flow code. The
public single-page-app client is registered with
`Requirements.Features.ProofKeyForCodeExchange`, detailed in
[the seeding and bootstrap guide](13-seeding-bootstrap.md). Gate 8 proves the
requirement is real: a direct authorize request that omits `code_challenge` is
refused, no `code=` appears in the redirect, and the response is a
`BadRequest` or carries an `error`. A missing challenge cannot produce a code.

Two more properties are fixed. The tenant is carried into the authorize request
(the spike's `tenant` parameter) and becomes the token audience, so the issued
token is tenant-bound the same way every other token is. See
[multi-tenancy and the audience](05-multitenancy-audience.md) for how the
audience is stamped and checked. And the token subject is the authenticated
**user**. Gate 8 supersedes gate 7's client-credentials stand-in, where the
subject was the client. The production flow carries subject = the authenticated
user, and gate 8 asserts the resolved subject equals the user id and does not
equal the single-page-app client id.

## The backend-for-frontend session

The session is where the reference token lives. The browser holds a handle to
the session, never the token, so a cross-site-scripting flaw in the single-page
app cannot exfiltrate a resource credential.

The session store maps an opaque session id to a
`{UserId, Tenant, ReferenceToken}` record. In the spike, `IBffSessionStore` and
`InMemoryBffSessionStore` implement this, and `/bff/callback` calls
`Create(...)` with the token returned from the server-side code exchange. The
session id is the only value that leaves the process: the callback protects it
with data protection and writes it as the `bff_session` cookie, which is
`httpOnly`, `Secure`, and `SameSite`. No access or refresh token ever reaches
the browser.

Both gates assert this directly. Gate 7 decodes the session cookie back to the
session id, reads the server-side session, and confirms the reference token is
present in the store but appears in neither the cookie value nor the response
body. Gate 8 drives the full redirect chain and confirms the chain carries only
`code` and `state`, that no `access_token` appears in any callback URL, and that
the only credential the browser ends up with is the `bff_session` cookie.

## The cookie-to-bearer resolver

The resolver is the single place a cookie touches a resource request, and it
exists so there is exactly one validation path, not the v1 dual path. It turns a
session cookie into a bearer header before authentication runs, so the rest of
the pipeline cannot tell a cookie-backed request from a raw bearer request.

In the spike, `UseBffSessionResolver` runs **before** `UseAuthentication`. When a
request carries the `bff_session` cookie and no `Authorization` header, the
middleware unprotects the cookie to the session id, looks up the session, and
sets `Authorization: Bearer <reference token>`. From that point the request
flows through the identical reference-token validation, including the per-request
`TenantAudienceValidationHandler` that binds the token's audience to the
Finbuckle-resolved tenant. A tampered or stale cookie that fails to unprotect is
ignored, and the request proceeds unauthenticated.

This is the design's load-bearing claim, and both gates prove it. Gate 7 logs in
for tenant A, then sends the same session cookie at a tenant-A route (200) and a
tenant-B route (401). The 401 comes from the very audience handler a raw bearer
request hits, not from a second cookie-specific check. Gate 8 repeats the
tenant-A 200 and tenant-B 401 against a session minted by the real PKCE flow.
One validation path, proven from both the stand-in and the real login.

## CSRF protection

Because the browser now sends an ambient credential (the session cookie),
cross-site request forgery protection is mandatory. It is in the locked set as
invariant 9, so it applies whenever the session surface is enabled and a consumer
cannot subtract it.

The protection is two layers. The session cookie is `SameSite`, which blocks the
browser from attaching it to most cross-site requests in the first place. On top
of that, every mutating request must present an anti-forgery token. In the spike,
`AddBff` registers anti-forgery with the header name `X-CSRF-TOKEN`, `/bff/csrf`
issues the request token to an authenticated caller, and `/bff/widgets` validates
it through `IAntiforgery` before it writes. A request that fails validation is
rejected before any state changes.

Gate 7 proves the rejection. With a valid session cookie present (so
authentication passes through the resolver) but no anti-forgery token, a
`POST /bff/widgets` returns `BadRequest`. The same request with the
`X-CSRF-TOKEN` header succeeds. The cookie alone is not enough to mutate state.

## Hardening and deferred work

The spike proves the composition, not a hardened backend-for-frontend. One
hardening step is required before this ships, and one test is deferred because the
spike ran in-process. Treat the first as a blocking production requirement.

The required step is binding `state` to the initiating browser. In the spike,
`state` is server-global and not bound to any browser, which opens OAuth
login-CSRF: any browser presenting a valid `state` at `/bff/callback` consumes
the flow. The `AuthCodeEndpoints.cs` source flags this as a spike limitation you
must not copy as-is. The production v2 implementation must bind `state` to the
browser. At initiation, set a short-lived `httpOnly`, `Secure`,
`SameSite=Lax` `bff_oauth_state` cookie alongside the redirect. In
`/bff/callback`, require a constant-time match between the cookie and the inbound
`state` parameter, then clear the cookie, before consuming the flow. A callback
whose `state` does not match the cookie is refused.

The deferred test is the real cross-site `SameSite` redirect. The spike ran
in-process, so a genuine cross-site redirect return was never exercised against a
real browser's `SameSite` enforcement. That test is deferred and tracked in the
[hardening and open questions](15-hardening-and-open-questions.md) doc.

## Dependencies

This flow sits on top of three other parts of v2. Build or read them first.

- [The OpenIddict server](04-openiddict-server.md) hosts `/connect/authorize`
  and `/connect/token` and issues the reference tokens this flow exchanges and
  stores.
- [Multi-tenancy and the audience](05-multitenancy-audience.md) defines how the
  tenant becomes the token audience and how the per-request handler enforces it,
  which is the validation the resolver feeds into.
- [Seeding and bootstrap](13-seeding-bootstrap.md) registers the public
  single-page-app client with its redirect URIs and the PKCE requirement
  (`Requirements.Features.ProofKeyForCodeExchange`) that makes PKCE enforced.

## Acceptance criteria

The flow is correct when both gates pass. Gate 8 is the real login proof and
gate 7 is the shared-path and anti-forgery proof.

Gate 8 (real PKCE login) requires all of the following:

- The full `/bff/login-pkce` to `/connect/authorize` to `/bff/callback` flow
  completes and leaves only the `bff_session` cookie on the browser.
- The issued token's subject is the authenticated user, not the single-page-app
  client.
- No access or refresh token appears in any redirect URL or callback response.
- An authorize request with no `code_challenge` is rejected and issues no code.

Gate 7 (shared path and anti-forgery) requires all of the following:

- The session cookie resolves server-side to its reference token, which appears
  in neither the cookie nor the response body.
- The same session resolves through the same audience handler: a tenant-A route
  returns 200 and a tenant-B route returns 401.
- A mutating request that carries the session cookie but no anti-forgery token is
  rejected, and the same request with the token succeeds.

## Next steps

With browser login and the session proven, the next two docs turn the locked
behavior into a buildable surface.

- [The locked seam](10-locked-seam.md) shows how the cross-site request forgery
  invariant and the rest of the locked set are applied unconditionally in
  `Build()`.
- [Endpoint scaffolding](11-endpoint-scaffolding.md) shows how consumers mount
  routes under the pre-authorized groups the session feeds.
