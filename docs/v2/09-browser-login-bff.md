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
what to build, where the proof lives, and the blocking state-to-browser binding
the spike deliberately did not build.

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
through the standard RFC 8707 `resource` parameter (the tenant URN registered as
an OpenIddict resource) and becomes the token audience, so the issued token is
tenant-bound the same way every other token is. This is the standard parameter,
not the spike's custom `tenant` field, which v2 drops. See [multi-tenancy and the
audience](05-multitenancy-audience.md) for how the audience is stamped and
checked. And the token subject is the authenticated **user**. Gate 8 supersedes gate 7's client-credentials stand-in, where the
subject was the client. The production flow carries subject = the authenticated
user, and gate 8 asserts the resolved subject equals the user id and does not
equal the single-page-app client id.

The second factor is confirmed here, at interactive `/connect/authorize`. This
is the one interactive point in the user grants where a challenge can be
rendered, so it is where invariant 8 is enforced: before the authorize endpoint
issues a code, the user's second factor must be satisfied, and the satisfaction
is recorded into the authorization (for example as a claim or property on the
issued authorization) so it travels with the grant rather than being re-checked
out of band. Issuance then reads that recorded state rather than re-running the
challenge; that issuance-time read, and the pure-client-credentials exemption,
are handled in [the tenant access gate](06-tenant-access-gate.md). Pure
client-credentials has no user subject and no interactive step, so it never
reaches this confirmation.

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

## Data Protection key ring

Every cookie in this flow is protected by ASP.NET Core Data Protection: the
`bff_session` cookie (protected in `/bff/callback` and unprotected in the
resolver), the `AuthServerLogin` cookie, and the anti-forgery token. They all
read and write through the same key ring, so the key ring must be persisted and
shared, not the framework default.

The default key ring is ephemeral and per-instance. Each process generates its
own keys in memory, so a key minted on one instance cannot decrypt a cookie
presented to another, and a restart discards the keys entirely. The symptom is
silent random logout: a user signed in on instance A is logged out the moment
the load balancer routes them to instance B, and everyone is logged out on every
deploy. There is no error, just a cookie that fails to unprotect and a request
that proceeds unauthenticated, which is exactly the resolver's documented
behavior for a cookie it cannot unprotect.

v2 requires a persisted, shared key ring backed by a durable store: a database
table or a key vault. Persist the keys so they survive restarts and configure the
same store for every instance so they share one ring. The persistence package is
listed in [solution and packages](01-solution-and-packages.md). This is a
production requirement, not a tuning option, because the BFF session, the login
cookie, and anti-forgery all silently break without it.

## CORS for the single-page app

The single-page app and the host are different origins in any real deployment, so
the browser will not send the `bff_session` cookie on cross-origin requests
unless CORS explicitly permits credentialed requests from the app's origin. CORS
is required for the session to work from a hosted front end, not optional polish.

The policy is narrow. Allowed origins come from configuration, never a wildcard,
because credentialed CORS forbids `*` and because the allow-list is part of the
deployment's trust boundary. The policy sets `AllowCredentials()` so the browser
is permitted to attach the cookie, and it allows the anti-forgery header
(`X-CSRF-TOKEN`) so the single-page app can send the request token on mutating
calls. Register `UseCors` before `UseAuthentication` (see the middleware order
below) so the preflight and the credential rules apply before any authentication
runs.

This pairs with the deferred cross-site `SameSite` redirect test. The spike ran
in-process, so a genuine cross-origin credentialed request and a real browser's
`SameSite` enforcement on the redirect return were never exercised. That test is
tracked in [hardening and open questions](15-hardening-and-open-questions.md);
the CORS policy here is what it will exercise.

## Middleware order

The resolver only works in one position, and so do the pieces around it, so the
order is definitive rather than a suggestion. Register the pipeline in exactly
this sequence:

1. Exception handler.
2. Security headers.
3. CORS.
4. Rate limiter (global).
5. `UseMultiTenant`.
6. The BFF session resolver (`UseBffSessionResolver`).
7. `UseAuthentication`.
8. `UseAuthorization`.

Two placements carry the load. `UseMultiTenant` runs before the resolver and
before `UseAuthentication` so the Finbuckle-resolved tenant is populated by the
time the audience handler runs (the same ordering [multi-tenancy and the
audience](05-multitenancy-audience.md) requires). The resolver runs before
`UseAuthentication` so the `Authorization: Bearer` header it sets is in place
when authentication reads it, which is what makes a cookie-backed request
indistinguishable from a raw bearer request.

Rate limiting defaults to global and sits before tenant resolution, because a
global limiter does not need a tenant and placing it first sheds load before any
per-request work. If you instead want a per-tenant limiter, that limiter must
resolve after routing (it needs the resolved tenant to pick a partition), so it
moves after `UseMultiTenant` and after `UseRouting`. The global-first default is
the prescribed shape; the per-tenant variant is the documented alternative.

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

## State-to-browser binding (blocking)

Binding `state` to the initiating browser is a blocking requirement of this BFF
task, not near-term hardening. It is a login-CSRF defect that is present on a
single instance, so it is a correctness bug in the flow itself, not scale-out
polish that can be deferred. The flow is not done until it is built.

In the spike, `state` is server-global and not bound to any browser, which opens
OAuth login-CSRF: any browser presenting a valid `state` at `/bff/callback`
consumes the flow, so an attacker can fixate a victim's session onto an
attacker-initiated login. The `AuthCodeEndpoints.cs` source flags its own `state`
handling as a spike limitation you must not copy as-is. The production v2
implementation must bind `state` to the browser. At initiation, set a short-lived
`httpOnly`, `Secure`, `SameSite=Lax` `bff_oauth_state` cookie alongside the
redirect. In `/bff/callback`, require a constant-time match between the cookie and
the inbound `state` parameter, then clear the cookie, before consuming the flow. A
callback whose `state` does not match the cookie is refused.

This carries an acceptance test (listed under the acceptance criteria below): a
`/bff/callback` presented with a valid `state` but no matching `bff_oauth_state`
cookie, or a mismatched one, is refused and does not establish a session.

## Hardening and deferred work

The spike proves the composition, not a hardened backend-for-frontend. With the
state binding above built as a blocker, one test remains deferred because the
spike ran in-process.

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

State-to-browser binding (blocking, see the section above) requires:

- A `/bff/callback` request that presents a valid `state` but no matching
  `bff_oauth_state` cookie (or a mismatched cookie) is refused and establishes no
  session, while a callback whose cookie matches the inbound `state` completes the
  flow.

## Next steps

With browser login and the session proven, the next two docs turn the locked
behavior into a buildable surface.

- [The locked seam](10-locked-seam.md) shows how the cross-site request forgery
  invariant and the rest of the locked set are applied unconditionally in
  `Build()`.
- [Endpoint scaffolding](11-endpoint-scaffolding.md) shows how consumers mount
  routes under the pre-authorized groups the session feeds.
