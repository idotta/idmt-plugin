# Hardening and open questions

This is the closing tracker of the v2 build playbook. It collects the follow-up
work the core build deliberately leaves on the table, split into two kinds you
must not conflate. The first is near-term hardening: things the spike proved as
a composition but shipped with a stand-in, so production must finish them. The
second is genuinely open questions: decisions [ADR 0002](../../adr/0002-idmt-v2-openiddict-authorization-layer.md)
declined to settle, which you must record explicitly rather than answer silently
while you write code.

Read this as a bottom line up front. The core build (docs `00` through `14`) is
complete and correct on a single instance. Nothing here blocks that build. Every
item below is scheduled work or a decision to capture, and each one names exactly
what the spike proved and what it left for you.

## Source of truth

This tracker does not invent requirements. It promotes the ones the ADR and the
spike already recorded, so each item traces back to a written origin you can
reopen. The authority for the hardening items is the ADR risk register and the
spike's own "production fix" comments; the authority for the open questions is
the ADR's open-questions list.

The anchors you need:

- [ADR 0002 §5.2 (risk and mitigation)](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#52-risk-and-mitigation):
  the revocation backplane as a near-term requirement, not a deferred nicety.
- [ADR 0002 §7.0 (prototype gate)](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#70-prototype-gate-precondition-to-ratification):
  the stand-in scope note (the single-instance topology and the unexercised
  cross-site redirect).
- [ADR 0002 §7.1 (open questions)](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#71-open-questions):
  the five decisions tracked separately from the gate.

The three spike "production fix" comments, by repo-relative path:

- `spike/src/Idmt.Spike.Host/Bff/AuthCodeEndpoints.cs`: the `state` value is not
  bound to the browser, so the BFF login flow is open to OAuth login-CSRF.
- `spike/src/Idmt.Spike.Host/Server/UserTokenMint.cs`: the find-or-create
  authorization is idempotent only sequentially, so concurrent mints can
  duplicate a `(subject, tenant)` authorization.
- `spike/src/Idmt.Spike.Host/Bff/BffEndpoints.cs`: the gate-7 session token came
  from a client-credentials back-channel stand-in. Gate 8 resolved this, so this
  one is closed (see [Resolved stand-ins](#resolved-stand-ins)).

## Near-term hardening

These are the items the spike composed correctly but did not finish to
production strength. Each one names what the spike proved, what it left as a
stand-in, and the concrete fix. You schedule these as work items; you do not
treat them as blockers to the core build, because the build is correct on a
single instance and these close the gap to a hardened, scaled-out deployment.

### Reference-token revocation backplane

Single-instance revocation is proven correct. The spike showed that with
`EnableTokenEntryValidation()` and the co-hosted local validation handler, a
revoked reference token returns `401` on the very next request. What the spike
did not exercise is scale-out. When the local handler caches token-entry lookups
and the deployment runs more than one instance, an instance with a stale cache
keeps honoring a revoked token until its cache lifetime expires. That window is
the scale-out concern.

[ADR 0002 §5.2](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#52-risk-and-mitigation)
treats the backplane as a near-term requirement, not a deferred nicety, because
support-token revocation latency is itself a security property. You must add a
revocation backplane that propagates an invalidation to every instance so the
staleness window collapses. The transport choice (Redis publish-subscribe versus
database polling) is itself [open question 3](#3-reference-token-revocation-backplane-transport-at-scale-out),
so settling that question and building this item are the same piece of work. See
[`04-openiddict-server.md`](04-openiddict-server.md) for where the local handler
and its caching live.

### State-to-browser binding for the BFF login

This is the most important promoted TODO. The spike's BFF login proves the
authorization-code-with-PKCE composition end to end, but the `state` value it
generates is server-global and not tied to the browser that started the flow.
Any browser that presents a valid `state` at `/bff/callback` consumes the flow,
which is textbook OAuth login-CSRF. The comment in
`spike/src/Idmt.Spike.Host/Bff/AuthCodeEndpoints.cs` flags this and says, in so
many words, do not copy it as-is.

You must bind `state` to the initiating browser. At flow initiation, set a
short-lived `bff_oauth_state` cookie that is `httpOnly`, `Secure`, and
`SameSite=Lax`, carrying the same `state` value. In `/bff/callback`, require a
constant-time match between the inbound `state` and the cookie before you consume
the flow, then clear the cookie. Without this match, the flow stays open to
login-CSRF. The details and the surrounding flow live in
[`09-browser-login-bff.md`](09-browser-login-bff.md).

### Authorization uniqueness guard for the mint

The mint groups every tenant-scoped token a user holds under one OpenIddict
authorization keyed to `(subject, tenant)`, which is how the single-tenant
revoke finds and drops exactly that tenant's tokens. The spike's
find-or-create, in `spike/src/Idmt.Spike.Host/Server/UserTokenMint.cs`, is
idempotent only when calls run sequentially. The spike is single-threaded, so
its proof holds.

Under concurrency the check-then-create races: two mints for the same
`(subject, tenant)` can both miss the existing row and both create an
authorization. A later single-tenant revoke then hits one authorization and
misses the other, so it under-revokes and leaves live tokens behind, which is a
revocation-correctness defect, not a cosmetic one. You must add a uniqueness
constraint on `(subject, tenant)` or an upsert so the grouping invariant holds
under concurrent mints. The grouping design and the revoke path live in
[`07-revocation-hooks.md`](07-revocation-hooks.md).

### Real cross-site SameSite redirect test

The spike ran in-process against a `TestServer`, so the authorization-code
redirect never crossed a real site boundary and the `SameSite` cookie behavior
on a cross-site redirect-return was never exercised. The
[ADR 0002 §7.0](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#70-prototype-gate-precondition-to-ratification)
stand-in note records this explicitly.

You must add a test that drives the BFF login through a real cross-site redirect
so the `SameSite=Lax` session cookie and the new `bff_oauth_state` cookie behave
as they will in a browser, not as they happen to behave in-process. This test
pairs naturally with the
[state-to-browser binding](#state-to-browser-binding-for-the-bff-login) item,
since both concern cookie behavior across the redirect. Add it to the suite in
[`14-test-suite.md`](14-test-suite.md).

## Open questions

These are the five decisions
[ADR 0002 §7.1](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#71-open-questions)
deliberately left undecided. They are not gaps the spike forgot to close; they
are choices the ADR refused to make on paper. You must record each one as an
explicit decision (a new ADR or an amendment) rather than letting an
implementation detail settle it by accident. The first is now decided in
[ADR 0003](../../adr/0003-machine-client-authentication.md); the other four
remain open.

### 1. Machine-client authentication without the password grant (decided)

This question is settled in
[ADR 0003](../../adr/0003-machine-client-authentication.md). The interactive
browser flow was already closed by gate 8 (authorization code with PKCE behind a
server-side BFF session). For non-interactive callers, v2 uses the OAuth 2.0
client-credentials grant against the existing OpenIddict server rather than a
separate token scheme: each trusted gateway or service is a registered
confidential client whose secret is its durable credential, and it mints
short-lived, tenant-audienced reference tokens that flow through the one shared
validation path. The build task is
[`16-machine-client-auth.md`](16-machine-client-auth.md). No further decision is
needed here; what remains is implementation.

### 2. Out-of-process resource servers

v2 currently assumes the resource API is co-hosted with the OpenIddict server,
because the local validation handler enforces per-request revocation only when
it can read the shared token store in-process. A split deployment falls back to
remote introspection, which does not enforce per-request revocation and so
reopens the C1 gap. You must decide whether to support a split deployment at
all, and if you do, whether introspection without response caching is an
acceptable revocation story. Until that decision is recorded, co-hosting stays
the assumption; see [`04-openiddict-server.md`](04-openiddict-server.md).

### 3. Reference-token revocation backplane transport at scale-out

The backplane is a near-term hardening requirement (see
[Reference-token revocation backplane](#reference-token-revocation-backplane)),
but its transport is an open question. The two candidates are Redis
publish-subscribe and database polling, and they trade latency against
infrastructure footprint differently. You must record the transport choice
explicitly, because it shapes both the revocation-latency property and the
deployment dependencies the backplane introduces.

### 4. Per-tenant signing keys

The default is a single issuer with the tenant carried as the token audience,
which keeps the OpenID Connect discovery document single-issuer and conformant.
Per-tenant signing keys would give hard cryptographic tenant isolation at the
cost of that simplicity. You revisit this only if hard cryptographic tenant
isolation becomes a stated requirement, and if you do, you record the move away
from the single-issuer default as an explicit decision.

### 5. Multi-factor factor selection and rollout timeline

The requirement is locked: system users and multi-tenant users must satisfy a
second factor before a token issues, enforced as a core domain invariant. What
is open is the implementation, not the requirement: TOTP versus WebAuthn and the
phasing of the rollout. You must record the factor choice and the timeline
explicitly. See [`12-mfa.md`](12-mfa.md) for the locked requirement and the
factor-provider seam.

## Resolved stand-ins

The spike surfaced two questions that look open but are closed. Record them as
closed so you do not chase them as if they were live work.

The gate-7 client-credentials session stand-in is closed by gate 8. Gate 7
acquired the BFF session's reference token through a client-credentials
back-channel, so the token's subject was the client, not the user. Gate 8
replaced that with real authorization code plus PKCE through an interactive
authorization-server session, so the issued token's subject is the authenticated
user. The stand-in comment in `spike/src/Idmt.Spike.Host/Bff/BffEndpoints.cs`
describes the old path; the live path is in
`spike/src/Idmt.Spike.Host/Bff/AuthCodeEndpoints.cs`. This also resolves the
first-party interactive-auth question. The machine-client half is now decided too,
in [ADR 0003](../../adr/0003-machine-client-authentication.md) (see
[open question 1](#1-machine-client-authentication-without-the-password-grant-decided)).

The `RevokeBySubjectAsync` availability question is closed. The ADR originally
hedged on whether the installed OpenIddict version exposed it; the spike
confirmed OpenIddict 7.5.0 does. A full credential change drops every token the
user holds with a single `RevokeBySubjectAsync` call, and a single-tenant revoke
uses `RevokeByAuthorizationIdAsync` on the `(subject, tenant)` authorization,
both proven against a 100-token user. There is nothing left to investigate here.

## Dependencies

This doc closes the build playbook, so it points backward rather than forward.
Start from the [playbook overview](00-overview.md) for how the pieces fit, then
follow each item below to the doc that owns the surface it touches.

- The backplane and the out-of-process question touch
  [`04-openiddict-server.md`](04-openiddict-server.md).
- The state-to-browser binding and the cross-site redirect test touch
  [`09-browser-login-bff.md`](09-browser-login-bff.md).
- The authorization uniqueness guard touches
  [`07-revocation-hooks.md`](07-revocation-hooks.md).
- The cross-site redirect test lands in
  [`14-test-suite.md`](14-test-suite.md).
- The multi-factor question touches [`12-mfa.md`](12-mfa.md).

## Next steps

There are no next steps in the build sense. Everything in this tracker is
scheduled work or a decision to record, and none of it blocks the core build,
which is complete and correct on a single instance. Treat the hardening items as
work items to plan into a production-readiness milestone, and treat the open
questions as decisions to capture in an ADR or an amendment before the relevant
code lands, so none of them gets settled silently.
