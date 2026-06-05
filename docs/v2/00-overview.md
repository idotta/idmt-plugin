# IDMT v2 build playbook: overview

This playbook is the engineering build guide for IDMT v2, a .NET 10 and
C# 14 multi-tenant identity library. It turns the accepted architecture in
[ADR 0002](../../adr/0002-idmt-v2-openiddict-authorization-layer.md) into an
ordered set of build tasks you follow to ship the two packages. You follow
this playbook if you're implementing IDMT v2, reviewing that implementation, or
extending it as a consumer who needs to know which behavior is locked and which
is yours to shape. v2 is greenfield: there is no v1 migration path, no
production data to carry, and no backward-compatibility contract. v1 hand-rolled
its own bearer-token and session machinery; v2 rents that machinery from
OpenIddict and keeps only the multi-tenant authorization policy that is
genuinely IDMT's. Every mechanism in this playbook was proven by a throwaway
spike across eight gates before the ADR moved to accepted, so each task promotes
a composition that already works rather than one you're inventing as you go.

## How to read this playbook

The numeric order of the task files is the recommended build order, and you can
follow it top to bottom to reach a working system. The build is a directed
acyclic graph, not a strict line: each task names its own dependencies in its
opening section, so when you want to jump ahead you can read the prerequisites a
task declares and build only what it needs. Every task promotes a mechanism the
spike already proved, which means you're hardening a known-good composition into
shippable code rather than discovering whether the composition holds. When a
task touches a locked security property, it links the ADR section that locked it
and the spike gate that proved it, so you can trace any decision back to its
evidence.

## The thesis

IDMT v2 owns the policy and rents the protocol. OpenIddict owns every commodity
OAuth 2.0 and OpenID Connect concern (the authorize, token, introspection,
revocation, and userinfo endpoints; refresh rotation; and reference tokens),
ASP.NET Core Identity stays the user and credential store, and
Finbuckle.MultiTenant stays the tenant resolver. IDMT contributes exactly three
things of its own: the canonical identity and `TenantAccess` and `SysRole`
authorization model projected into tokens, the opinionated wiring that composes
these engines correctly for multi-tenancy, and the endpoint scaffolding that
hands consumers pre-authorized route groups for both the tenant side and the
system-admin side. This division is fixed, and the rest of the playbook holds it.

## Package map

v2 ships as two NuGet packages, built from three projects plus a test project
that enforces the boundary between them. `Idmt.Core` is a separate project but
not a shipped package: there is no consumer of the domain without the host, so
its assembly is folded into the `Idmt.AspNetCore` package. The split stays a
project boundary purely to keep the engine-isolation guarantee compile-enforced.
The boundary that matters keeps the engine infrastructure (OpenIddict, Finbuckle,
Entity Framework Core) out of the domain, and you enforce it with a fitness test
rather than a convention. The following list names each project and the single
responsibility it carries.

- `Idmt.Core`: a separate, non-packable project holding the domain only (canonical
  `IdmtUser`, `IdmtRole`, `TenantAccess`, `ClientTenantAccess`, `SysRole`, the
  authorization policies, the support-capability rule, the gate service ports, and
  a clock port). It references no engine infrastructure (no OpenIddict, Finbuckle,
  or Entity Framework Core) and depends only on the ASP.NET Core Identity
  abstractions its entities extend. Data access is not abstracted here: it lives in
  `Idmt.AspNetCore` against Entity Framework Core directly.
- `Idmt.AspNetCore`: the composition root and the package most consumers add,
  hosting OpenIddict, Finbuckle, Entity Framework Core, and the endpoints in
  dedicated folders. Its package includes the `Idmt.Core` assembly.
- `Idmt.Mfa`: the opt-in second factor (TOTP now, WebAuthn through
  `fido2-net-lib` later), shipped as its own package so the WebAuthn dependency
  stays off the main package.
- `Idmt.Architecture.Tests`: the fitness function that fails the build if
  `Idmt.Core` references any denied infrastructure assembly.

## Locked security invariants

These are the nine security properties IDMT applies unconditionally, regardless
of what a consumer configured. They are the heart of the "opinionated but
customizable" seam: a consumer can add behavior but cannot subtract any one of
them. They are not all enforced the same way. The options-flag invariants (class
A) are enforced by the `Build()` last-wins registration plus a startup self-check;
the rest (class B) are guaranteed structurally by the absence of a subtraction
seam plus the CI test suite. The list below states each invariant in one line;
[`10-locked-seam.md`](10-locked-seam.md) holds the full split and covers how each
class is enforced.

1. The uniform `TenantAccess` gate runs at token issuance for every grant and at
   every server-side support-token mint.
2. Access tokens are reference (opaque) tokens with `EnableTokenEntryValidation()`
   and the co-hosted local validation handler, so revocation is enforced per
   request.
3. Refresh tokens rotate on every use, with reuse detection.
4. An IDMT-owned per-request audience validation handler binds a token to the
   Finbuckle-resolved tenant and rejects a mismatch.
5. A `SecurityStamp`-change propagation hook revokes a user's tokens on
   credential change (`RevokeBySubjectAsync` for a full change,
   `RevokeByAuthorizationIdAsync` for a single tenant).
6. The support-token lifetime is bounded by a TTL ceiling a consumer can lower
   but not raise.
7. Support is audited, with a required reason, in the same transaction as the
   token-store insert.
8. A second authentication factor is mandatory for system users and for users
   with access to more than one tenant.
9. Cross-site request forgery protection (a `SameSite` cookie plus an
   anti-forgery token) is mandatory on the backend-for-frontend session whenever
   that session surface is enabled.

The lock works in two ways, split by class. For the class A options-flag
invariants (reference tokens, token-entry validation, refresh rotation, and the
audience handler registration), `Build()` applies the locked configuration as the
last-registered options so it overrides earlier consumer configuration, and an
`IStartupFilter` self-check asserts those flags at startup and fails fast when one
is missing. The class B invariants (the uniform gate, the TTL ceiling, atomic
audit, MFA, and CSRF) are not snapshot-checkable flags: they are guaranteed
structurally, because IDMT exposes no API to disable them, owns their call sites,
and the test suite fails on regression. A consumer can add behavior on top of any
invariant, but cannot subtract a locked property without the build, the startup
self-check, or CI failing. [`10-locked-seam.md`](10-locked-seam.md) holds the full
class A versus class B split.

## Build tasks

Each row below maps one task file to its scope and to the ADR section and spike
gate that back it. Read the table as the spine of the playbook: the files run in
the order shown, and the source column tells you where to verify any claim a task
makes.

| File | Task | Source (ADR / spike) |
|------|------|----------------------|
| `01-solution-and-packages.md` | Greenfield solution scaffold: two packages, the non-packable `Idmt.Core` project, plus the `Idmt.Architecture.Tests` fitness function | §2.2, §4 |
| `02-core-domain.md` | `Idmt.Core`: `IdmtUser` (global), `IdmtRole` (per-tenant), `SysRole`/`SysRoleKind`, `TenantAccess`, policy constants, support-capability rules, gate service ports, clock port | §2.1, §2.7 |
| `03-persistence-and-contexts.md` | Three public EF Core contexts: `IdmtDbContext` (identity and multi-tenant app data), `IdmtOpenIddictDbContext` (tenant-agnostic OpenIddict store), and the tenant-store context (tenant metadata); separate migration histories | §2.6, §3; gate 4 |
| `04-openiddict-server.md` | Engine wiring: reference tokens, `EnableTokenEntryValidation()`, `UseLocalServer()`, grants (auth-code with PKCE, client credentials, refresh), `/connect/*` endpoints | §2.3, §2.5; gate 1 |
| `05-multitenancy-audience.md` | Finbuckle wiring, `TenantUrns`, `TenantAudienceValidationHandler`, `resource` parameter convention, refresh `aud` precedence | §2.4, §2.6; gates 3, 4 |
| `06-tenant-access-gate.md` | Uniform `TenantAccess` gate at issuance for every grant and every mint | §2.7; gates 2, 6 |
| `07-revocation-hooks.md` | Authorization grouping per (user, tenant); `RevokeBySubjectAsync` and `RevokeByAuthorizationIdAsync`; `SecurityStamp` hook | §2.7; gate 6 |
| `08-support-token-mint.md` | Server-side mint via `IOpenIddictTokenManager.CreateAsync` in an owned transaction; audit atomicity; TTL ceiling; `SupportSession` policy | §2.8; gate 2 |
| `09-browser-login-bff.md` | Auth-code with PKCE interactive login and BFF session; cookie-to-bearer resolver; anti-forgery; state-to-browser binding | §2.4, §2.5, §2.5.1; gates 7, 8 |
| `10-locked-seam.md` | `IIdmtBuilder` fluent API; `Build()` last-wins lock; `IStartupFilter` self-check; MFA fail-fast rule | §2.9; gate 5 |
| `11-endpoint-scaffolding.md` | `MapIdmtTenantApi` and `MapIdmtSysAdminApi` pre-authorized route groups; policy constants | §2.10 |
| `12-mfa.md` | `Idmt.Mfa` package: TOTP now, WebAuthn later; requirement enforced by core | §2.2, §2.9, §7.1 |
| `13-seeding-bootstrap.md` | `IIdmtApplicationSeeder`: idempotent client registration, scope catalog, first sys-admin from config | §3 |
| `14-test-suite.md` | CI-gated invariant matrix mapping ADR §4 tests to spike gates | §4 |
| `15-hardening-and-open-questions.md` | Near-term hardening and open-questions tracker | §5.2, §7.1 |
| `16-machine-client-auth.md` | Machine-client authentication: confidential clients, the client-credentials grant, a client-to-tenant gate, and gateway provisioning | ADR-0003; §2.4, §2.6 |

## Prototype evidence

The architecture in this playbook is not theoretical: a throwaway spike proved
every load-bearing composition claim before the ADR moved from proposed to
accepted. All eight gates passed (19 tests total) on .NET 10 with OpenIddict
7.5.0, Finbuckle.MultiTenant 10.0.3, and SQLite, covering reference-token
revocation, the server-side support-token mint with atomic audit, per-request
audience rejection, the tenant-agnostic OpenIddict context, the hostile-override
self-check, the `SecurityStamp` revocation hook against a 100-token user, the
backend-for-frontend session, and the real browser login (authorization code
with PKCE through an interactive session). Each task doc links the specific gate
that proved its mechanism, so you can read the task and its evidence side by
side. The spike stays out of `Idmt.slnx` and out of CI: it served its purpose as
proof and is not shipped or maintained as part of v2.

## Open questions

The following questions remain genuinely open and are tracked separately from
the gate. You must not settle any of them silently during implementation: when a
task brushes up against one, raise it and record the decision rather than
encoding an assumption in code.

- Machine-client authentication without the password grant: decided in
  [ADR 0003](../../adr/0003-machine-client-authentication.md). Non-interactive
  callers use the OAuth 2.0 client-credentials grant, built in
  [`16-machine-client-auth.md`](16-machine-client-auth.md).
- Out-of-process resource servers: whether to support a split deployment at all,
  and if so whether introspection without response caching is an acceptable
  revocation story.
- Reference-token revocation backplane transport at scale-out: Redis
  publish-subscribe versus database polling.
- Per-tenant signing keys: whether to move beyond a single issuer with tenant as
  audience if hard cryptographic tenant isolation becomes a requirement.
- Multi-factor factor selection and timeline: TOTP versus WebAuthn and the
  rollout, given that the requirement for a second factor is already locked.

The tracker lives in
[`15-hardening-and-open-questions.md`](15-hardening-and-open-questions.md);
take any answer there before it reaches the rest of the build.
