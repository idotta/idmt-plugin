# ADR 0002 — IDMT v2 Architecture Sketch (architect-reviewer)

- **Status:** Draft / for comparison
- **Date:** 2026-06-04
- **Author:** architect-reviewer
- **Scope:** Greenfield v2 layout sketch. Design artifact only, no implementation.
- **Relates to:** ADR-0001 (canonical identity), `SECURITY_AUDIT.md`

> This is one of three parallel architect sketches. It is written to be read
> side-by-side against the others. It is deliberately opinionated. The central
> bet: **v2 should own a multi-tenant *authorization* model and stop owning an
> *authentication server*.** OpenIddict is the token engine; IDMT is the
> tenancy-and-authorization layer wrapped around it, plus the endpoint
> scaffolding that makes both the tenant side and the sys-admin side trivial to
> stand up.

---

## 0. Framing: what changed, and the one architectural insight

ADR-0001 set out to hand-build the hard parts of an identity provider:
server-side opaque sessions for instant revocation, a `/sys-switch` flow with
step-up and time-bound elevation, per-(user,tenant) lockout, audit shipping. All
of that is correct *as requirements*. The v2 insight is that **most of it is
commodity IdP machinery that OpenIddict already provides**:

| ADR-0001 hand-rolled mechanism | OpenIddict native equivalent |
|---|---|
| `ServerSession` table + 30s cache + opaque cookie id | **Reference (opaque) access tokens** — token data lives server-side, the wire value is a lookup handle. Revoke = delete one row. |
| `/sys-switch` minting a scoped, time-bound, audited session | **Token exchange (RFC 8693)** — trade a sys token for a tenant-scoped, short-lived, fully-auditable token. |
| `UpdateSecurityStampAsync` invalidating all sessions | **Bulk token revocation by subject** in the OpenIddict token store. |
| Hand-rolled refresh + bearer expiry | OpenIddict **refresh-token rotation** with reuse detection. |

So v2's job shrinks to the part that is genuinely *ours* and not commodity:

1. The **multi-tenant authorization model** (`TenantAccess`, `SysRole`, role
   resolution per tenant).
2. The **mapping** from that model onto OpenIddict's token issuance (which
   claims/scopes/audiences go into a token, and *whether a token may be issued
   at all* — the TenantAccess gate).
3. **Endpoint scaffolding** so a consumer can mount a tenant-facing surface and
   a sys-admin-facing surface with the right policies pre-attached.

Everything else we delete (see §7).

---

## 1. Bounded contexts / module boundaries

I decompose v2 into **five bounded contexts**. The decomposition is driven by
the *dependency rule* (dependencies point inward toward the domain) and by
*blast radius* (a change to OpenIddict's API, or to Finbuckle, should be
absorbable in one assembly).

```
┌───────────────────────────────────────────────────────────────────┐
│ Context A — Identity & Access Domain  (the part that is OURS)       │
│   Canonical IdmtUser, SysRole, TenantAccess, TenantRole.            │
│   Pure model + invariants. No EF, no HTTP, no OpenIddict types.     │
├───────────────────────────────────────────────────────────────────┤
│ Context B — Multi-Tenancy Resolution                                │
│   Tenant identity, tenant store, route/header/claim resolution.     │
│   Owns the Finbuckle seam. Knows nothing about tokens.              │
├───────────────────────────────────────────────────────────────────┤
│ Context C — Authorization Server Integration                        │
│   The OpenIddict seam. Token issuance, scopes, reference tokens,    │
│   refresh rotation, token exchange. The ONLY context that names     │
│   OpenIddict types.                                                 │
├───────────────────────────────────────────────────────────────────┤
│ Context D — Support / Impersonation                                 │
│   Sys-user "support a tenant" via token exchange. Audit. Policy.    │
│   Depends on A (capability check) + C (mint exchange token).        │
├───────────────────────────────────────────────────────────────────┤
│ Context E — Endpoint Scaffolding & Composition                      │
│   The consumer-facing surface. AddIdmt, MapIdmt*, policy contract,  │
│   MFA, rate limiting, email flows. Composes A–D.                    │
└───────────────────────────────────────────────────────────────────┘
```

**What is a separate assembly vs. a folder, and why.**

The rule I apply: *an assembly boundary exists where I want an independent
substitution point, an independent test surface, or an independent compile-time
guarantee about what an inner layer may reference.* A folder is enough when the
only goal is organization.

| Context | Packaging | Why |
|---|---|---|
| A — Identity & Access Domain | **Separate assembly** `Idmt.Core` | The domain must be testable with zero infrastructure and must *not be able to* reference EF/OpenIddict/Finbuckle. An assembly boundary makes that a compile-time guarantee (the package simply doesn't reference them), not a code-review convention. This is the dependency-rule firewall. |
| B — Multi-Tenancy | **Separate assembly** `Idmt.MultiTenancy` | Finbuckle is a swap candidate (the owner might one day want path-based-only, or a custom resolver). Isolating it means a Finbuckle major-version bump or replacement is a one-package blast radius. Also independently testable against an in-memory tenant store. |
| C — Auth-Server Integration | **Separate assembly** `Idmt.OpenIddict` | This is the single most coupled-to-a-vendor context and the one most likely to churn (OpenIddict releases, OAuth spec nuances). It must be the *only* place that `using OpenIddict.*`. An assembly boundary is the firewall that keeps OpenIddict types from leaking into handlers and tests. |
| D — Support/Impersonation | **Folder inside `Idmt.OpenIddict`**, with its *contract* in `Idmt.Core` | The token-exchange mechanics are inseparable from OpenIddict, so the implementation lives with C. But the *policy* ("who may support whom, for how long, with what reason") is domain and lives in A. This split is deliberate: the dangerous capability is governed by domain rules that are unit-testable without OpenIddict. |
| E — Scaffolding & Composition | **Separate assembly** `Idmt.AspNetCore` (the NuGet consumers reference) | This is the only package most consumers add. It transitively pulls A–D. Keeping it thin and composition-only means the "opinionated defaults" live in one auditable place. |

Net packaging: **four shipped assemblies** (`Idmt.Core`, `Idmt.MultiTenancy`,
`Idmt.OpenIddict`, `Idmt.AspNetCore`) plus a persistence assembly (below).
Fewer than this and OpenIddict leaks into the domain; more than this and we are
gold-plating. EF lives in its own `Idmt.Persistence.EntityFrameworkCore`
implementing repository interfaces declared in `Idmt.Core`, so the store is
swappable and the domain never sees `DbContext`.

> **Distinctive choice #1:** I do *not* keep v1's vertical-slice "static class
> per feature" as a layering primitive. Vertical slices are a *delivery*
> pattern; they belong inside `Idmt.AspNetCore` as the shape of the endpoint
> code, but they are not allowed to be the place where domain invariants or
> OpenIddict calls live. v1 conflated "feature folder" with "layer" and that is
> why `GrantTenantAccess.cs` ended up doing shadow-row surgery. v2 puts the
> invariant in the domain and the handler stays thin.

---

## 2. Solution & project layout with dependency direction

```
Idmt.slnx
│
├── src/
│   ├── Idmt.Core/                         ← Context A (domain). NO infra refs.
│   │   ├── Identity/                       IdmtUser, SysRole, TenantAccess, TenantRole
│   │   ├── Authorization/                  IdmtPolicies, ITenantAccessPolicy, capability rules
│   │   ├── Support/                        ISupportPolicy (token-exchange *rules*, not mechanics)
│   │   ├── Abstractions/                   repository + service interfaces (ports)
│   │   └── Results/                        ErrorOr error catalog (IdmtErrors)
│   │
│   ├── Idmt.MultiTenancy/                  ← Context B. Refs: Core, Finbuckle.
│   │   ├── Resolution/                      strategy wiring (route/header/claim/basepath)
│   │   ├── Store/                           tenant store abstraction over IdmtTenantInfo
│   │   └── TenantContextAccessor           bridges Finbuckle → Core's ICurrentTenant
│   │
│   ├── Idmt.OpenIddict/                    ← Context C+D impl. Refs: Core, MultiTenancy, OpenIddict.
│   │   ├── Server/                          authorize/token/introspect/revoke/userinfo wiring
│   │   ├── Tokens/                          reference-token config, refresh rotation, scopes
│   │   ├── ClaimsPipeline/                  Core model → token claims (TenantAccess gate here)
│   │   └── Support/                         RFC 8693 token-exchange handler (sys-support)
│   │
│   ├── Idmt.Persistence.EntityFrameworkCore/  ← store impl. Refs: Core, EF, OpenIddict.EF stores.
│   │   ├── Contexts/                         IdmtDbContext, IdmtTenantStoreDbContext
│   │   ├── Repositories/                     implements Core.Abstractions ports
│   │   └── Migrations/
│   │
│   └── Idmt.AspNetCore/                    ← Context E. The package consumers add.
│       ├── DependencyInjection/             AddIdmt<TStore>(...) builder
│       ├── Endpoints/                        MapIdmtTenant(), MapIdmtSystem(), MapIdmtAuthServer()
│       │   ├── Tenant/                        login, manage, tenant membership (vertical slices)
│       │   └── System/                        sys-user mgmt, support/exchange (vertical slices)
│       ├── Mfa/                              TOTP / WebAuthn step-up on the token foundation
│       ├── RateLimiting/                     edge limiter policy
│       └── Email/                            confirmation/reset flows
│
└── tests/
    ├── Idmt.Core.Tests/                    pure domain, no infra
    ├── Idmt.OpenIddict.Tests/              token issuance + gate + exchange
    ├── Idmt.Architecture.Tests/            FITNESS FUNCTIONS (see §6)
    └── Idmt.Integration.Tests/            WebApplicationFactory + SQLite, cross-tenant fuzzer
```

**Dependency direction (must hold; enforced as a fitness function):**

```
                 Idmt.AspNetCore  (composition root)
                 /     |      \      \
                v      v       v      v
   Idmt.OpenIddict  Idmt.MultiTenancy  Idmt.Persistence.EF
                \      |      /
                 v     v     v
                  Idmt.Core         ← depends on NOTHING of ours, no infra
```

- `Idmt.Core` references no other Idmt package and no infrastructure.
- `Idmt.OpenIddict` is the *only* package allowed to reference `OpenIddict.*`.
- `Idmt.MultiTenancy` is the *only* package allowed to reference `Finbuckle.*`.
- `Idmt.Persistence.EntityFrameworkCore` is the *only* package allowed to
  reference `Microsoft.EntityFrameworkCore.*`.
- `Idmt.AspNetCore` is the composition root and the only package allowed to
  reference ASP.NET Core hosting + all the others.

The seams that make OpenIddict / Finbuckle / EF swappable and testable are,
respectively: the **ClaimsPipeline + token port** in C, the
**ICurrentTenant / tenant-store port** in B, and the **repository ports** in
the persistence package. Each vendor is named in exactly one assembly.

---

## 3. Public API sketch (consumer-facing contracts)

### 3.1 Registration surface

The v1 `AddIdmt<TDbContext>` with five positional `Action<>`/delegate parameters
is a smell — positional delegates are unergonomic and force the consumer to know
ordering. v2 uses a **builder** so each concern is named and discoverable, and so
"opinionated default" vs "extension point" is visible in the type system.

```csharp
public static IdmtBuilder AddIdmt(
    this IServiceCollection services,
    IConfiguration configuration,
    Action<IdmtOptions>? configureOptions = null);

// Fluent builder — every method is an explicit, documented seam.
public sealed class IdmtBuilder
{
    // Persistence: pick a store implementation (default EF Core).
    IdmtBuilder UsePersistence(Action<IdmtPersistenceBuilder> configure);

    // Multi-tenancy: tenant resolution strategies + store.
    IdmtBuilder UseMultiTenancy(Action<IdmtTenancyBuilder> configure);

    // Auth server: OpenIddict is the default; swappable in principle.
    IdmtBuilder UseAuthorizationServer(Action<IdmtAuthServerBuilder> configure);

    // Security-critical knobs (MFA requirement, support TTL, token lifetimes).
    IdmtBuilder ConfigureSecurity(Action<IdmtSecurityOptions> configure);

    // Extension points — see §4 for the locked/open line.
    IdmtBuilder AddClaimsEnricher<T>() where T : class, IIdmtClaimsEnricher;
    IdmtBuilder AddAuthorizationPolicies(Action<AuthorizationBuilder> extend);
}
```

`AddIdmt` returns a builder rather than `IServiceCollection` so that the
security-critical wiring (the TenantAccess gate, reference tokens, refresh
rotation) is applied *eagerly and unconditionally* inside the builder's
`Build()` and cannot be omitted by a consumer who forgets a call. The
extension hooks are *additive only* — they cannot remove a default.

### 3.2 Endpoint scaffolding — tenant side and system side

This is the "opinionated but customizable" payoff. Two mapping entry points,
each pre-attaching the correct authentication scheme and authorization policies.
The consumer chooses *which* surfaces to mount and where.

```csharp
public static class IdmtEndpointRouteBuilderExtensions
{
    // The OAuth/OIDC server endpoints (OpenIddict-backed): authorize, token,
    // introspection, revocation, userinfo. Mounted once.
    static IEndpointConventionBuilder MapIdmtAuthorizationServer(
        this IEndpointRouteBuilder app, Action<IdmtAuthServerEndpointOptions>? o = null);

    // Tenant-facing surface: login/logout, account self-management, email flows,
    // tenant-membership management. All policies pre-attached.
    static IdmtTenantEndpoints MapIdmtTenantApi(
        this IEndpointRouteBuilder app, Action<IdmtTenantEndpointOptions>? o = null);

    // System-admin surface: sys-user CRUD, sys-role assignment, and the
    // support/impersonation (token-exchange) endpoint. RequireSysAdmin pre-attached.
    static IdmtSystemEndpoints MapIdmtSystemApi(
        this IEndpointRouteBuilder app, Action<IdmtSystemEndpointOptions>? o = null);
}
```

The returned `IdmtTenantEndpoints` / `IdmtSystemEndpoints` expose the individual
route groups so a consumer can add their *own* endpoints under the same group
with the same pre-attached policy, or selectively disable a built-in:

```csharp
var tenant = app.MapIdmtTenantApi(o =>
{
    o.Membership.Enabled = true;       // opinionated default: on
    o.SelfService.Enabled = true;
});
// Consumer composes their own endpoints under the SAME policy umbrella:
tenant.MembershipGroup.MapGet("/grants/pending", MyHandler)
                      .RequireAuthorization(IdmtPolicies.TenantManager);
```

### 3.3 Authorization policy contract

Policies are exposed as **string constants on a public static surface** so they
are referenceable from consumer endpoints, and the *policy objects* are
registered by the builder. The consumer never re-declares them.

```csharp
public static class IdmtPolicies
{
    public const string SysAdmin       = "Idmt.SysAdmin";
    public const string SysUser        = "Idmt.SysUser";
    public const string TenantManager  = "Idmt.TenantManager";
    public const string TenantMember   = "Idmt.TenantMember";   // new in v2: the gate baseline
    public const string SupportSession = "Idmt.SupportSession"; // token-exchange-minted tokens
}
```

> **Distinctive choice #2:** v2 adds `TenantMember` and `SupportSession` as
> first-class policies. v1 only had role-shaped policies (SysAdmin/SysUser/
> TenantManager) and relied on the login-time gate for membership. In v2 the
> gate also runs *at token-issuance* (§5), and `TenantMember` lets every
> tenant endpoint assert membership declaratively rather than implicitly.
> `SupportSession` lets endpoints distinguish a real member from an
> impersonating sys user — important for audit and for blocking destructive
> operations during support.

---

## 4. The opinionated-vs-customizable seam (the central design problem)

This is where I plant the flag. The failure mode of a "customizable security
library" is that a consumer customizes away a security property without
realizing it (v1 already had to special-case `SameSite=None` → force `Strict`).
My rule:

> **Security invariants are locked and additive-only. Shape and surface are
> open.** A consumer may add behavior; they may never subtract a security
> property, and the type system should make subtraction impossible rather than
> merely discouraged.

### 4.1 LOCKED (no extension point, enforced in `Build()`)

- **The TenantAccess gate.** No token is issued for a (user, tenant) without an
  active, unexpired `TenantAccess` row. Uniform for *all* users including
  SysAdmin (carried forward from v1's locked decision #4). There is no hook to
  bypass it. Sys access to a tenant goes through token exchange (§5), which
  itself writes an audit record — there is no ambient path.
- **Reference (opaque) access tokens.** Self-contained JWT access tokens are
  *not offered as an option*, because that would silently reintroduce the
  revocation gap ADR-0001 exists to close. (ID tokens for OIDC clients remain
  signed JWTs — that's protocol-correct and not a revocation concern.)
- **Refresh-token rotation with reuse detection.** On.
- **Support-token TTL ceiling.** A consumer may lower it; they cannot raise it
  above the hard ceiling (e.g. 15 min, matching ADR-0001 §2.3).
- **Per-tenant token audience isolation** — a token minted for tenant A is
  rejected at tenant B (the v1 `ValidateBearerTokenTenantMiddleware` invariant,
  now enforced by OpenIddict audience validation rather than custom middleware).
- **Support requires a `reason` and emits an audit event.** Not optional.

### 4.2 OPEN (documented extension points)

- **Claims enrichment** (`IIdmtClaimsEnricher`) — add custom claims/scopes to a
  token *after* the gate has run. Additive; cannot remove gate-mandated claims.
- **Tenant resolution strategy** — route/header/claim/basepath/custom resolver.
- **MFA factor selection** — which factors are required for whom (subject to the
  locked rule that sys users *must* have a second factor).
- **Email transport** (`IIdmtEmailSender`) and link generation.
- **Additional authorization policies** layered on top of the built-ins.
- **Custom endpoints** under the pre-attached policy groups (§3.2).
- **Store backend** — EF is the default, but the repository ports allow another.

### 4.3 Why this line

The locked set is exactly the properties whose violation is invisible at runtime
until exploited — revocation latency, gate bypass, audience confusion, support
without audit. Those are *correctness*, not *configuration*. Everything in the
open set is a property the consumer can verify by inspection (an email arrives, a
claim appears, a route exists), so a misconfiguration there is self-revealing and
safe to delegate. The builder enforces the line structurally: locked behavior is
applied in `Build()` regardless of what the consumer called; open behavior is
opt-in via named methods.

---

## 5. Token-exchange sys-support flow & reference-token revocation

### 5.1 Sys-support via RFC 8693 token exchange

This replaces ADR-0001's `/sys-switch` *and* v1's shadow-row-into-tenant
approach. Responsibilities split cleanly across contexts:

```
Sys user (already authenticated, holds reference token, SysRole=SysSupport)
        │ POST /system/support/exchange
        │   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
        │   subject_token=<sys reference token>
        │   audience=tenant:acme
        │   scope=support
        │   reason="ticket #1234"        ← required (LOCKED, §4.1)
        ▼
Idmt.AspNetCore (System endpoints)      — auth: RequireSysUser, rate-limited
        ▼
Idmt.OpenIddict / Support handler       — OpenIddict token-exchange grant
        │  1) calls Core ISupportPolicy.CanSupport(subject, targetTenant)  ┐ DOMAIN
        │  2) writes SupportAudit row (who, tenant, reason, expiry, ip)    ┘ rule + audit
        │  3) mints REFERENCE token: aud=tenant:acme, scope=support,
        │     ttl<=ceiling, claim idmt:support_of=<sysUserId>
        ▼
Returns a tenant-scoped, opaque, short-lived support token.
```

- **Capability check lives in `Idmt.Core`** (`ISupportPolicy`) — unit-testable
  with no OpenIddict. "Has an active SysRole grant" is a domain rule.
- **Mechanics live in `Idmt.OpenIddict`** — only it knows what a token-exchange
  grant is.
- **The minted token is reference-typed and tenant-audienced**, so the existing
  per-tenant audience isolation applies for free: a support token for `acme`
  cannot touch `globex`.
- **Audit is written before the token is returned**, in the same unit of work as
  the token-store insert, so there is no "token exists but no audit" window.
- The `SupportSession` policy (§3.3) lets tenant endpoints detect impersonation
  and refuse destructive operations under support, or surface a banner.

> **Distinctive choice #3:** I treat the support token as *just another
> tenant-audienced reference token with a `support` scope and a `support_of`
> claim*, not as a special session object. This means the entire revocation,
> expiry, and audience machinery is shared with normal tokens — one code path,
> one set of fitness functions. No second session table, no `IsSysSession`
> branch threaded through authorization (ADR-0001 had that branch in its core
> `CanAccessTenantAsync`; v2 deletes it).

### 5.2 Reference-token revocation & blast radius

- **Revoke one token:** delete its row in the OpenIddict token store. Instant;
  next introspection fails.
- **Revoke a user everywhere (compromise / password change):** bulk-revoke by
  subject in the token store. This is the OpenIddict-native replacement for
  ADR-0001's "bump SecurityStamp → invalidate all ServerSessions." We still bump
  `SecurityStamp` on the canonical user as the *source-of-truth signal*, and the
  revocation is the *enforcement*.
- **Revoke a tenant grant:** revoke tokens whose `aud = tenant:X` for that
  subject; the canonical user's tokens for *other* tenants survive. This is the
  fine-grained-without-cross-tenant-collateral property ADR-0001 §2.7 wanted,
  achieved by audience filtering rather than a session table.
- **Revoke a sys-support session:** revoke tokens with `scope=support` and
  `support_of=<sysUserId>`; the sys user's normal sys token survives.

Blast radius is bounded by *audience + scope + subject* filters on a single
token store, which is conceptually identical to ADR-0001's session filters but
implemented by the engine we chose precisely so we don't maintain it.

---

## 6. Key tradeoffs, risks, and the fitness functions that guard them

| # | Risk | Likelihood / Impact | Guard (test / fitness function) |
|---|---|---|---|
| R1 | **Canonical-identity blast radius** — one stolen credential ⇒ all tenants. | Med / High | LOCKED: sys users require a second factor; multi-tenant members require MFA (config, defaulting on). Fitness fn: assert no token is issued to a multi-tenant subject without an MFA-satisfied claim. |
| R2 | **Coupling to OpenIddict** — vendor API churn / future relicensing. | Med / Med | Architecture test: only `Idmt.OpenIddict` may reference `OpenIddict.*`. The `IIdmtAuthorizationServer` port in Core means a future engine swap is one assembly. |
| R3 | **Finbuckle ↔ OpenIddict tenancy reconciliation** — two systems each have a notion of "current tenant"; they can disagree (token says `acme`, route resolves `globex`). | **High / High — the sharpest risk.** | Audience = tenant is the single source of truth at the resource. Fitness fn / route-mutation fuzzer (carried from ADR-0001 §4): authenticate for tenant A, mutate the route segment to every other tenant, assert 403. Plus: the ClaimsPipeline stamps `aud` from the *resolved* tenant at issuance, and the resource validates `aud == resolved-tenant` on every request. |
| R4 | **TenantAccess gate bypass** — a refactor lets a token issue without the gate. | Low / Critical | The gate is a mandatory step in the ClaimsPipeline registered in `Build()`. Test: parametric "issue token for user with no/expired TenantAccess ⇒ denied" across every grant type, including token-exchange. |
| R5 | **Reference-token store hot path** — every API call introspects. | Med / Med | Bench + cache (OpenIddict supports introspection caching; mirror ADR-0001's bounded TTL). Fitness fn: p99 introspection latency budget asserted in a load smoke test. |
| R6 | **Migration from v1** — v1 uses ASP.NET bearer-token handler + per-tenant cookies; v2 uses OpenIddict reference tokens. Token formats differ. | High / Med | Dual-run window: v2 mounts the OpenIddict server alongside; v1 tokens expire naturally; force re-auth at cutover (ADR-0001 already accepts forced password reset pre-prod). Migrator carries `IdmtUser`/`TenantAccess`/`SysRole` rows unchanged — schema is largely preserved (§7), lowering migration risk relative to ADR-0001's destructive reshape. |
| R7 | **Support-flow audit gap** — token minted but not audited. | Low / High | Audit insert and token-store insert in one transaction (§5.1). Test: simulate audit-write failure ⇒ assert no token returned. |
| R8 | **Opinionated defaults too rigid** — a real consumer needs something the locked set forbids. | Med / Low | Document each locked item with its rationale and the *supported* alternative (e.g. "need long-lived API tokens? issue a separate API-key surface, don't unlock self-contained access tokens"). Escape hatches are *parallel surfaces*, never weakened core. |

> **Distinctive choice #4:** I elevate R3 (Finbuckle/OpenIddict tenancy
> reconciliation) to *the* primary risk and make the resource-side audience
> check, not the middleware, the enforcement point. v1 had a bespoke
> `ValidateBearerTokenTenantMiddleware`; v2 deletes it because audience
> validation is a first-class token property the engine enforces. The
> route-mutation fuzzer is promoted from "nice test" to a required CI fitness
> function gating merge.

---

## 7. What v2 deletes, keeps, and adds — framed as boundary decisions

### Deletes (because the boundary moved to OpenIddict)
- **`ValidateBearerTokenTenantMiddleware`** → replaced by token `aud` validation.
- **`ITokenRevocationService` + `TokenRevocationCleanupService`** → replaced by
  the OpenIddict token store + its built-in pruning. We owned a revocation list
  because the bearer handler had none; OpenIddict reference tokens make the
  store authoritative.
- **The hybrid `CookieOrBearer` PolicyScheme + per-tenant cookie isolation as
  the primary auth model** → the API auth model becomes OpenIddict reference
  tokens. Cookies, if kept at all, become a thin first-party-client convenience
  over the same token store, not a parallel auth universe. (This collapses a
  whole class of "cookie path vs bearer path diverge" bugs.)
- **The bespoke bearer expiry/refresh config** (`BearerOptions`) → OpenIddict
  token + refresh lifetimes.
- **ADR-0001's `ServerSession` table, `/sys-switch`, and `IsSysSession`
  branch** → reference tokens + token exchange. We get the *capability* without
  building or maintaining the *mechanism*.
- **The five-positional-delegate `AddIdmt`** → the builder (§3.1).

### Keeps (because the boundary is genuinely ours)
- **Canonical `IdmtUser : IdentityUser<Guid>`, globally unique email.** ASP.NET
  Identity stays as the user/credential store. OpenIddict sits *in front of* it.
- **`TenantAccess` (IsActive, ExpiresAt) and the uniform login-time gate** — now
  *also* enforced at token issuance. This is the heart of what IDMT is.
- **`SysRole` (None/SysAdmin/SysSupport)** as a global flag.
- **`IdmtRole` per-tenant**, projected into per-tenant token claims.
- **Finbuckle.MultiTenant** for tenant resolution (isolated in `Idmt.MultiTenancy`).
- **Two EF contexts** (app data + tenant store), now joined by OpenIddict's own
  entity sets in the persistence assembly.
- **Vertical-slice endpoint shape** — but demoted to a *delivery* convention
  inside `Idmt.AspNetCore`, not a layering primitive (see §1, distinctive #1).
- **ErrorOr + FluentValidation, PiiMasker, the error catalog.**

### Adds
- The four-package boundary with the dependency-rule firewall (§2).
- `Idmt.Architecture.Tests` enforcing assembly reference rules as CI gates.
- `TenantMember` and `SupportSession` policies (§3.3).
- The token-exchange support surface and `SupportAudit` (§5.1).
- The `IdmtBuilder` opinionated/open seam (§4).

---

## 8. One-paragraph summary of the bet

v2 stops competing with OpenIddict on commodity IdP machinery and instead
becomes the **multi-tenant authorization layer and endpoint scaffolding** that
sits on top of it. The decomposition is firewalled by assembly boundaries so
that OpenIddict, Finbuckle, and EF are each named in exactly one package and are
swappable behind Core-owned ports; the domain (`Idmt.Core`) can be unit-tested
with zero infrastructure. Sys-support becomes a tenant-audienced, reason-bearing,
audited reference token minted via RFC 8693 token exchange — sharing one
revocation/expiry/audience code path with every other token, deleting ADR-0001's
bespoke session table and `IsSysSession` branch. The opinionated/customizable
line is drawn structurally: security invariants (gate, reference tokens, refresh
rotation, support TTL, audience isolation, audited support) are locked and
applied unconditionally in the builder; shape, claims, MFA factors, transport,
and extra endpoints are open. The Finbuckle/OpenIddict tenancy reconciliation is
named the primary risk and is guarded by making the token audience the single
source of truth plus a CI-gating route-mutation fuzzer.
