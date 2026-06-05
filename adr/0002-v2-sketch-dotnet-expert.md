# ADR 0002 — IDMT v2 Architecture Sketch (.NET Expert Lens)

- **Status:** Draft / Design Sketch (one of several competing proposals)
- **Date:** 2026-06-04
- **Author lens:** .NET 10 / C# 14 specialist
- **Supersedes (if adopted):** the hand-rolled token machinery in IDMT v1
- **Scope:** Design artifact only. No implementation. Signatures and structure are illustrative.

---

## 0. Thesis in one paragraph

IDMT v2 stops being an identity-provider and becomes a **multi-tenant authorization shell around OpenIddict**. OpenIddict owns every commodity OAuth2/OIDC concern (authorize/token/introspection/revocation/userinfo, refresh rotation, reference tokens, token exchange). ASP.NET Core Identity stays as the user store. Finbuckle stays as the tenant resolver. IDMT contributes exactly three things of its own: (1) the **canonical-identity + TenantAccess + SysRole authorization model** projected into tokens, (2) **opinionated-but-overridable wiring** that glues OpenIddict + Identity + Finbuckle together correctly for multi-tenancy, and (3) **endpoint scaffolding** that hands the consumer pre-authorized route groups for both the tenant side and the sys-admin side. Everything else gets deleted.

The architectural bet: *own the policy, rent the protocol.*

---

## 1. Solution & Project Layout

Multi-package, layered, dependency arrows point inward. net10.0 everywhere, `<LangVersion>14</LangVersion>`, `<Nullable>enable</Nullable>`, `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`, `ImplicitUsings` on.

```
Idmt.slnx
├── src/
│   ├── Idmt.Abstractions/                 ──►  (no IDMT deps)        [NuGet: Idmt.Abstractions]
│   │     Contracts only. Interfaces, options records, claim/scope/policy
│   │     name constants, ErrorOr error catalog, marker delegates.
│   │     Refs: ErrorOr, Microsoft.Extensions.* abstractions only.
│   │
│   ├── Idmt.Core/                         ──►  Abstractions          [NuGet: Idmt.Core]
│   │     The authorization MODEL (no web, no OpenIddict types leaking).
│   │     - Entities: IdmtUser : IdentityUser<Guid>, IdmtRole, TenantAccess,
│   │       SysRoleAssignment (table per ADR 0001), audit aggregates.
│   │     - ITenantAccessService, ISysRoleService, ICurrentPrincipalAccessor.
│   │     - The "claims projection" engine (IdmtClaimsProjector) — the single
│   │       source of truth for what TenantAccess/SysRole means as claims/scopes.
│   │     Refs: AspNetCore.Identity.Stores, EFCore.Abstractions.
│   │
│   ├── Idmt.Server/                        ──►  Core                  [NuGet: Idmt.Server]  ◄── MAIN PACKAGE
│   │     The OpenIddict integration + ASP.NET wiring + endpoint scaffolding.
│   │     - AddIdmt(...) entry point and the builder graph (§2).
│   │     - OpenIddict server/validation registration + IDMT handlers that
│   │       inject tenant/SysRole/TenantAccess into issued tokens.
│   │     - Token-exchange (RFC 8693) handler for sys-support (§4).
│   │     - Reference-token + Finbuckle wiring (§5, §6).
│   │     - Endpoint groups: MapIdmtTenantApi / MapIdmtSysAdminApi (§3).
│   │     Refs: OpenIddict.AspNetCore, OpenIddict.EntityFrameworkCore,
│   │           Finbuckle.MultiTenant.AspNetCore, FluentValidation, ErrorOr.
│   │
│   ├── Idmt.Persistence.EfCore/            ──►  Core                  [NuGet: Idmt.Persistence.EntityFrameworkCore]
│   │     IdmtDbContext, IdmtTenantStoreDbContext, OpenIddict store mapping,
│   │     entity configs, model-building extensions. Provider-agnostic.
│   │
│   └── Idmt.Mfa/                           ──►  Core                  [NuGet: Idmt.Mfa]  (optional add-on)
│         TOTP (Identity token providers) now; fido2-net-lib WebAuthn later.
│         Kept out of the main package so the WebAuthn dependency is opt-in.
│
├── tools/
│   └── Idmt.Migrator/                      console — v1→v2 data migration harness
│
├── samples/
│   └── Idmt.Sample.Host/                   reference host wiring both endpoint groups
│
└── tests/
      ├── Idmt.Core.UnitTests/             xUnit + EF InMemory + TimeProvider.Testing
      ├── Idmt.Server.IntegrationTests/    WebApplicationFactory + SQLite + Testcontainers(pg)
      └── Idmt.Server.Benchmarks/          BenchmarkDotNet (token issuance, claims projection)
```

### Dependency direction (strict)

```
Abstractions  ◄── Core  ◄── { Server, Persistence.EfCore, Mfa }
```

`Idmt.Abstractions` has **zero** dependency on OpenIddict, Finbuckle, or ASP.NET. This is what lets a consumer reference contracts (e.g. to implement `ITenantAccessStore`) without dragging the whole server runtime, and it's what keeps OpenIddict swappable in theory and testable in practice.

### Why OpenIddict lives only in `Idmt.Server`

OpenIddict types (`OpenIddictRequest`, `OpenIddictServerBuilder`, the event-handler model) are deliberately *not* exposed by Core or Abstractions. The integration is a leaf. If OpenIddict's API churns across a major version, only one project recompiles. The consumer never types `using OpenIddict.*` unless they explicitly reach for the `customizeServer` escape hatch (§2.4).

---

## 2. Module / Registration Design

### 2.1 Entry point

```csharp
namespace Idmt.Server;

public static class IdmtServiceCollectionExtensions
{
    extension(IServiceCollection services) // C# 14 extension block
    {
        public IIdmtBuilder AddIdmt(
            IConfiguration configuration,
            Action<IdmtBuilderOptions>? configure = null)
            => AddIdmt<IdmtDbContext>(configuration, configure);

        public IIdmtBuilder AddIdmt<TDbContext>(
            IConfiguration configuration,
            Action<IdmtBuilderOptions>? configure = null)
            where TDbContext : IdmtDbContext;
    }
}
```

The old positional-delegate soup (`configureDb`, `configureOptions`, `customizeAuthentication`, `customizeAuthorization`) is replaced by **a single options object that returns a fluent builder**. The builder is the override seam; the options object holds declarative config; both are validated `OnStart`.

### 2.2 The builder graph

`AddIdmt` returns `IIdmtBuilder`, deliberately mirroring how OpenIddict and Identity compose so it feels native:

```csharp
public interface IIdmtBuilder
{
    IServiceCollection Services { get; }

    IIdmtBuilder UseEntityFrameworkCore(Action<DbContextOptionsBuilder> configureDb);
    IIdmtBuilder AddMultiTenancy(Action<IdmtTenancyBuilder> configure);
    IIdmtBuilder AddServer(Action<IdmtServerBuilder> configure);          // wraps OpenIddict server
    IIdmtBuilder AddValidation(Action<IdmtValidationBuilder> configure);  // wraps OpenIddict validation
    IIdmtBuilder AddMfa(Action<IdmtMfaBuilder> configure);                // from Idmt.Mfa
    IIdmtBuilder ConfigureAuthorization(Action<AuthorizationBuilder> configure); // raw ASP.NET seam
}
```

Typical host wiring (opinionated defaults already applied; this is the *override* surface):

```csharp
builder.Services
    .AddIdmt<AppDbContext>(builder.Configuration, o =>
    {
        o.Issuer            = new Uri("https://id.example.com");
        o.AccessTokenFormat = IdmtTokenFormat.Reference;   // opaque + instant revocation (default)
        o.RefreshTokenTtl   = TimeSpan.FromDays(14);
        o.SupportTokenTtl   = TimeSpan.FromMinutes(15);    // sys-support exchange ceiling
    })
    .UseEntityFrameworkCore(db => db.UseNpgsql(cs))
    .AddMultiTenancy(t => t
        .ResolveBy(IdmtTenantStrategy.Route, IdmtTenantStrategy.Header)
        .WithPerTenantCookies()
        .WithRouteParameter("__tenant__"))
    .AddServer(s => s
        .AllowPasswordFlow()                 // first-party tenant login
        .AllowRefreshTokenFlow()
        .AllowTokenExchangeFlow()            // RFC 8693 — sys-support
        .EnableDegradedModeOff())            // we register real EF stores
    .AddValidation(v => v.UseLocalServer())  // introspect reference tokens in-process
    .AddMfa(m => m.AddTotp());
```

### 2.3 Opinionated defaults vs. override seams

| Concern | Opinionated default (zero-config) | Override seam |
|---|---|---|
| Access token format | **Reference (opaque)** for instant revocation | `o.AccessTokenFormat = Jwt` |
| Flows | password + refresh + token-exchange | `AddServer(s => ...)` |
| Token TTLs | access 10 min / refresh 14 d / support 15 min | options record |
| Endpoints | `/connect/token`, `/connect/userinfo`, `/connect/introspect`, `/connect/revoke` (OpenIddict conventions) | `IdmtServerBuilder.SetTokenEndpointUris(...)` |
| Authorization policies | the named policies in §3.4, pre-registered | `ConfigureAuthorization(...)` |
| Tenant resolution | Route → Header fallback | `AddMultiTenancy(...)` |
| Claims projection | `IdmtClaimsProjector` (TenantAccess + SysRole → claims/scopes) | replace via `services.Replace<IIdmtClaimsProjector>()` |
| Signing/encryption keys | dev: ephemeral; prod: **fails fast** unless configured | `IdmtServerBuilder.AddSigningCertificate(...)` |

Defaults are productive on day one but *refuse to silently ship insecure prod config* (ephemeral keys throw under `IsProduction()`).

### 2.4 How OpenIddict is wrapped (not hidden)

`IdmtServerBuilder` is a thin facade that (a) sets IDMT's opinionated OpenIddict options, (b) registers IDMT's event handlers, and (c) exposes a typed escape hatch for everything IDMT doesn't model:

```csharp
public sealed class IdmtServerBuilder
{
    public IdmtServerBuilder AllowPasswordFlow();
    public IdmtServerBuilder AllowRefreshTokenFlow();
    public IdmtServerBuilder AllowTokenExchangeFlow();
    public IdmtServerBuilder UseReferenceAccessTokens(bool enabled = true);
    public IdmtServerBuilder AddSigningCertificate(X509Certificate2 cert);
    public IdmtServerBuilder AddEncryptionCertificate(X509Certificate2 cert);

    /// Raw OpenIddict for anything IDMT does not opinion about (custom claims
    /// destinations, extra grant types, scope handling). IDMT applies its own
    /// config first, then invokes this, so the consumer always wins.
    public IdmtServerBuilder Configure(Action<OpenIddictServerBuilder> configure);
}
```

Internally `AddServer` does roughly:

```csharp
services.AddOpenIddict()
    .AddCore(c => c.UseEntityFrameworkCore().UseDbContext<IdmtDbContext>())
    .AddServer(server =>
    {
        server.SetTokenEndpointUris("connect/token")
              .SetUserinfoEndpointUris("connect/userinfo")
              .SetIntrospectionEndpointUris("connect/introspect")
              .SetRevocationEndpointUris("connect/revoke");

        server.UseReferenceAccessTokens();          // §5
        server.AllowRefreshTokenFlow();
        server.AllowCustomFlow(IdmtGrants.TokenExchange); // urn:ietf:params:oauth:grant-type:token-exchange

        // IDMT's own pipeline handlers — the heart of the library:
        server.AddEventHandler(IdmtPasswordGrantHandler.Descriptor);   // validates TenantAccess gate
        server.AddEventHandler(IdmtTokenExchangeHandler.Descriptor);   // sys-support (§4)
        server.AddEventHandler(IdmtClaimsDestinationHandler.Descriptor);// projects TenantAccess/SysRole

        server.UseAspNetCore().EnableTokenEndpointPassthrough();

        builderConsumerOverride?.Invoke(server); // consumer wins last
    })
    .AddValidation(v => { v.UseLocalServer(); v.UseAspNetCore(); });
```

### 2.5 Options + validation (fail fast)

```csharp
public sealed record IdmtBuilderOptions
{
    public required Uri Issuer { get; set; }
    public IdmtTokenFormat AccessTokenFormat { get; set; } = IdmtTokenFormat.Reference;
    public TimeSpan AccessTokenTtl  { get; set; } = TimeSpan.FromMinutes(10);
    public TimeSpan RefreshTokenTtl { get; set; } = TimeSpan.FromDays(14);
    public TimeSpan SupportTokenTtl { get; set; } = TimeSpan.FromMinutes(15);
    public bool RequireConfirmedEmail { get; set; } = true;
    public IdmtRateLimitOptions RateLimiting { get; init; } = new();
}
```

```csharp
services.AddOptions<IdmtBuilderOptions>()
    .Bind(configuration.GetSection("Idmt"))
    .Configure(configure)
    .Validate(o => o.SupportTokenTtl <= TimeSpan.FromMinutes(60),
              "Idmt:SupportTokenTtl must not exceed 60 minutes.")
    .ValidateDataAnnotations()
    .ValidateOnStart();   // surfaces misconfig at boot, not first request
```

`ValidateOnStart()` (plus a hosted `IValidateOptions` for cross-field rules like "Reference tokens require EF stores, not degraded mode") replaces v1's hand-rolled `IdmtOptionsValidator.Validate(null, ...)` call inside registration.

---

## 3. Public API Sketch

### 3.1 Carried-forward model types (from ADR 0001)

```csharp
public class IdmtUser : IdentityUser<Guid>            // GLOBAL canonical identity
{
    public string? PendingEmail { get; set; }
    public DateTimeOffset? PendingEmailExpiresAt { get; set; }
}

public class IdmtRole : IdentityRole<Guid>            // PER-TENANT
{
    public string TenantId { get; set; } = default!;
}

public sealed class TenantAccess                      // user ↔ tenant edge
{
    public Guid UserId { get; set; }
    public string TenantId { get; set; } = default!;
    public bool IsActive { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
}

public enum SysRoleKind { None = 0, SysAdmin = 1, SysSupport = 2 }
```

### 3.2 Claims projection — the one piece of "secret sauce"

The single place that decides how the authorization model becomes token content. Pure, testable, no OpenIddict types in the signature:

```csharp
namespace Idmt.Abstractions;

public interface IIdmtClaimsProjector
{
    /// Produces the IDMT claim set for a (user, tenant, sysRole, purpose) tuple.
    /// Called by the OpenIddict pipeline handler during token issuance.
    ValueTask<IdmtClaimSet> ProjectAsync(IdmtPrincipalContext context, CancellationToken ct);
}

public sealed record IdmtPrincipalContext(
    Guid UserId,
    string? TenantId,
    SysRoleKind SysRole,
    IdmtTokenPurpose Purpose);       // TenantAccess | SysAdmin | SupportSession

public sealed record IdmtClaimSet(
    IReadOnlyList<Claim> Claims,
    IReadOnlyList<string> Scopes,
    string? Audience);

public enum IdmtTokenPurpose { TenantAccess, SysAdmin, SupportSession }
```

### 3.3 Endpoint scaffolding — the "opinionated but customizable" core

Two route-group factories. Each returns a `RouteGroupBuilder` with the **right policy already attached**, so the consumer can append their own endpoints into a correctly-authorized group, or take the batteries-included defaults.

```csharp
namespace Idmt.Server;

public static class IdmtEndpointRouteBuilderExtensions
{
    extension(IEndpointRouteBuilder app)
    {
        /// Tenant-facing surface. Resolves tenant via Finbuckle, requires a
        /// tenant-scoped access token, applies the auth rate-limiter.
        /// includeBuiltIn maps: /me (userinfo proxy), /manage/info,
        /// /manage/password, /manage/email-change, /manage/mfa.
        public RouteGroupBuilder MapIdmtTenantApi(
            string prefix = "/api",
            bool includeBuiltIn = true);

        /// System-admin surface. Requires RequireSysAdmin. includeBuiltIn maps:
        /// tenant CRUD, grant/revoke TenantAccess, SysRole assignment,
        /// active-session listing, and POST /sys/support/{tenantId} (§4).
        public RouteGroupBuilder MapIdmtSysAdminApi(
            string prefix = "/sys",
            bool includeBuiltIn = true);
    }
}
```

Host usage — the balance point in action:

```csharp
// Take the defaults, then bolt on consumer endpoints inside the pre-authorized group.
var tenant = app.MapIdmtTenantApi();                 // built-ins + tenant policy + rate limit
tenant.MapGet("/assets", ListAssets);                // inherits tenant authorization

var sys = app.MapIdmtSysAdminApi(includeBuiltIn: false); // I want ONLY my own sys endpoints
sys.MapGet("/tenants/{id}/usage", GetTenantUsage);       // already RequireSysAdmin

// OpenIddict's own protocol endpoints are mapped separately (passthrough handlers):
app.MapIdmtServerEndpoints();   // /connect/token, /userinfo, /introspect, /revoke
```

Built-in endpoints follow v1's vertical-slice shape but **thinner**: a slice is now `{ Request record, ErrorOr<T> handler, FluentValidation validator, mapper }` — minus everything OpenIddict now owns. Mappers use `TypedResults`:

```csharp
internal static RouteHandlerBuilder MapChangePassword(this RouteGroupBuilder g) =>
    g.MapPost("/manage/password",
        async (ChangePasswordRequest req, IChangePasswordHandler h, CancellationToken ct)
            => (await h.HandleAsync(req, ct)).ToHttpResult())   // ErrorOr<T> → Results<Ok, ValidationProblem, ...>
     .WithName("Idmt.ChangePassword");
```

### 3.4 Authorization policy names (constants in Abstractions)

```csharp
public static class IdmtPolicies
{
    public const string RequireSysAdmin     = "Idmt:RequireSysAdmin";
    public const string RequireSysUser      = "Idmt:RequireSysUser";       // SysAdmin or SysSupport
    public const string RequireTenantManager= "Idmt:RequireTenantManager";
    public const string RequireTenantMember = "Idmt:RequireTenantMember";  // new: any active TenantAccess
    public const string SupportSessionOnly  = "Idmt:SupportSessionOnly";   // tokens minted via §4
}

public static class IdmtScopes
{
    public const string Tenant  = "idmt.tenant";
    public const string SysAdmin= "idmt.sys";
    public const string Support = "idmt.support";
}
```

Policies bind to OpenIddict's validation handler (not cookie/bearer schemes from v1). `RequireTenantMember` is a **resource-based** check: it compares the token's `tenant` claim against the Finbuckle-resolved tenant for the request — this is the v2 successor to v1's `ValidateBearerTokenTenantMiddleware`, now expressed as an `IAuthorizationHandler` rather than middleware.

---

## 4. Token-Exchange / Sys-Support Flow (RFC 8693)

**Goal:** a SysAdmin/SysSupport user "drops into" a tenant for a bounded, audited window — *without* shadow rows, without a second login, and with instant revocability.

### 4.1 Flow

```
SysAdmin already holds a sys token (scope=idmt.sys, purpose=SysAdmin).

POST /connect/token
  grant_type     = urn:ietf:params:oauth:grant-type:token-exchange
  subject_token  = <the caller's sys access token>          (reference token)
  subject_token_type = urn:ietf:params:oauth:token-type:access_token
  scope          = idmt.support
  resource       = https://id.example.com/tenants/acme      (target tenant)
  // optional: reason=<free text>, captured for audit

      │
      ▼
IdmtTokenExchangeHandler (OpenIddict event handler):
  1. Require caller principal has SysRole ∈ {SysAdmin, SysSupport}.   else → forbidden
  2. Resolve target tenant from `resource`; assert it exists/active.
  3. Mint a NEW reference access token via the projector with
     purpose = SupportSession, tenant = acme,
     ttl = min(options.SupportTokenTtl, remaining sys-token life),
     claims: sub=<sys user>, act={ sub=<sys user> } (RFC 8693 actor claim),
             idmt:support=true, idmt:reason=<reason>.
  4. Write SupportSessionAudit row (immutable): actor, tenant, reason,
     issuedAt, expiresAt, jti, ip, userAgent.   <-- mandatory
  5. Return the tenant-scoped support token (no refresh token issued).
```

Key properties:
- **No new account, no shadow row.** The support token's `sub` is the sys user; the `act` (actor) claim makes the impersonation explicit and auditable per the RFC.
- **Non-extendable.** No refresh token is issued for support sessions; when it expires, the sys user must re-exchange (re-audited each time).
- **Bounded by `SupportTokenTtl`** AND by the parent sys token's remaining life (can't outlive the grant).
- **Tenant pages can't tell the difference** at the authorization layer (it's a normal tenant-scoped token) but logs/audit always can (`idmt:support=true`, `act` claim).

### 4.2 Surface

```csharp
public interface ISupportSessionService
{
    ValueTask<ErrorOr<SupportSession>> BeginAsync(
        Guid sysUserId, string targetTenantId, string? reason, CancellationToken ct);
}

public sealed record SupportSession(
    string AccessToken, string TenantId, DateTimeOffset ExpiresAt, string Jti);
```

The exchange handler delegates to this service; the service is also what the audit and revocation paths key off `Jti`. The built-in `POST /sys/support/{tenantId}` endpoint is a thin convenience wrapper over the standard `/connect/token` exchange for consumers who prefer a named endpoint.

---

## 5. Reference-Token Revocation (Instant)

Because access tokens are **reference (opaque)**, every API call introspects a server-side token record. Revocation is therefore a single store update — no waiting for short JWT expiry, no denylist gymnastics.

```
Issue:   OpenIddict persists an OpenIddictToken row (status=valid) and returns
         an opaque handle as the access token.
Validate:Idmt.Server uses OpenIddict *local* validation (UseLocalServer) — it
         reads the token row in-process on each request and rejects if
         status != valid or past expiry.
Revoke:  flip the row(s) to status=revoked → next request fails instantly.
```

IDMT layers a small fan-out service on top so business events map to revocations:

```csharp
public interface IIdmtTokenRevoker
{
    ValueTask RevokeTokenAsync(string jti, CancellationToken ct);
    ValueTask RevokeUserTokensAsync(Guid userId, CancellationToken ct);            // password change, etc.
    ValueTask RevokeTenantAccessAsync(Guid userId, string tenantId, CancellationToken ct); // access revoked
    ValueTask RevokeSupportSessionAsync(string jti, CancellationToken ct);
}
```

Wired to model events:
- `SecurityStamp` change / password reset → `RevokeUserTokensAsync` (single canonical user → all tokens; the v1 shadow-row propagation bug is structurally gone).
- `TenantAccess.IsActive = false` or `ExpiresAt` passed → `RevokeTenantAccessAsync`.
- SysAdmin "end support" → `RevokeSupportSessionAsync(jti)`.

Background hygiene: a `BackgroundService` prunes expired/revoked OpenIddict token + authorization rows (replaces v1's `TokenRevocationCleanupService`; OpenIddict ships `OpenIddictQuartz`/pruning hooks we can reuse instead of hand-rolling).

**Performance note:** reference tokens add a DB read per request. Mitigate with a short-TTL in-memory cache of *valid* token records keyed by handle, invalidated on revoke via the revoker (cache the positive, never the negative). Benchmarked in `Idmt.Server.Benchmarks`. This is the central performance/security tradeoff of v2 and should be measured, not assumed.

---

## 6. Multi-Tenancy Integration (Finbuckle × OpenIddict × cookies)

Three concerns must coexist on one host. The integration rules:

### 6.1 Tenant resolution ordering
Finbuckle middleware runs **before** OpenIddict's pipeline so the OpenIddict server endpoints (`/connect/token`) see a resolved tenant. For first-party password login the tenant comes from the route (`/{__tenant__}/connect/token`) or a header; for token-exchange it comes from the `resource` parameter (§4), cross-checked against Finbuckle.

```
[ Finbuckle.UseMultiTenant ]
        → [ Idmt tenant-coherence middleware (assert resolved) ]
            → [ OpenIddict validation/server ]
                → [ Authorization (RequireTenantMember resource check) ]
                    → endpoints
```

### 6.2 Per-tenant cookies vs. the token server
v1 isolated **cookies** per tenant (`ConfigurePerTenant<CookieAuthenticationOptions>`). v2 keeps that *only for the interactive sign-in surface* (the authorize-code/MFA UI, if used). API auth is **bearer reference tokens**, which carry their tenant in a claim — no per-tenant cookie needed for APIs. So:
- Cookies (per-tenant, Finbuckle-isolated): the human-facing login/consent pages only.
- Tokens (tenant claim + resource audience): all API traffic.

This collapses v1's "hybrid cookie/bearer per request" complexity: the *cookie session* exists to obtain a *token*; resource servers only ever see tokens.

### 6.3 Signing keys per tenant?
**Decision: shared issuer, single signing key, tenant as a claim/audience.** Per-tenant keys/issuers are a documented non-goal for v1 parity (one trust domain, owner-controlled infra). Left as an open question (§8) only if a hard tenant-cryptographic-isolation requirement appears.

### 6.4 OpenIddict stores are tenant-tagged but globally stored
OpenIddict's token/application/authorization tables live in `IdmtDbContext` (the canonical, *not* per-tenant-row-filtered store for these tables), with `tenant` carried as token payload + audience. This avoids fighting Finbuckle's global query filters on the OAuth plumbing while still enforcing tenant scope at the authorization layer.

---

## 7. v1 Code: Deleted vs. Kept

### Deleted (OpenIddict / Identity now own it)
- `Features/Auth/Login.cs` (`LoginHandler`, `TokenLoginHandler`) → OpenIddict password grant + IDMT TenantAccess-gate handler.
- `Features/Auth/RefreshToken.cs` → OpenIddict refresh-token flow + rotation.
- `Features/Auth/Logout.cs` token side → OpenIddict revocation endpoint.
- `Services/TokenRevocationService.cs`, `ITokenRevocationService`, `Models/RevokedToken.cs` → OpenIddict reference-token status + `IIdmtTokenRevoker` facade.
- `Services/TokenRevocationCleanupService.cs` → OpenIddict pruning.
- `Middleware/ValidateBearerTokenTenantMiddleware.cs` → `RequireTenantMember` authorization handler (§3.4).
- `AddBearerToken` / `AddPolicyScheme` (`CookieOrBearerScheme`) wiring → OpenIddict validation; PolicyScheme no longer needed because API auth is uniformly bearer.
- Hand-rolled bearer query-string token plumbing for WebSockets → OpenIddict validation + a small token extractor for the SignalR path.
- The "duplicate account into tenant" cross-tenant access path (already partly gone in v1) → token exchange (§4).

### Kept / carried forward
- Canonical `IdmtUser`, `IdmtRole`, `TenantAccess`, `SysRoleAssignment` model (ADR 0001) — moved to `Idmt.Core`.
- `ITenantAccessService` and the **uniform TenantAccess login gate** (now a pre-issuance OpenIddict handler, still uniform incl. SysAdmin).
- Finbuckle multi-tenant resolution + `IdmtTenantInfo` + `IdmtTenantStoreDbContext`.
- Email flows (confirm/forgot/reset/email-change) and `IIdmtLinkGenerator`, `IEmailSender<IdmtUser>` — these remain IDMT's, now sitting on the token foundation.
- `PiiMasker`, audit aggregates, `ICurrentUserService` (renamed `ICurrentPrincipalAccessor`).
- Vertical-slice shape for the *remaining* business endpoints (manage/admin), `ErrorOr<T>` + FluentValidation.
- Rate limiting (built-in middleware) on the token + email endpoints.
- The v1→v2 data migration harness (`tools/Idmt.Migrator`).

---

## 8. Open Questions / Risks (.NET 10 + OpenIddict + Finbuckle)

1. **Finbuckle global query filters vs. OpenIddict EF stores.** OpenIddict's `OpenIddictEntityFrameworkCore` stores query their tables directly; if `IdmtDbContext` applies a Finbuckle `HasQueryFilter` broadly, OpenIddict reads could be silently tenant-filtered and break token validation. Mitigation: keep OpenIddict tables out of the multi-tenant filter set (own `DbContext` partition or explicit `IgnoreQueryFilters` mapping). **Needs a prototype to confirm composition order.**
2. **Reference-token read amplification.** One DB round-trip per request. The positive-cache mitigation (§5) must be validated under load; revocation-cache invalidation across multiple app instances needs a backplane (Redis pub/sub or DB change polling) — otherwise instant revocation degrades to cache-TTL revocation in a scaled-out deployment. This is the single biggest production risk.
3. **Token-exchange (RFC 8693) maturity in OpenIddict.** Token exchange is supported via custom-flow registration but is less turnkey than password/refresh; the actor (`act`) claim handling and `resource`→tenant mapping are bespoke handlers we own. Risk of OpenIddict API drift around custom grants across majors.
4. **Tenant resolution for the token endpoint.** Route-based tenant in the OAuth path (`/{tenant}/connect/token`) deviates from standard single-issuer OIDC discovery. Header/`resource`-based resolution is cleaner but means generic OIDC clients need IDMT-aware configuration. **Pick one and document the OIDC-conformance tradeoff.**
5. **Per-tenant cookies + OpenIddict authorize UI.** If interactive flows (authorize-code, MFA challenge pages) are enabled, Finbuckle per-tenant cookie isolation must coexist with OpenIddict's own auth/consent cookies — name-collision and SameSite interplay to verify.
6. **AOT / trimming.** OpenIddict and EF Core are not fully Native-AOT friendly today; the "AOT-ready" aspiration from the v1 checklist is likely **out of reach** for the server package. Scope AOT only to the (hypothetical) validation-only edge package if pursued.
7. **Single signing key vs. tenant crypto-isolation.** §6.3 assumes one trust domain. If a future requirement demands per-tenant key isolation, OpenIddict's single-issuer model fights it — would need multiple OpenIddict server instances or a custom key-selection handler. Flagged, not solved.
8. **Migration of live sessions.** v1 issues bearer tokens via `AddBearerToken`; v2 issues OpenIddict reference tokens. There is no in-place token translation — cutover requires forcing re-authentication (acceptable, but must be sequenced with the ADR 0001 data migration).

---

## 9. Summary table (for side-by-side comparison)

| Dimension | This sketch's stance |
|---|---|
| Package count | 5 src packages; `Idmt.Server` is the main one |
| OpenIddict location | leaf (`Idmt.Server` only), wrapped by `IdmtServerBuilder` facade + raw escape hatch |
| Entry point | `AddIdmt<TDb>()` → fluent `IIdmtBuilder` (no positional-delegate soup) |
| Access tokens | reference/opaque by default → instant revocation |
| Sys-support | RFC 8693 token exchange, `act` claim, mandatory audit, no refresh |
| Endpoint scaffolding | `MapIdmtTenantApi` / `MapIdmtSysAdminApi` returning pre-authorized `RouteGroupBuilder`s |
| v1 tenant-token middleware | replaced by `RequireTenantMember` authorization handler |
| Biggest risk | reference-token read amplification + cross-instance revocation backplane |
| Distinctive bet | "own the policy, rent the protocol"; claims projection is the one piece of IDMT secret sauce |
```
