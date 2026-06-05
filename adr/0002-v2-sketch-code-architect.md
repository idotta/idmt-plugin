# ADR 0002 — IDMT v2 Architecture Sketch: OpenIddict-Based Multi-Tenant Authorization Layer

- **Status:** Draft / Design Sketch
- **Date:** 2026-06-04
- **Author:** @idotta (architecture sketch)
- **Scope:** Greenfield v2 rewrite target architecture — design artifact only, no implementation
- **Supersedes:** v1 hand-rolled bearer token machinery (BearerToken middleware, TokenRevocationService, RefreshToken slice, Login.TokenLoginHandler, ValidateBearerTokenTenantMiddleware)

---

## 0. Purpose and Scope

This document sketches the concrete project layout, public API, slice shapes, and migration map for a v2 rewrite of IDMT. It is grounded in the v1 source code read directly from `Idmt.Plugin/` and `tests/`. The target architecture replaces hand-rolled OAuth2 token machinery with **OpenIddict** while keeping every concept that is genuinely IDMT's: canonical `IdmtUser`, `TenantAccess`, `SysRole`, Finbuckle tenant resolution, vertical-slice features, ErrorOr, FluentValidation, and the `AddIdmt<TDbContext>()` / `UseIdmt()` entry-point pattern.

Three architects are producing parallel sketches; this sketch is intended for side-by-side comparison. Section numbers match the requested output format.

---

## 1. Migration Map: v1 → v2

Every v1 file is mapped to one of three fates: **DELETED** (OpenIddict owns the concern), **KEPT** (unchanged or trivially adapted), **RESHAPED** (substantial rewrite into a different abstraction).

### 1.1 Auth Features (`Idmt.Plugin/Features/Auth/`)

| v1 File | Fate | Reason / v2 equivalent |
|---|---|---|
| `Login.cs` — `LoginHandler` (cookie sign-in) | **RESHAPED** → `Features/Auth/Authorize.cs` | Becomes the interactive OIDC `/connect/authorize` handler; session-cookie issuance delegates to OpenIddict's `SignInManager`-integrated flow. Logic: resolve tenant, validate `TenantAccess`, then `SignInAsync` against the OpenIddict Authorization endpoint. |
| `Login.cs` — `TokenLoginHandler` (bearer token) | **DELETED** — OpenIddict owns it | `/connect/token` with `password` grant or `authorization_code`. The hand-rolled `BearerTokenProtector.Protect(authTicket)` pattern is replaced entirely. |
| `Login.cs` — `AccessTokenResponse` record | **DELETED** | OpenIddict returns RFC 6749 JSON (`access_token`, `token_type`, `expires_in`, `refresh_token`). |
| `RefreshToken.cs` | **DELETED** | OpenIddict `/connect/token` with `refresh_token` grant owns refresh rotation. `RefreshTokenHandler`, `RefreshTokenProtector`, revocation check in handler — all gone. |
| `Logout.cs` | **RESHAPED** → `Features/Auth/Revoke.cs` | Wraps OpenIddict `/connect/revocation` (RFC 7009). Cookie sign-out still calls `SignInManager.SignOutAsync`. `ITokenRevocationService.RevokeUserTokensAsync` is replaced by OpenIddict's built-in revocation. |
| `ConfirmEmail.cs` | **KEPT** | ASP.NET Core Identity token, not an OAuth2 concern. Minor reshape: endpoint names and Base64URL decode stay identical. |
| `ConfirmEmailChange.cs` | **KEPT** | Same — Identity-issued `ChangeEmail` token. `PendingEmail` staging flow unchanged. |
| `ResendConfirmationEmail.cs` | **KEPT** | Pure Identity concern; no token infrastructure changes. |
| `ForgotPassword.cs` | **KEPT** | Pure Identity concern. |
| `ResetPassword.cs` | **KEPT** | Pure Identity concern. |
| `DiscoverTenants.cs` | **KEPT** | Pre-login tenant discovery via `TenantAccess` join. No token machinery involved. |

### 1.2 Manage Features (`Idmt.Plugin/Features/Manage/`)

| v1 File | Fate | v2 notes |
|---|---|---|
| `RegisterUser.cs` | **KEPT** | Minor update: token grant for email link uses OpenIddict's link generator convention rather than `userManager.GeneratePasswordResetTokenAsync` sent directly. Core logic (transaction, TenantAccess row creation) unchanged. |
| `UnregisterUser.cs` | **KEPT** | Hard-delete path unchanged. Add: call OpenIddict token store to revoke all tokens for the deleted user's `sub` claim. |
| `UpdateUser.cs` | **KEPT** | `IsActive` flag toggle unchanged. |
| `GetUserInfo.cs` | **KEPT** | `GetRolesAsync` + `SysRole` claim read unchanged. |
| `UpdateUserInfo.cs` | **KEPT** | OOB email change flow (`PendingEmail`, `GenerateChangeEmailTokenAsync`) unchanged. Password change: after `ChangePasswordAsync`, call OpenIddict token store to revoke existing tokens for user (replaces `tokenRevocationService.RevokeUserTokensAsync`). |

### 1.3 Admin Features (`Idmt.Plugin/Features/Admin/`)

| v1 File | Fate | v2 notes |
|---|---|---|
| `CreateTenant.cs` | **KEPT** | Role seeding + invoker `TenantAccess` bootstrap in `BootstrapTenantAsync` unchanged. |
| `DeleteTenant.cs` | **KEPT** | Soft-delete plus: revoke all OpenIddict tokens whose `tenant` claim equals the deleted tenant identifier. |
| `GrantTenantAccess.cs` | **KEPT** | `TenantAccess` row write unchanged. |
| `RevokeTenantAccess.cs` | **RESHAPED** | `TenantAccess.IsActive = false` stays. Replace `tokenRevocationService.RevokeUserTokensAsync(userId, tenantId)` with an OpenIddict-native call: enumerate and revoke all `OpenIddictToken` rows where `Subject == userId && [tenant claim] == tenantId`. |
| `GetAllTenants.cs` | **KEPT** | Paginated query unchanged. |
| `GetUserTenants.cs` | **KEPT** | `TenantAccess` join unchanged. |
| `AdminModels.cs` (`TenantInfoResponse`, `PaginatedResponse`) | **KEPT** | Shared response records unchanged. |
| NEW: `SupportTenant.cs` | **NEW** | Token-exchange "sys-support a tenant" slice (RFC 8693). SysSupport/SysAdmin trades their token for a tenant-scoped, time-bound, audited support token via OpenIddict token exchange. Replaces the old shadow-row approach. See Section 5. |

### 1.4 Services

| v1 File | Fate | v2 notes |
|---|---|---|
| `ICurrentUserService.cs` / `CurrentUserService.cs` | **KEPT** | `TenantId`, `TenantIdentifier` now read from OpenIddict's JWT standard `tenant` claim rather than the Finbuckle-strategy claim. Interface unchanged. |
| `ITenantAccessService.cs` / `TenantAccessService.cs` | **KEPT** | `CanAccessTenantAsync`, `CanAssignRole`, `CanManageUser` — all unchanged. |
| `ITenantOperationService.cs` / `TenantOperationService.cs` | **KEPT** | Inner-scope DI pattern unchanged. |
| `ITokenRevocationService.cs` / `TokenRevocationService.cs` | **DELETED** | OpenIddict's `IOpenIddictTokenManager` is the revocation store. `RevokedToken` EF entity deleted. `TokenRevocationCleanupService` deleted (OpenIddict has its own pruning via `OpenIddictEntityFrameworkCoreCleanupService` / `IOpenIddictTokenManager.PruneAsync`). |
| `IdmtUserClaimsPrincipalFactory.cs` | **RESHAPED** | Still extends `UserClaimsPrincipalFactory<IdmtUser, IdmtRole>`. Now also emits the OIDC `sub` claim (= `user.Id`), `iss`, and the tenant claim as `tenant` (standard claim name, not Finbuckle strategy-driven). The factory is the single claim emission point consumed by OpenIddict's authorization endpoint. |
| `IdmtLinkGenerator.cs` / `IIdmtLinkGenerator.cs` | **KEPT** | Link generation for email confirmation / password reset is unchanged. |
| `IdmtEmailSender.cs` / `IdmtEmailSenderStartupCheck.cs` | **KEPT** | Email contract unchanged. |
| `PiiMasker.cs` | **KEPT** | Structured logging utility unchanged. |
| `Base64Service.cs` | **KEPT** | Token decode utility unchanged. |
| `TenantOperationService.cs` | **KEPT** | ExecuteInTenantScopeAsync pattern unchanged. |

### 1.5 Middleware

| v1 File | Fate | v2 notes |
|---|---|---|
| `ValidateBearerTokenTenantMiddleware.cs` | **DELETED** | Replaced by an OpenIddict **validation handler** (a typed `IOpenIddictValidationHandler<ProcessAuthenticationContext>`) that enforces `token.Claims["tenant"] == currentTenant.Identifier`. The middleware approach is replaced by the OpenIddict pipeline hook; the logic (fail-closed, 401/403 ProblemDetails) stays identical but sits inside `Features/Auth/TenantValidationHandler.cs`. |
| `CurrentUserMiddleware.cs` | **KEPT** | Populates `ICurrentUserService` from `HttpContext.User` after OpenIddict validation runs. |

### 1.6 Models

| v1 File | Fate | v2 notes |
|---|---|---|
| `IdmtUser.cs` | **KEPT** | `SysRole`, `PendingEmail`, `IsActive`, `LastLoginAt`, `Guid.CreateVersion7()` unchanged. |
| `IdmtRole.cs` | **KEPT** | Per-tenant `IdmtRole`, `IdmtDefaultRoleTypes` unchanged. |
| `SysRoleKind.cs` | **KEPT** | Enum unchanged. |
| `TenantAccess.cs` | **KEPT** | `IsActive`, `ExpiresAt` unchanged. |
| `IdmtTenantInfo.cs` | **KEPT** | `IsActive`, `LoginPath`, `LogoutPath` unchanged. |
| `IdmtAuditLog.cs` | **KEPT** | Audit interceptor unchanged. |
| `IAuditable.cs` | **KEPT** | Interface unchanged. |
| `RevokedToken.cs` | **DELETED** | OpenIddict token store replaces this. |

### 1.7 Persistence

| v1 File | Fate | v2 notes |
|---|---|---|
| `IdmtDbContext.cs` | **RESHAPED** | Inherits `OpenIddictDbContext<...>` (or uses `UseOpenIddict()` extension on the existing `MultiTenantIdentityDbContext` base) to add the four OpenIddict entity sets. `RevokedTokens` DbSet removed. `DateTimeOffset` converter and audit interceptor stay. |
| `IdmtTenantStoreDbContext.cs` | **KEPT** | Finbuckle EFCore store unchanged. |

### 1.8 Configuration

| v1 File | Fate | v2 notes |
|---|---|---|
| `IdmtOptions.cs` — `BearerOptions` class | **RESHAPED** | Replaces `BearerTokenExpiration` / `RefreshTokenExpiration` with OpenIddict equivalents (`AccessTokenLifetime`, `RefreshTokenLifetime`). The `QueryTokenPrefix` SignalR hook moves to an OpenIddict validation event. |
| `IdmtOptions.cs` — everything else | **KEPT** | `ApplicationOptions`, `MultiTenantOptions`, `DatabaseOptions`, `RateLimitingOptions`, `IdmtPasswordOptions`, `IdmtAuthOptions` policy constants unchanged. |
| `IdmtAuthOptions` constants | **KEPT** | `CookieOrBearerScheme`, `RequireSysAdminPolicy`, `RequireSysUserPolicy`, `RequireTenantManagerPolicy`, `CookieOnlyPolicy`, `BearerOnlyPolicy` all unchanged. Authorization policies are reconstructed with OpenIddict's Bearer scheme. |
| `IdmtOptionsValidator.cs` | **KEPT** | Validation rules unchanged; drop validation of bearer token expiry config when `BearerOptions` is refactored. |
| `IdmtEndpointNames.cs` | **KEPT** + extended | Add `ConnectAuthorize`, `ConnectToken`, `ConnectRevoke`, `ConnectUserInfo`. |

### 1.9 Migration Harness

| v1 File | Fate |
|---|---|
| `Migration/CanonicalIdentityDataMigrator.cs` | **KEPT** — v1→v2 canonical migrator reusable as v1.x→v2 pre-flight step. |
| `Migration/MigrationServiceCollectionExtensions.cs` | **KEPT** |
| `Migration/MigrationCurrentUserService.cs` | **KEPT** |

---

## 2. Solution & Project Layout

```
Idmt.slnx
│
├── src/
│   ├── Idmt.Plugin/                     # Main NuGet package (Idmt.Plugin)
│   │   ├── Configuration/
│   │   │   ├── IdmtOptions.cs           # KEPT + reshaped BearerOptions
│   │   │   ├── IdmtOptionsValidator.cs  # KEPT
│   │   │   └── IdmtEndpointNames.cs     # KEPT + extended
│   │   │
│   │   ├── Constants/
│   │   │   ├── IdmtClaimTypes.cs        # KEPT + add "tenant", "sub"
│   │   │   └── AuditAction.cs           # KEPT
│   │   │
│   │   ├── Errors/
│   │   │   └── IdmtErrors.cs            # KEPT + add Token.ExchangeFailed
│   │   │
│   │   ├── Extensions/
│   │   │   ├── ServiceCollectionExtensions.cs    # RESHAPED — add OpenIddict wiring
│   │   │   └── ApplicationBuilderExtensions.cs   # RESHAPED — add OpenIddict endpoints
│   │   │
│   │   ├── Features/
│   │   │   ├── AuthEndpoints.cs         # RESHAPED — remove /login/token, /refresh; add OIDC endpoint registrations
│   │   │   ├── ManageEndpoints.cs       # KEPT
│   │   │   ├── AdminEndpoints.cs        # KEPT + add SupportTenant
│   │   │   │
│   │   │   ├── Auth/
│   │   │   │   ├── Authorize.cs         # NEW — interactive OIDC authorize flow (wraps /connect/authorize)
│   │   │   │   ├── ConfirmEmail.cs      # KEPT
│   │   │   │   ├── ConfirmEmailChange.cs # KEPT
│   │   │   │   ├── DiscoverTenants.cs   # KEPT
│   │   │   │   ├── ForgotPassword.cs    # KEPT
│   │   │   │   ├── ResendConfirmationEmail.cs  # KEPT
│   │   │   │   ├── ResetPassword.cs     # KEPT
│   │   │   │   ├── Revoke.cs            # NEW (replaces Logout.cs token revocation)
│   │   │   │   ├── TenantValidationHandler.cs   # NEW (replaces ValidateBearerTokenTenantMiddleware)
│   │   │   │   └── UserInfo.cs          # NEW — /connect/userinfo slice
│   │   │   │
│   │   │   ├── Admin/
│   │   │   │   ├── AdminModels.cs       # KEPT
│   │   │   │   ├── CreateTenant.cs      # KEPT
│   │   │   │   ├── DeleteTenant.cs      # KEPT
│   │   │   │   ├── GetAllTenants.cs     # KEPT
│   │   │   │   ├── GetUserTenants.cs    # KEPT
│   │   │   │   ├── GrantTenantAccess.cs # KEPT
│   │   │   │   ├── RevokeTenantAccess.cs # RESHAPED
│   │   │   │   └── SupportTenant.cs     # NEW — token-exchange slice (RFC 8693)
│   │   │   │
│   │   │   ├── Manage/
│   │   │   │   ├── GetUserInfo.cs       # KEPT
│   │   │   │   ├── RegisterUser.cs      # KEPT
│   │   │   │   ├── UnregisterUser.cs    # KEPT
│   │   │   │   ├── UpdateUser.cs        # KEPT
│   │   │   │   └── UpdateUserInfo.cs    # KEPT
│   │   │   │
│   │   │   └── Health/
│   │   │       └── BasicHealthCheck.cs  # KEPT
│   │   │
│   │   ├── Middleware/
│   │   │   └── CurrentUserMiddleware.cs # KEPT (ValidateBearerTokenTenantMiddleware DELETED)
│   │   │
│   │   ├── Migration/
│   │   │   ├── CanonicalIdentityDataMigrator.cs  # KEPT
│   │   │   ├── MigrationCurrentUserService.cs    # KEPT
│   │   │   └── MigrationServiceCollectionExtensions.cs  # KEPT
│   │   │
│   │   ├── Models/
│   │   │   ├── IAuditable.cs            # KEPT
│   │   │   ├── IdmtAuditLog.cs          # KEPT
│   │   │   ├── IdmtRole.cs              # KEPT
│   │   │   ├── IdmtTenantInfo.cs        # KEPT
│   │   │   ├── IdmtUser.cs              # KEPT
│   │   │   ├── SysRoleKind.cs           # KEPT
│   │   │   └── TenantAccess.cs          # KEPT
│   │   │   # RevokedToken.cs            DELETED
│   │   │
│   │   ├── Persistence/
│   │   │   ├── IdmtDbContext.cs         # RESHAPED — add OpenIddict entity sets, remove RevokedTokens
│   │   │   └── IdmtTenantStoreDbContext.cs  # KEPT
│   │   │
│   │   ├── Services/
│   │   │   ├── Base64Service.cs         # KEPT
│   │   │   ├── CurrentUserService.cs    # KEPT
│   │   │   ├── ICurrentUserService.cs   # KEPT
│   │   │   ├── IdmtEmailSender.cs       # KEPT
│   │   │   ├── IdmtEmailSenderStartupCheck.cs  # KEPT
│   │   │   ├── IdmtLinkGenerator.cs     # KEPT
│   │   │   ├── IdmtUserClaimsPrincipalFactory.cs  # RESHAPED
│   │   │   ├── ITenantAccessService.cs  # KEPT
│   │   │   ├── ITenantOperationService.cs  # KEPT
│   │   │   ├── PiiMasker.cs             # KEPT
│   │   │   ├── TenantAccessService.cs   # KEPT
│   │   │   └── TenantOperationService.cs  # KEPT
│   │   │   # ITokenRevocationService.cs  DELETED
│   │   │   # TokenRevocationService.cs   DELETED
│   │   │   # TokenRevocationCleanupService.cs DELETED
│   │   │
│   │   └── Validation/
│   │       ├── ValidationHelper.cs      # KEPT
│   │       ├── Validators.cs            # KEPT
│   │       └── [feature validators]     # KEPT
│   │
│   └── Idmt.Plugin.Abstractions/        # OPTIONAL second package
│       # (future: thin interfaces-only package for consumers
│        # who want compile-time types without pulling full plugin)
│       # Not required for v2.0.
│
├── samples/
│   └── Idmt.BasicSample/               # Updated sample using OpenIddict PKCE flow
│
└── tests/
    ├── Idmt.UnitTests/                  # KEPT structure — see Section 6
    └── Idmt.BasicSample.Tests/          # KEPT structure — see Section 6
```

**NuGet package boundaries:** v2 ships as a single `Idmt.Plugin` package. NuGet dependencies gain:
- `OpenIddict.AspNetCore` (token server + validation)
- `OpenIddict.EntityFrameworkCore` (token / application / authorization / scope stores)

Finbuckle, ASP.NET Core Identity, ErrorOr, FluentValidation, EntityFrameworkCore — all unchanged.

---

## 3. Public API Sketch

### 3.1 `AddIdmt<TDbContext>()` Entry Point

The signature is deliberately kept identical to v1 to minimize consumer migration surface.

```csharp
// Idmt.Plugin/Extensions/ServiceCollectionExtensions.cs

public delegate void CustomizeAuthentication(AuthenticationBuilder authenticationBuilder);
public delegate void CustomizeAuthorization(AuthorizationBuilder authorizationBuilder);
// NEW in v2:
public delegate void CustomizeOpenIddict(OpenIddictBuilder openIddictBuilder);

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddIdmt<TDbContext>(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DbContextOptionsBuilder>? configureDb = null,
        Action<IdmtOptions>? configureOptions = null,
        CustomizeAuthentication? customizeAuthentication = null,
        CustomizeAuthorization? customizeAuthorization = null,
        CustomizeOpenIddict? customizeOpenIddict = null)       // NEW parameter
        where TDbContext : IdmtDbContext
    { ... }

    // Overload without TDbContext (default IdmtDbContext) — unchanged shape
    public static IServiceCollection AddIdmt(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DbContextOptionsBuilder>? configureDb = null,
        Action<IdmtOptions>? configureOptions = null,
        CustomizeAuthentication? customizeAuthentication = null,
        CustomizeAuthorization? customizeAuthorization = null,
        CustomizeOpenIddict? customizeOpenIddict = null)
    { ... }
}
```

Internal registration sequence (mirrors v1's numbered steps, new step 8a inserted):

```
1.  ConfigureIdmtOptions          // unchanged
2.  ConfigureDatabase<TDbContext> // + adds OpenIddict EF stores to DbContext
3.  ConfigureIdentity             // unchanged
4.  ConfigureAuthentication       // PolicyScheme: CookieOrBearer now forwards
                                  //   bearer to OpenIddict validation scheme
5.  ConfigureAuthorization        // policies unchanged
6.  ConfigureMultiTenant          // unchanged
7.  ConfigureOpenIddict           // NEW — registers AS + validation pipelines
8.  RegisterApplicationServices   // ITokenRevocationService removed
9.  RegisterFeatures              // remove Login.ITokenLoginHandler etc.
10. RegisterMiddleware             // remove ValidateBearerTokenTenantMiddleware
11. ConfigureRateLimiting         // unchanged
```

### 3.2 `ConfigureOpenIddict` (new internal method)

```csharp
private static void ConfigureOpenIddict(
    IServiceCollection services,
    IdmtOptions idmtOptions,
    Action<DbContextOptionsBuilder>? configureDb,
    CustomizeOpenIddict? customizeOpenIddict)
{
    var openIddictBuilder = services.AddOpenIddict()

        // Authorization server component
        .AddServer(options =>
        {
            // OAuth2 / OIDC endpoints
            options.SetAuthorizationEndpointUris("/connect/authorize")
                   .SetTokenEndpointUris("/connect/token")
                   .SetRevocationEndpointUris("/connect/revocation")
                   .SetUserinfoEndpointUris("/connect/userinfo")
                   .SetIntrospectionEndpointUris("/connect/introspect");

            // v2 locked decision: reference (opaque) access tokens for instant revocation.
            // Token payloads are stored server-side; clients receive an opaque handle.
            options.UseReferenceAccessTokens()
                   .UseReferenceRefreshTokens();

            // Supported grants
            options.AllowAuthorizationCodeFlow()
                   .AllowRefreshTokenFlow()
                   .AllowTokenExchangeFlow();    // RFC 8693 — for SupportTenant slice

            // Lifetimes mirror v1 IdmtOptions.Identity.Bearer defaults
            options.SetAccessTokenLifetime(idmtOptions.Identity.Bearer.BearerTokenExpiration)
                   .SetRefreshTokenLifetime(idmtOptions.Identity.Bearer.RefreshTokenExpiration);

            // Sign / encrypt with development keys in dev; consumer provides production keys
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();

            // ASP.NET Core integration
            options.UseAspNetCore()
                   .EnableAuthorizationEndpointPassthrough()
                   .EnableTokenEndpointPassthrough()
                   .EnableRevocationEndpointPassthrough()
                   .EnableUserinfoEndpointPassthrough();
        })

        // Validation component — validates reference tokens server-side
        .AddValidation(options =>
        {
            options.UseLocalServer();
            options.UseAspNetCore();

            // Tenant isolation enforcement hook
            options.AddEventHandler<ProcessAuthenticationContext>(
                builder => builder
                    .UseSingletonHandler<TenantValidationHandler>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 500));
        })

        // EF Core token / application / authorization / scope stores
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore()
                   .UseDbContext<IdmtDbContext>();
        });

    customizeOpenIddict?.Invoke(openIddictBuilder);
}
```

### 3.3 Updated `IdmtOptions` Shape

Only the `BearerOptions` class changes. All other option classes are byte-for-byte compatible with v1.

```csharp
// v2 BearerOptions — replaces v1 BearerOptions
// v1 BearerTokenExpiration → AccessTokenLifetime (same default: 60 min)
// v1 RefreshTokenExpiration → RefreshTokenLifetime (same default: 30 days)
public class BearerOptions
{
    public const string HeaderTokenPrefix = "Bearer";
    public const string QueryTokenPrefix = "access_token";   // SignalR/WebSocket — kept

    // Renamed from BearerTokenExpiration (value and default unchanged)
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);

    // Renamed from RefreshTokenExpiration (value and default unchanged)
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
}
```

### 3.4 Authentication Scheme Wiring

```csharp
// PolicyScheme — v2 forwards to OpenIddict validation scheme instead of
// IdentityConstants.BearerScheme. Cookie scheme unchanged.
authenticationBuilder.AddPolicyScheme(IdmtAuthOptions.CookieOrBearerScheme, "Cookie or Bearer",
    options =>
    {
        options.ForwardDefaultSelector = context =>
        {
            var authHeader = context.Request.Headers.Authorization.ToString();
            if (!string.IsNullOrEmpty(authHeader) &&
                authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            }
            return IdentityConstants.ApplicationScheme;
        };
    });
```

### 3.5 `UseIdmt()` / `MapIdmtEndpoints()` — Unchanged Shape

```csharp
// ApplicationBuilderExtensions.cs — consumer call site unchanged
app.UseIdmt();
app.MapIdmtEndpoints();

// Internally, MapIdmtEndpoints also maps OIDC endpoints:
endpoints.MapGroup(apiPrefix).MapAuthEndpoints();
// AuthEndpoints.cs adds:
//   auth.MapAuthorizeEndpoint();    → POST/GET /connect/authorize (passthrough)
//   auth.MapTokenEndpoint();        → POST /connect/token (passthrough)
//   auth.MapRevocationEndpoint();   → POST /connect/revocation
//   auth.MapUserInfoEndpoint();     → GET /connect/userinfo
//   [existing email/password/discover endpoints unchanged]
```

### 3.6 Authorization Policy Constants — Unchanged

```csharp
// IdmtAuthOptions constants — 100% backward compatible
public const string CookieOrBearerScheme = "CookieOrBearer";
public const string CookieOnlyPolicy     = "CookieOnly";
public const string BearerOnlyPolicy     = "BearerOnly";
public const string RequireSysAdminPolicy     = "RequireSysAdmin";
public const string RequireSysUserPolicy      = "RequireSysUser";
public const string RequireTenantManagerPolicy = "RequireTenantManager";
```

Policies are rebuilt in `ConfigureAuthorization` using `OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme` as the bearer scheme in place of `IdentityConstants.BearerScheme`.

---

## 4. Representative Vertical Slice: `SupportTenant.cs` (Token Exchange)

This is a new v2 Admin slice. It demonstrates how the v1 slice pattern is preserved exactly, with OpenIddict plumbing substituted for hand-rolled token work.

```csharp
// Idmt.Plugin/Features/Admin/SupportTenant.cs

using ErrorOr;
using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;

namespace Idmt.Plugin.Features.Admin;

public static class SupportTenant
{
    // --- Request / Response ---

    public sealed record SupportTenantRequest
    {
        /// <summary>
        /// The identifier of the tenant the sys-user wants to act as support in.
        /// </summary>
        public required string TenantIdentifier { get; init; }

        /// <summary>
        /// How long the support token should be valid. Capped by IdmtOptions.
        /// </summary>
        public TimeSpan? RequestedLifetime { get; init; }
    }

    public sealed record SupportTenantResponse
    {
        /// <summary>Opaque reference access token scoped to the target tenant.</summary>
        public required string AccessToken { get; init; }
        public required long ExpiresIn { get; init; }
        public required string TokenType { get; init; } = "Bearer";
        public required string TenantIdentifier { get; init; }
    }

    // --- Handler interface + implementation ---

    public interface ISupportTenantHandler
    {
        Task<ErrorOr<SupportTenantResponse>> HandleAsync(
            SupportTenantRequest request,
            ClaimsPrincipal invoker,
            CancellationToken cancellationToken = default);
    }

    internal sealed class SupportTenantHandler(
        IOpenIddictTokenManager tokenManager,
        IOpenIddictApplicationManager applicationManager,
        ITenantAccessService tenantAccessService,
        ICurrentUserService currentUserService,
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        IdmtDbContext dbContext,
        IOptions<IdmtOptions> idmtOptions,
        TimeProvider timeProvider,
        ILogger<SupportTenantHandler> logger) : ISupportTenantHandler
    {
        // Max lifetime for a support token — hard cap regardless of what caller requests.
        private static readonly TimeSpan MaxSupportTokenLifetime = TimeSpan.FromHours(4);

        public async Task<ErrorOr<SupportTenantResponse>> HandleAsync(
            SupportTenantRequest request,
            ClaimsPrincipal invoker,
            CancellationToken cancellationToken = default)
        {
            var invokerUserId = currentUserService.UserId;
            if (invokerUserId is null)
                return IdmtErrors.Auth.Unauthorized;

            // 1. Validate target tenant exists and is active.
            var targetTenant = await tenantStore.GetByIdentifierAsync(request.TenantIdentifier);
            if (targetTenant is null)
                return IdmtErrors.Tenant.NotFound;
            if (!targetTenant.IsActive)
                return IdmtErrors.Tenant.Inactive;

            // 2. Uniform TenantAccess gate — even SysAdmin must have an active row
            //    (locked decision #4 carries forward to v2).
            if (!await tenantAccessService.CanAccessTenantAsync(
                    invokerUserId.Value, targetTenant.Id!, cancellationToken))
                return IdmtErrors.Auth.Unauthorized;

            // 3. Build the support principal — tenant claim scoped to target tenant,
            //    SysRole forwarded, audit metadata embedded.
            var lifetime = request.RequestedLifetime.HasValue
                ? TimeSpan.FromTicks(Math.Min(request.RequestedLifetime.Value.Ticks, MaxSupportTokenLifetime.Ticks))
                : TimeSpan.FromHours(1);

            var now = timeProvider.GetUtcNow();

            var identity = new ClaimsIdentity(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                OpenIddictConstants.Claims.Name,
                OpenIddictConstants.Claims.Role);

            // sub = canonical invoker userId (not re-created; audit trail unbroken)
            identity.AddClaim(OpenIddictConstants.Claims.Subject, invokerUserId.Value.ToString());
            identity.AddClaim("tenant", targetTenant.Identifier!);
            identity.AddClaim("tenant_id", targetTenant.Id!);
            identity.AddClaim("support_session", "true");
            identity.AddClaim("support_invoker", invokerUserId.Value.ToString());

            // Forward SysRole so RequireSysUser / RequireSysAdmin policies pass in target tenant
            var sysRole = invoker.FindFirstValue(ClaimTypes.Role);
            if (!string.IsNullOrEmpty(sysRole))
                identity.AddClaim(ClaimTypes.Role, sysRole);

            // Destination: access token only (refresh not issued for support sessions)
            foreach (var claim in identity.Claims)
            {
                claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
            }

            var principal = new ClaimsPrincipal(identity);
            principal.SetAccessTokenLifetime(lifetime);
            principal.SetScopes(OpenIddictConstants.Scopes.OpenId, "idmt");

            // 4. Write an audit log entry before token creation.
            dbContext.AuditLogs.Add(new IdmtAuditLog
            {
                UserId = invokerUserId,
                TenantId = targetTenant.Id,
                Action = AuditAction.SupportSessionStarted.ToString(),
                Resource = nameof(TenantAccess),
                ResourceId = $"{invokerUserId}:{targetTenant.Id}",
                Success = true,
                Timestamp = now,
                IpAddress = currentUserService.IpAddress,
                UserAgent = currentUserService.UserAgent,
            });
            await dbContext.SaveChangesAsync(cancellationToken);

            // 5. Create the reference access token via OpenIddict token manager.
            //    The token descriptor follows the OpenIddict server-side store contract.
            var descriptor = new OpenIddictTokenDescriptor
            {
                Principal = principal,
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = invokerUserId.Value.ToString(),
                Type = OpenIddictConstants.TokenTypes.Bearer,
                ExpirationDate = now.Add(lifetime),
                CreationDate = now,
            };

            var token = await tokenManager.CreateAsync(descriptor, cancellationToken);
            // OpenIddict reference tokens: the opaque handle is the ReferenceId.
            var opaqueToken = await tokenManager.GetReferenceIdAsync(token!, cancellationToken)
                ?? throw new InvalidOperationException("OpenIddict did not produce a reference token handle.");

            return new SupportTenantResponse
            {
                AccessToken = opaqueToken,
                ExpiresIn = (long)lifetime.TotalSeconds,
                TokenType = "Bearer",
                TenantIdentifier = targetTenant.Identifier!,
            };
        }
    }

    // --- Validator (inline, consistent with v1 style) ---

    internal sealed class SupportTenantRequestValidator : AbstractValidator<SupportTenantRequest>
    {
        public SupportTenantRequestValidator()
        {
            RuleFor(x => x.TenantIdentifier)
                .NotEmpty()
                .Must(Validators.IsValidTenantIdentifier)
                .WithMessage("Tenant identifier must be lowercase alphanumeric, dashes, or underscores.");

            RuleFor(x => x.RequestedLifetime)
                .Must(lt => lt == null || lt > TimeSpan.Zero)
                .WithMessage("Requested lifetime must be positive.");
        }
    }

    // --- Endpoint mapper (static extension method, identical v1 pattern) ---

    public static RouteHandlerBuilder MapSupportTenantEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost(
            "/tenants/{tenantIdentifier}/support-session",
            async Task<Results<Ok<SupportTenantResponse>, UnauthorizedHttpResult, NotFound, ForbidHttpResult, ValidationProblem, ProblemHttpResult>> (
                string tenantIdentifier,
                [FromBody] SupportTenantRequest request,
                ClaimsPrincipal invoker,
                [FromServices] ISupportTenantHandler handler,
                [FromServices] IValidator<SupportTenantRequest> validator,
                HttpContext context) =>
            {
                // Bind route into request for unified validation
                var merged = request with { TenantIdentifier = tenantIdentifier };

                if (ValidationHelper.Validate(merged, validator) is { } validationErrors)
                    return TypedResults.ValidationProblem(validationErrors);

                var result = await handler.HandleAsync(merged, invoker,
                    cancellationToken: context.RequestAborted);

                if (result.IsError)
                {
                    return result.FirstError.Type switch
                    {
                        ErrorType.Unauthorized => TypedResults.Unauthorized(),
                        ErrorType.Forbidden    => TypedResults.Forbid(),
                        ErrorType.NotFound     => TypedResults.NotFound(),
                        ErrorType.Validation   => TypedResults.Problem(
                            result.FirstError.Description,
                            statusCode: StatusCodes.Status400BadRequest),
                        _ => TypedResults.Problem(
                            result.FirstError.Description,
                            statusCode: StatusCodes.Status500InternalServerError),
                    };
                }

                return TypedResults.Ok(result.Value);
            })
        .RequireAuthorization(IdmtAuthOptions.RequireSysUserPolicy)
        .WithSummary("Start support session in tenant")
        .WithDescription(
            "Issues a tenant-scoped, time-bound, audited access token for a SysAdmin or " +
            "SysSupport user to act within a specific tenant. Replaces the v1 shadow-row " +
            "GrantTenantAccess approach for sys-user cross-tenant operations. Implements " +
            "RFC 8693 token exchange semantics via OpenIddict. No refresh token is issued; " +
            "the support session is strictly time-bounded.");
    }
}
```

**Why this is the right shape:**
- Identical file structure to v1 `GrantTenantAccess.cs`: sealed Request/Response records, `IHandler` interface, `internal sealed` implementation, inline validator, static `Map*Endpoint` extension.
- `ErrorOr<T>` return on handler; `TypedResults` switch in endpoint — matches every existing v1 endpoint.
- `RequireAuthorization(RequireSysUserPolicy)` — consistent with v1's `RequireSysAdminPolicy` on admin endpoints.
- TenantAccess gate preserved (locked decision #4).
- Audit log written inside the handler before token creation, consistent with `SaveChangesAsync` in `IdmtDbContext.SaveChangesAsync` audit interceptor pattern.

---

## 5. Token-Exchange Sys-Support Flow and Reference-Token Revocation Wiring

### 5.1 Token-Exchange Sys-Support Flow

```
SysAdmin/SysSupport
  │
  │  POST /api/v1/admin/tenants/{tenantIdentifier}/support-session
  │  Authorization: Bearer <current-sys-token>
  │  Body: { "requestedLifetime": "01:00:00" }
  │
  ▼
[RequireAuthorization(RequireSysUserPolicy)]
  │  OpenIddict validation: unpack reference token → verify against token store
  │  TenantValidationHandler: token.Claims["tenant"] == currentTenant.Identifier
  │
  ▼
SupportTenantHandler
  │  1. Resolve invokerUserId from ICurrentUserService
  │  2. Resolve targetTenant from Finbuckle IMultiTenantStore
  │  3. CanAccessTenantAsync(invokerUserId, targetTenant.Id) — TenantAccess gate
  │  4. Build ClaimsPrincipal: sub=invokerUserId, tenant=targetTenant.Identifier,
  │     support_session=true, support_invoker=invokerUserId, SysRole forwarded
  │  5. Write AuditLog (SupportSessionStarted) via DbContext.SaveChangesAsync
  │  6. IOpenIddictTokenManager.CreateAsync(descriptor) → opaque reference handle
  │
  ▼
Response: 200 OK { accessToken: "<opaque>", expiresIn: 3600, tenantIdentifier: "acme" }

Consumer stores token, uses it for next request to acme-scoped endpoints:

  POST /api/v1/manage/users  (acme tenant)
  Authorization: Bearer <support-token>
  __tenant__: acme

  ▼
OpenIddict validation: dereference opaque handle → server-side token row
  TenantValidationHandler: token.Claims["tenant"] == "acme" ✓
  CurrentUserMiddleware: populates ICurrentUserService with invoker identity + tenant=acme
  Handler proceeds normally under acme tenant context.
```

**Revocation of support token:** Call `POST /connect/revocation` with the opaque token. OpenIddict marks the token row `Status = Revoked`. On next use the validation pipeline rejects it with 401. No background cleanup table needed — OpenIddict's `IOpenIddictTokenManager.PruneAsync` removes expired/revoked rows.

**Explicit session end (admin revokes support access):**
`RevokeTenantAccess` handler (`DELETE /admin/users/{userId}/tenants/{tenantIdentifier}`) is reshaped to additionally call:
```csharp
// enumerate and revoke all valid tokens for this subject + tenant combination
await foreach (var token in tokenManager.FindBySubjectAsync(userId.ToString(), cancellationToken))
{
    var tenantClaim = await tokenManager.GetClaimValueAsync(token, "tenant", cancellationToken);
    if (tenantClaim == targetTenant.Identifier)
        await tokenManager.TryRevokeAsync(token, cancellationToken);
}
```

### 5.2 Reference-Token Revocation Wiring

OpenIddict **reference tokens** are the v2 revocation mechanism. The opaque string the client holds is a `ReferenceId`. Every API call:

1. OpenIddict validation middleware receives `Authorization: Bearer <opaque>`.
2. Calls `IOpenIddictTokenManager.FindByReferenceIdAsync(opaque)` — single DB lookup.
3. Checks `token.Status == Valid` and `token.ExpirationDate > now`.
4. Rehydrates the `ClaimsPrincipal` from the stored token payload.
5. `TenantValidationHandler` then cross-checks the `tenant` claim.

Instant revocation events that set `Status = Revoked` on the token row:
- `POST /connect/revocation` (explicit logout or client-side token discard)
- `RevokeTenantAccess` handler (admin removes access)
- `UpdateUserInfo` handler after password/username change (revoke all tokens for user + tenant)
- `UnregisterUser` handler (revoke all tokens for deleted user)
- `DeleteTenant` handler (revoke all tokens with `tenant` = deleted identifier)

Cleanup: `IOpenIddictTokenManager.PruneAsync` (called periodically via a hosted service registered by `AddOpenIddict()`) removes rows where `ExpirationDate < now || Status == Revoked`. No custom `TokenRevocationCleanupService` needed.

### 5.3 `TenantValidationHandler` (Replaces `ValidateBearerTokenTenantMiddleware`)

```csharp
// Idmt.Plugin/Features/Auth/TenantValidationHandler.cs

internal sealed class TenantValidationHandler(
    IMultiTenantContextAccessor tenantContextAccessor,
    ILogger<TenantValidationHandler> logger)
    : IOpenIddictValidationHandler<ProcessAuthenticationContext>
{
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
        = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseSingletonHandler<TenantValidationHandler>()
            .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 500)
            .Build();

    public ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        var principal = context.Principal;
        if (principal is null) return default;

        var currentTenant = tenantContextAccessor.MultiTenantContext?.TenantInfo;
        if (currentTenant is null)
        {
            logger.LogWarning("Bearer token used but no tenant context resolved. Rejecting.");
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidToken,
                description: "No tenant context could be resolved for this request.");
            return default;
        }

        var tokenTenantClaim = principal.FindFirstValue("tenant");
        if (string.IsNullOrEmpty(tokenTenantClaim))
        {
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidToken,
                description: "The token does not contain a required tenant claim.");
            return default;
        }

        if (!tokenTenantClaim.Equals(currentTenant.Identifier, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Token tenant {TokenTenant} != request tenant {RequestTenant}. Rejecting.",
                tokenTenantClaim, currentTenant.Identifier);
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidToken,
                description: "The token was not issued for the requested tenant.");
            return default;
        }

        return default;
    }
}
```

---

## 6. Test Layout

### 6.1 `tests/Idmt.UnitTests/` — which v1 tests survive

```
tests/Idmt.UnitTests/
├── Configuration/
│   ├── IdmtOptionsValidatorTests.cs          KEPT (no changes needed)
│   └── RateLimitingOptionsTests.cs           KEPT
│
├── Features/
│   ├── Auth/
│   │   ├── ConfirmEmailHandlerTests.cs       KEPT
│   │   ├── ConfirmEmailChangeHandlerTests.cs KEPT
│   │   ├── DiscoverTenantsHandlerTests.cs    KEPT
│   │   ├── ForgotPasswordHandlerTests.cs     KEPT
│   │   ├── LoginHandlerTests.cs              RESHAPED → AuthorizeHandlerTests.cs
│   │   │   (cookie sign-in path refactored to OpenIddict authorize flow)
│   │   ├── LogoutHandlerTests.cs             RESHAPED → RevokeHandlerTests.cs
│   │   │   (verify OpenIddict token manager revoke is called)
│   │   ├── RefreshTokenHandlerTests.cs       DELETED
│   │   │   (OpenIddict owns refresh; no custom handler to test)
│   │   ├── ResendConfirmationEmailHandlerTests.cs KEPT
│   │   ├── ResetPasswordHandlerTests.cs      KEPT
│   │   ├── TokenLoginHandlerTests.cs         DELETED
│   │   │   (OpenIddict /connect/token tested via integration)
│   │   └── NEW: SupportTenantHandlerTests.cs NEW
│   │       (mock IOpenIddictTokenManager, verify TenantAccess gate,
│   │        verify audit log row, verify support_session claim on principal)
│   │
│   ├── Admin/
│   │   ├── CreateTenantHandlerTests.cs       KEPT
│   │   ├── DeleteTenantHandlerTests.cs       KEPT (add: verify token revoke called)
│   │   ├── GetAllTenantsHandlerTests.cs      KEPT
│   │   ├── GetUserTenantsHandlerTests.cs     KEPT
│   │   ├── GrantTenantAccessHandlerTests.cs  KEPT
│   │   └── RevokeTenantAccessHandlerTests.cs RESHAPED
│   │       (verify IOpenIddictTokenManager.TryRevokeAsync called, not old ITokenRevocationService)
│   │
│   ├── Manage/
│   │   ├── GetUserInfoHandlerTests.cs        KEPT
│   │   ├── RegisterHandlerTests.cs           KEPT
│   │   ├── UnregisterHandlerTests.cs         KEPT (add: verify token revoke on delete)
│   │   ├── UpdateUserHandlerTests.cs         KEPT
│   │   └── UpdateUserInfoHandlerTests.cs     RESHAPED
│   │       (verify IOpenIddictTokenManager.FindBySubjectAsync + TryRevokeAsync
│   │        called on credential change, not old ITokenRevocationService)
│   │
│   └── Health/
│       └── BasicHealthCheckTests.cs          KEPT
│
├── Middleware/
│   ├── CurrentUserMiddlewareTests.cs         KEPT
│   └── ValidateBearerTokenTenantMiddlewareTests.cs  DELETED
│       (replaced by)
│   └── NEW: TenantValidationHandlerTests.cs  NEW
│       (unit test the OpenIddict validation handler in isolation with mocked
│        IMultiTenantContextAccessor; assert Reject() called for wrong tenant)
│
├── Models/
│   ├── IdmtTenantInfoTests.cs                KEPT
│   ├── IdmtUserTests.cs                      KEPT
│   └── SysRoleKindTests.cs                   KEPT
│
├── Persistence/
│   └── IdmtDbContextTests.cs                 RESHAPED
│       (remove RevokedTokens tests; add OpenIddict entity set presence check)
│
├── Services/
│   ├── CoreServicesTests.cs                  KEPT
│   ├── IdmtLinkGeneratorTests.cs             KEPT
│   ├── IdmtUserClaimsPrincipalFactoryTests.cs RESHAPED
│   │   (verify "tenant" claim, "sub" = userId, SysRole forwarded;
│   │    remove strategy-option-keyed claim key test)
│   ├── TenantAccessServiceTests.cs           KEPT
│   ├── TenantOperationServiceTests.cs        KEPT
│   ├── TokenRevocationCleanupServiceTests.cs DELETED
│   └── TokenRevocationServiceTests.cs        DELETED
│
├── Migration/
│   └── CanonicalIdentityDataMigratorTests.cs KEPT
│
└── Validation/
    ├── FluentValidatorTests.cs               KEPT
    └── ValidatorsTests.cs                    KEPT
```

### 6.2 `tests/Idmt.BasicSample.Tests/` — which integration tests survive

```
tests/Idmt.BasicSample.Tests/
├── IdmtApiFactory.cs           RESHAPED
│   (replace AddBearerToken with AddOpenIddict; add OpenIddict OIDC client in factory;
│    CreateAuthenticatedClientAsync calls /connect/token instead of /auth/token;
│    mock IEmailSender unchanged)
│
├── BaseIntegrationTest.cs      RESHAPED
│   (CreateAuthenticatedClientAsync: POST /connect/token with grant_type=password
│    or authorization_code; ExtractAccessTokenAsync reads standard OIDC JSON response)
│
├── AuthIntegrationTests.cs     RESHAPED
│   (remove /auth/token tests; add /connect/token happy + error paths;
│    add /connect/revocation test; add invalid-tenant-in-token 401 test)
│
├── ManageIntegrationTests.cs   KEPT (endpoints unchanged)
│
├── MultiTenancyIntegrationTests.cs  RESHAPED
│   (tenant isolation test uses reference tokens; cross-tenant-token rejection
│    test exercises TenantValidationHandler path)
│
├── Admin/
│   ├── CreateTenantInvokerAccessTests.cs    KEPT
│   ├── GrantTenantAccessIntegrationTests.cs KEPT
│   ├── RevokeTenantAccessIntegrationTests.cs RESHAPED
│   │   (assert token is immediately invalid after revoke, not just DB-flagged)
│   └── NEW: SupportTenantIntegrationTests.cs NEW
│       Scenario tests:
│       - SysAdmin can obtain support token for tenant they have TenantAccess to
│       - Support token works for tenant-scoped endpoints
│       - Support token rejected for different tenant (TenantValidationHandler)
│       - Support token is revoked when RevokeTenantAccess is called
│       - TenantAdmin cannot call /support-session (403)
│       - Support token has no refresh token in response
│       - Expired support token is rejected
│
├── Auth/
│   ├── ConfirmEmailChangeIntegrationTests.cs  KEPT
│   └── NEW: TokenExchangeIntegrationTests.cs  NEW
│       (end-to-end: login → get sys token → exchange for tenant support token →
│        use support token → logout / revoke)
│
├── Migration/
│   └── MigrationApplyTests.cs               KEPT
│
└── HttpResponseExtensions.cs               KEPT
```

### 6.3 New Scenario Tests Required for v2

Scenarios not covered by any v1 test:

1. **Reference token instant revocation**: mint a token, revoke via `/connect/revocation`, assert next use returns 401 (not 403 — the token is invalid, not forbidden).
2. **Support session audit trail**: after `POST /support-session`, verify `IdmtAuditLog` contains a `SupportSessionStarted` row with correct `TenantId`, `UserId`, `IpAddress`.
3. **Support token lifetime cap**: request `requestedLifetime: "8:00:00"` (8 hours > 4-hour cap), assert issued token expires in ≤ 4 hours.
4. **Cross-tenant token rejection via TenantValidationHandler**: issue a valid token for tenant A, use it against tenant B endpoint (different `__tenant__` header), assert 401 with body `"The token was not issued for the requested tenant."`.
5. **TenantAccess gate on support session**: SysAdmin without a `TenantAccess` row for the target tenant gets 401 (not 403), consistent with locked decision #4.
6. **OpenIddict token pruning hook**: confirm that after `DeleteTenant`, all tokens for that tenant's `tenant` claim are marked revoked (unit test mocking `IOpenIddictTokenManager`).
7. **SignalR/WebSocket opaque token via query string**: `GET /hubs/...?access_token=<opaque>` is validated by OpenIddict validation with `QueryTokenPrefix` hook.

---

## 7. Open Questions and Risks

### 7.1 OpenIddict Integration Complexity

**Risk:** OpenIddict's authorization server pipeline (passthrough endpoints, `IOpenIddictApplicationManager` client registration, scope definitions) adds significant startup wiring that v1 did not have. The library must either auto-register a default "idmt" client application at startup (similar to how v1 auto-seeds the default tenant) or document the consumer's responsibility clearly.

**Proposed resolution:** `AddIdmt` auto-seeds an internal OpenIddict application registration for the "resource server" use case (opaque tokens, no PKCE) via `IHostedService`. A `CustomizeOpenIddict` delegate allows consumers to override or add additional application registrations for their own clients (e.g., a SPA that needs PKCE). Document that calling `services.AddOpenIddict()` independently and then `AddIdmt` will cause conflicts; `AddIdmt` must own the OpenIddict registration.

### 7.2 `password` Grant Deprecation in OAuth 2.1

**Risk:** OAuth 2.1 (draft) removes the `password` grant. `BaseIntegrationTest.CreateAuthenticatedClientAsync` currently posts credentials directly to `/connect/token`. Integration tests will break if/when OpenIddict 5.x drops `password` grant support.

**Proposed resolution:** Integration tests use the `authorization_code` flow with PKCE and a test-only in-process redirect handler, or OpenIddict's test-mode `AllowNone` grant for unit scenarios. Flag the `password` grant as test-only, not surfaced in production configuration. Alternatively, keep the interactive login slice (`Authorize.cs`) as a custom credential-exchange endpoint that issues an auth code redeemable at `/connect/token`, avoiding `password` grant entirely.

### 7.3 Cookie + OpenIddict Coexistence

**Risk:** The v1 `Login.LoginHandler` issues a cookie via `SignInManager.Context.SignInAsync` directly. In v2 the OIDC authorization endpoint passthrough must integrate with the same `SignInManager` for the cookie scheme. OpenIddict's `EnableAuthorizationEndpointPassthrough` hands control to the `Authorize.cs` slice, which calls `SignInAsync` then hands back to OpenIddict. The ordering (Finbuckle MultiTenant middleware → OpenIddict authorization endpoint → sign-in) must be verified.

**Proposed resolution:** The `Authorize.cs` slice follows OpenIddict's documented "passthrough" pattern exactly. Unit tests for `AuthorizeHandler` mock `HttpContext` using `Microsoft.AspNetCore.Http.Features` to simulate the OpenIddict passthrough context. The sample project (`Idmt.BasicSample`) is updated to demonstrate the full flow.

### 7.4 `IdmtDbContext` and OpenIddict Entity Coexistence

**Risk:** `IdmtDbContext` currently inherits `MultiTenantIdentityDbContext<IdmtUser, IdmtRole, Guid>`. OpenIddict's `UseEntityFrameworkCore().UseDbContext<IdmtDbContext>()` adds four entity sets (`OpenIddictApplication`, `OpenIddictAuthorization`, `OpenIddictScope`, `OpenIddictToken`). If OpenIddict's `OpenIddictDbContext<...>` base conflicts with Finbuckle's base, a manual merge via `OnModelCreating` calling both `base.OnModelCreating` and OpenIddict's model builder is required.

**Proposed resolution:** Do NOT inherit OpenIddict's `OpenIddictDbContext`. Instead, call `builder.UseOpenIddict()` inside `IdmtDbContext.OnModelCreating` to register the four entity sets via model extension, consistent with OpenIddict's EF Core documentation for non-derived contexts. Validated against OpenIddict 5.x EF Core samples.

### 7.5 Per-Tenant Cookie Isolation in OpenIddict OIDC Flow

**Risk:** v1 configures per-tenant cookies via `builder.Services.ConfigurePerTenant<CookieAuthenticationOptions, IdmtTenantInfo>(IdentityConstants.ApplicationScheme, ...)`. The OpenIddict authorization endpoint issues cookies via the same `IdentityConstants.ApplicationScheme`. The per-tenant isolation must still work with OpenIddict's passthrough — the tenant context must be set before `SignInAsync` is called in the `Authorize.cs` slice.

**Proposed resolution:** `Authorize.cs` handler explicitly verifies Finbuckle tenant context before any sign-in call, consistent with the fail-closed pattern in v1's `IdmtUserClaimsPrincipalFactory`. Per-tenant cookie name isolation is preserved because cookie naming is configured at the scheme level, not at OpenIddict level.

### 7.6 `TenantAccess` Gate in OpenIddict `/connect/token` (Password Grant Path)

**Risk:** The `password` grant flow in OpenIddict 5.x can be handled by implementing `IOpenIddictServerHandler<HandleTokenRequestContext>`. This handler must enforce the `TenantAccess` gate (locked decision #4) before tokens are issued. The handler is called from within the OpenIddict server pipeline, where `IMultiTenantContextAccessor` is available but the Finbuckle tenant context must have been set by middleware before the token endpoint is reached.

**Proposed resolution:** Register a custom `IOpenIddictServerHandler<HandleTokenRequestContext>` in `Features/Auth/Authorize.cs` (or a sibling `TokenEndpointHandler.cs`) that:
1. Resolves the user from the `username`/`password` claims.
2. Calls `tenantAccessService.CanAccessTenantAsync`.
3. If denied, calls `context.Reject(error: "access_denied")`.
This mirrors v1's `Login.TokenLoginHandler` logic, now expressed as an OpenIddict pipeline handler.

### 7.7 Migration Path from v1 to v2

**Risk:** Existing deployments have `RevokedTokens` rows and hand-issued tokens (ASP.NET Core `BearerTokenProtector` format). These tokens are incompatible with OpenIddict reference tokens and cannot be used after migration.

**Proposed resolution:**
1. Existing v1 tokens are invalidated immediately on upgrade because the validation scheme changes. Clients must re-authenticate. Document this as a breaking change in the upgrade guide.
2. The `RevokedTokens` table can be dropped via a migration; no data migration is needed.
3. Provide a migration checklist in `UPGRADING.md`: (a) run schema migration (adds four OpenIddict tables, drops `RevokedTokens`), (b) auto-seed OpenIddict application registration, (c) notify client teams that all active sessions are terminated on deploy.

### 7.8 OpenIddict Key Management

**Risk:** v2 uses `AddDevelopmentEncryptionCertificate()` + `AddDevelopmentSigningCertificate()` in `ConfigureOpenIddict`. These generate in-memory keys that change on every restart, invalidating all reference tokens. Production deployments must supply persistent keys.

**Proposed resolution:** Add a `IdmtOpenIddictKeyOptions` nested class to `IdmtOptions` with `CertificatePath` / `CertificateThumbprint` / `KeyVaultUri` hooks. If none are configured and the environment is not `Development`, `IdmtOptionsValidator` should emit a warning (not a hard failure) at startup. The `CustomizeOpenIddict` delegate allows consumers to call `options.AddEncryptionCertificate(...)` / `options.AddSigningCertificate(...)` directly.

---

## Appendix A: `IdmtDbContext` v2 Shape (Sketch)

```csharp
// Idmt.Plugin/Persistence/IdmtDbContext.cs
// Inherits: MultiTenantIdentityDbContext<IdmtUser, IdmtRole, Guid>
// OpenIddict entities added via builder.UseOpenIddict() in OnModelCreating

public class IdmtDbContext
    : MultiTenantIdentityDbContext<IdmtUser, IdmtRole, Guid>
{
    // Existing DbSets — unchanged
    public DbSet<IdmtAuditLog> AuditLogs { get; set; } = null!;
    public DbSet<TenantAccess> TenantAccess { get; set; } = null!;
    // RevokedTokens DELETED

    // OpenIddict entity sets — injected by builder.UseOpenIddict()
    // (not declared explicitly; OpenIddict model extension adds them)

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);  // Finbuckle + Identity

        // Register OpenIddict entities without inheriting OpenIddictDbContext
        builder.UseOpenIddict();

        // [IdmtUser global entity de-tenanting — identical to v1]
        builder.Entity<IdmtUser>(entity => { /* unchanged */ });

        // [IdmtRole, TenantAccess, AuditLog, TenantInfo configs — unchanged] */

        // RevokedToken config DELETED
    }
}
```

---

## Appendix B: `AuthEndpoints.cs` v2 Shape (Sketch)

```csharp
// Idmt.Plugin/Features/AuthEndpoints.cs
public static class AuthEndpoints
{
    internal const string AuthRateLimiterPolicy = "idmt-auth";

    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var idmtOptions = endpoints.ServiceProvider
            .GetRequiredService<IOptions<IdmtOptions>>().Value;

        var auth = endpoints.MapGroup("/auth")
            .WithTags("Authentication");

        if (idmtOptions.RateLimiting.Enabled)
            auth.RequireRateLimiting(AuthRateLimiterPolicy);

        // OIDC endpoints — OpenIddict passthrough
        endpoints.MapAuthorizeEndpoint();           // GET+POST /connect/authorize
        endpoints.MapTokenEndpoint();               // POST     /connect/token
        endpoints.MapRevocationEndpoint();          // POST     /connect/revocation
        endpoints.MapUserInfoEndpoint();            // GET      /connect/userinfo

        // v1-identical endpoints
        auth.MapConfirmEmailEndpoint();
        auth.MapConfirmEmailDirectEndpoint();
        auth.MapConfirmEmailChangeEndpoint();
        auth.MapResendConfirmationEmailEndpoint();
        auth.MapForgotPasswordEndpoint();
        auth.MapResetPasswordEndpoint();
        auth.MapDiscoverTenantsEndpoint();

        // DELETED: MapCookieLoginEndpoint, MapTokenLoginEndpoint, MapRefreshTokenEndpoint
    }
}
```

---

*End of ADR 0002.*