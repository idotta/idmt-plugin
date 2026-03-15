# IDMT Plugin

An opinionated .NET 10 library for self-hosted identity management and multi-tenancy. Built on top of ASP.NET Core Identity and Finbuckle.MultiTenant, it exposes a complete set of Minimal API endpoints for authentication, user management, and tenant administration with minimal configuration.

**Key features:**

- Dual authentication: cookie-based and bearer token (opaque), resolved automatically per request
- Multi-tenancy via header, claim, route, or base-path strategies (Finbuckle.MultiTenant)
- Vertical slice architecture — each endpoint is a self-contained handler
- Optional per-IP fixed-window rate limiting on all auth endpoints (opt-in)
- Token revocation on logout with background cleanup
- Account lockout (5 failed attempts / 5-minute window)
- PII masking in all structured log output
- Audit logging on all entity mutations
- Per-tenant cookie isolation and bearer token tenant validation
- Security headers on every response

---

## Quick Start

```bash
dotnet add package Idmt.Plugin
```

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdmt<MyDbContext>(
    builder.Configuration,
    db => db.UseSqlServer(connectionString)
);

var app = builder.Build();

app.UseIdmt();
app.MapGroup("").MapIdmtEndpoints();

await app.EnsureIdmtDatabaseAsync();
await app.SeedIdmtDataAsync();

app.Run();
```

`MyDbContext` must extend `IdmtDbContext`. Call `AddIdmt` (without the generic parameter) to use the base context directly.

---

## Configuration

```json
{
  "Idmt": {
    "Application": {
      "ApiPrefix": "/api/v1",
      "ClientUrl": "https://myapp.com",
      "ConfirmEmailFormPath": "/confirm-email",
      "ResetPasswordFormPath": "/reset-password",
      "EmailConfirmationMode": "ClientForm"
    },
    "Identity": {
      "Password": {
        "RequireDigit": true,
        "RequireLowercase": true,
        "RequireUppercase": true,
        "RequireNonAlphanumeric": false,
        "RequiredLength": 8,
        "RequiredUniqueChars": 1
      },
      "SignIn": {
        "RequireConfirmedEmail": true
      },
      "Cookie": {
        "Name": ".Idmt.Application",
        "HttpOnly": true,
        "SameSite": "Strict",
        "ExpireTimeSpan": "14.00:00:00",
        "SlidingExpiration": true
      },
      "Bearer": {
        "BearerTokenExpiration": "01:00:00",
        "RefreshTokenExpiration": "30.00:00:00"
      },
      "ExtraRoles": []
    },
    "MultiTenant": {
      "DefaultTenantName": "System Tenant",
      "Strategies": ["header", "claim", "route"],
      "StrategyOptions": {
        "header": "__tenant__",
        "claim": "tenant",
        "route": "__tenant__"
      }
    },
    "Database": {
      "DatabaseInitialization": "Migrate"
    },
    "RateLimiting": {
      "Enabled": false,
      "PermitLimit": 10,
      "WindowInSeconds": 60
    }
  }
}
```

**Key options:**

- `ApiPrefix` — URI prefix applied to all endpoint groups (`/auth`, `/manage`, `/admin`, `/healthz`). Set to `""` to remove the prefix.
- `EmailConfirmationMode` — `ServerConfirm` sends a GET link that confirms directly on the server; `ClientForm` sends a link to `ClientUrl/ConfirmEmailFormPath` for SPA handling (default).
- `DatabaseInitialization` — `Migrate` runs pending EF Core migrations (production default); `EnsureCreated` skips migrations (development/testing); `None` leaves schema management to the consumer.
- `Strategies` — ordered list of tenant resolution strategies. Valid values: `header`, `claim`, `route`, `basepath`.
- `RateLimiting` — per-IP fixed-window limiter applied to all `/auth` endpoints. Disabled by default; set `Enabled: true` in production to protect against brute-force and email-flooding attacks.

---

## API Reference

All endpoints are mounted under `ApiPrefix` (default `/api/v1`).

### Authentication — `/auth`

Rate-limited when enabled. All endpoints are public except `/auth/logout`.

| Method | Path | Auth Required | Description |
|--------|------|:---:|-------------|
| POST | /auth/login | - | Cookie login. Returns `{ userId }` and sets the auth cookie. |
| POST | /auth/token | - | Bearer token login. Returns `{ accessToken, refreshToken, expiresIn, tokenType }`. |
| POST | /auth/logout | Yes | Signs out and revokes bearer token. |
| POST | /auth/refresh | - | Exchange a refresh token for a new bearer token. |
| POST | /auth/confirm-email | - | Confirm email address (Base64URL-encoded token in request body). |
| GET | /auth/confirm-email | - | Direct server-side email confirmation via query string (`tenantIdentifier`, `email`, `token`). Used when `EmailConfirmationMode` is `ServerConfirm`. |
| POST | /auth/resend-confirmation-email | - | Resend the confirmation email. |
| POST | /auth/forgot-password | - | Send a password reset email. |
| POST | /auth/reset-password | - | Reset password with a Base64URL-encoded token. |
| POST | /auth/discover-tenants | - | Discover tenants associated with an email address. Accepts `{ email }` and returns a tenant list. |

Login requests accept `email` or `username`, `password`, `rememberMe`, and optionally `twoFactorCode` / `twoFactorRecoveryCode`.

### User Management — `/manage`

All endpoints require authentication.

| Method | Path | Policy | Description |
|--------|------|--------|-------------|
| GET | /manage/info | Default (authenticated) | Get the current user's profile. |
| PUT | /manage/info | Default (authenticated) | Update profile, email, or password. |
| POST | /manage/users | RequireTenantManager | Register a new user (invite flow — sends password-setup email). |
| PUT | /manage/users/{userId:guid} | RequireTenantManager | Activate or deactivate a user. |
| DELETE | /manage/users/{userId:guid} | RequireTenantManager | Delete a user. |

### Administration — `/admin`

All endpoints require the `RequireSysUser` policy (`SysAdmin` or `SysSupport` role).

| Method | Path | Description |
|--------|------|-------------|
| POST | /admin/tenants | Create a new tenant. |
| DELETE | /admin/tenants/{tenantIdentifier} | Soft-delete a tenant. |
| GET | /admin/tenants | List all tenants (paginated; query params: `page`, `pageSize`, max 100). |
| GET | /admin/users/{userId:guid}/tenants | List tenants accessible by a user. |
| POST | /admin/users/{userId:guid}/tenants/{tenantIdentifier} | Grant a user access to a tenant. |
| DELETE | /admin/users/{userId:guid}/tenants/{tenantIdentifier} | Revoke a user's access to a tenant. |

### Health — `/healthz`

Requires `RequireSysUser`. Returns database connectivity status via ASP.NET Core Health Checks.

---

## Authorization Policies

| Policy | Roles |
|--------|-------|
| `RequireSysAdmin` | SysAdmin |
| `RequireSysUser` | SysAdmin, SysSupport |
| `RequireTenantManager` | SysAdmin, SysSupport, TenantAdmin |
| `CookieOnly` | — (requires cookie authentication scheme) |
| `BearerOnly` | — (requires bearer authentication scheme) |

Default roles seeded at startup: `SysAdmin`, `SysSupport`, `TenantAdmin`. Add custom roles via `Identity.ExtraRoles` in configuration.

The default authentication scheme (`CookieOrBearer`) routes to bearer token authentication when an `Authorization: Bearer` header is present, and falls back to cookie authentication otherwise.

---

## Multi-Tenancy

Tenant resolution strategies are evaluated in the order they appear in `Strategies`. The first strategy that resolves a tenant wins.

| Strategy | Config key | Default value |
|----------|-----------|---------------|
| `header` | `StrategyOptions.header` | `__tenant__` |
| `claim` | `StrategyOptions.claim` | `tenant` |
| `route` | `StrategyOptions.route` | `__tenant__` |
| `basepath` | — | — |

Authentication cookies are isolated per tenant — the cookie name includes the tenant identifier, preventing session leakage across tenants.

**Route strategy example:**

```csharp
app.MapGroup("/{__tenant__}").MapIdmtEndpoints();
```

**Bearer token tenant validation:**

When using bearer tokens, a middleware (`ValidateBearerTokenTenantMiddleware`) validates that the tenant embedded in the token matches the resolved tenant context on every request.

---

## Security

- Optional per-IP fixed-window rate limiting on all `/auth` endpoints (disabled by default; enable via `RateLimiting.Enabled`)
- `SameSite=Strict` cookies by default — browser never sends the auth cookie on cross-site requests; `SameSiteMode.None` is blocked and falls back to `Strict`
- Security headers on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`
- Token revocation on logout stored in the database; a background `IHostedService` periodically purges expired revoked tokens
- Account lockout: 5 failed attempts triggers a 5-minute lockout
- PII masking: email addresses and other sensitive values are masked in all structured log output
- Audit logging on all entity create/update/delete operations
- Per-tenant cookie isolation: each tenant gets a distinct cookie name
- Bearer token tenant validation middleware on all authenticated bearer requests

---

## Customization

### Service registration hooks

```csharp
builder.Services.AddIdmt<MyDbContext>(
    builder.Configuration,
    db => db.UseNpgsql(connectionString),
    options =>
    {
        options.Application.ApiPrefix = "/api/v2";
    },
    customizeAuthentication: auth =>
    {
        // Add additional authentication schemes
    },
    customizeAuthorization: authz =>
    {
        // Add additional authorization policies
    }
);
```

### Email delivery

The library registers a no-op `IEmailSender<IdmtUser>` by default and logs a startup warning when it is still active. Replace it with a real implementation before calling `app.Run()`:

```csharp
builder.Services.AddTransient<IEmailSender<IdmtUser>, MySmtpEmailSender>();
```

The sender is used for email confirmation, password reset, and the invite-based user registration flow.

### Database seeding

Pass a custom seed delegate to `SeedIdmtDataAsync` to run additional seeding after the default system tenant is created:

```csharp
await app.SeedIdmtDataAsync(async services =>
{
    var userManager = services.GetRequiredService<UserManager<IdmtUser>>();
    // seed initial admin user, etc.
});
```

### OpenAPI / Swagger

IDMT does not configure OpenAPI. To expose the bearer token scheme in Swagger UI, register a document transformer in the host application:

```csharp
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, ct) =>
    {
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "opaque"
        };
        return Task.CompletedTask;
    });
});
```

---

## Requirements

- .NET 10
- Any EF Core-supported database (SQL Server, PostgreSQL, SQLite, etc.)

**Key dependencies:**

| Package | Purpose |
|---------|---------|
| `Finbuckle.MultiTenant` | Tenant resolution and per-tenant authentication |
| `Microsoft.AspNetCore.Identity` | User, role, and sign-in management |
| `ErrorOr` | Discriminated union error handling in handlers |
| `FluentValidation` | Request validation |
