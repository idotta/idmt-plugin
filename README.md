# IDMT Plugin

Identity MultiTenant plugin library for ASP.NET Core that provides automatic identity management (authentication and authorization) and multi-tenancy support using Finbuckle.MultiTenant and Microsoft.AspNetCore.Identity.

## Features

- **Multi-Tenant Support**: Built-in multi-tenancy using Finbuckle.MultiTenant.
- **Identity Management**: ASP.NET Core Identity integration with support for both **Bearer Token** (JWT) and **Cookie** authentication.
- **Vertical Slice Architecture**: Each identity endpoint has its own handler interface and implementation.
- **Minimal APIs**: Modern endpoint routing with clean, composable APIs.
- **Configurable**: Extensive configuration options for identity, cookies, and multi-tenancy strategies.
- **Database Agnostic**: Works with any Entity Framework Core provider.

## Quick Start

### 1. Install the Package

```bash
dotnet add package Idmt.Plugin
```

### 2. Configure Services

In your `Program.cs`, add the IDMT services. You generally need to provide your own DbContext that inherits from `IdmtDbContext`.

```csharp
using Idmt.Plugin.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add IDMT services with your custom DbContext
builder.Services.AddIdmt<MyDbContext>(
    builder.Configuration,
    // Configure your database provider (e.g., SQL Server, PostgreSQL, SQLite)
    options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
);

var app = builder.Build();

// Configure the HTTP request pipeline
app.UseIdmt();

// Ensure database is created and seeded (optional helper)
app.EnsureIdmtDatabase();
app.SeedIdmtData();

app.Run();
```

### 3. Application Configuration

Add the `Idmt` section to your `appsettings.json`. Below is a comprehensive example with default or common values:

```json
{
  "Idmt": {
    "Application": {
      "ClientUrl": "https://myapp.com",
      "ResetPasswordFormPath": "/reset-password",
      "ConfirmEmailFormPath": "/confirm-email"
    },
    "Identity": {
      "Password": {
        "RequireDigit": true,
        "RequireLowercase": true,
        "RequireUppercase": true,
        "RequireNonAlphanumeric": false,
        "RequiredLength": 6
      },
      "User": {
        "RequireUniqueEmail": true
      },
      "SignIn": {
        "RequireConfirmedEmail": false
      },
      "Cookie": {
        "Name": ".Idmt.Application",
        "HttpOnly": true,
        "SameSite": "Lax",
        "ExpireTimeSpan": "14.00:00:00",
        "SlidingExpiration": true
      }
    },
    "MultiTenant": {
      "DefaultTenantId": "system-tenant",
      "Strategies": ["header", "route", "claim"],
      "StrategyOptions": {
        "HeaderName": "__tenant__",
        "RouteParameter": "__tenant__",
        "ClaimType": "tenant"
      }
    },
    "Database": {
      "AutoMigrate": false
    }
  }
}
```

## API Reference

The plugin exposes several groups of endpoints.

### Authentication (`/auth`)

Public endpoints for user authentication and account recovery.

| Method | Endpoint | Description | Query/Body Parameters |
|--------|----------|-------------|-----------------------|
| `POST` | `/auth/login` | Authenticate user | Body: `email`, `password`<br>Query: `useCookies`, `useSessionCookies` |
| `POST` | `/auth/logout` | Logout user | - |
| `POST` | `/auth/refresh` | Refresh JWT token | Body: `refreshToken` |
| `POST` | `/auth/forgotPassword` | Request password reset | Body: `email`<br>Query: `useApiLinks` (true/false) |
| `POST` | `/auth/resetPassword` | Reset password with token | Query: `tenantId`, `email`, `token`<br>Body: `newPassword` |
| `GET` | `/auth/confirmEmail` | Confirm email address | Query: `tenantId`, `email`, `token` |
| `POST` | `/auth/resendConfirmationEmail` | Resend confirmation | Body: `email`<br>Query: `useApiLinks` |

### User Management (`/auth/manage`)

Endpoints for managing user profiles and accounts.
*   **Authorization**: Some endpoints require specific roles (`SysAdmin`, `TenantAdmin`).

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| `GET` | `/auth/manage/info` | Authenticated | Get current user's info |
| `PUT` | `/auth/manage/info` | Authenticated | Update current user's info |
| `POST` | `/auth/manage/users` | `RequireSysUser` | Register a new user (Admin only) |
| `PUT` | `/auth/manage/users/{id}` | `RequireTenantManager` | Activate/Deactivate user |
| `DELETE` | `/auth/manage/users/{id}` | `RequireTenantManager` | Delete a user |

### System & Tenant Access (`/sys`)

System-level endpoints for managing tenant access.
*   **Authorization**: `RequireSysUser` (SysAdmin or SysSupport roles).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/sys/info` | Get system version and environment info |
| `GET` | `/sys/users/{id}/tenants` | List tenants accessible by a user |
| `POST` | `/sys/users/{id}/tenants/{tenantId}` | Grant user access to a tenant |
| `DELETE` | `/sys/users/{id}/tenants/{tenantId}` | Revoke user access to a tenant |

## Authorization Policies

The plugin comes with pre-configured authorization policies based on roles:

- **`RequireAuthenticatedUser`**: Any authenticated user.
- **`RequireSysAdmin`**: Users with `SysAdmin` role.
- **`RequireSysUser`**: Users with `SysAdmin` or `SysSupport` roles.
- **`RequireTenantManager`**: Users with `SysAdmin`, `SysSupport`, or `TenantAdmin` roles.

## Architecture

### Multi-Tenancy
The library supports multiple tenant resolution strategies out of the box:
- **Header**: Reads tenant ID from a request header (default `__tenant__`).
- **Route**: Reads from a route parameter (default `__tenant__`).
- **Claim**: Reads from the user's claims (useful for JWTs).

### Authentication Strategies
The plugin uses a hybrid approach:
- **Cookie**: Standard ASP.NET Core Identity cookies (great for browser apps).
- **Bearer Token**: Custom implementation compatible with ASP.NET Core Identity's bearer tokens (great for SPAs and Mobile apps).

The `CookieOrBearer` policy automatically selects the scheme based on the `Authorization` header.
