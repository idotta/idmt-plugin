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
        "SlidingExpiration": true,
        "IsRedirectEnabled": false
      },
      "Bearer": {
        "BearerTokenExpiration": "01:00:00",
        "RefreshTokenExpiration": "30.00:00:00"
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

| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| `POST` | `/auth/login` | Authenticate user with cookie | `email` or `username`, `password`, `rememberMe` (optional) | `LoginResponse` (sets authentication cookie) |
| `POST` | `/auth/token` | Authenticate user and get bearer token | `email` or `username`, `password`, `rememberMe` (optional) | `AccessTokenResponse` (access token, refresh token, expires in) |
| `POST` | `/auth/logout` | Logout user (cookie-based) | - | No content |
| `POST` | `/auth/refresh` | Refresh JWT token | `refreshToken` | `AccessTokenResponse` |
| `POST` | `/auth/forgotPassword` | Request password reset | `email`<br>Query: `useApiLinks` (true/false) | `ForgotPasswordResponse` |
| `POST` | `/auth/resetPassword` | Reset password with token | Query: `tenantId`, `email`, `token`<br>Body: `newPassword` | `ResetPasswordResponse` |
| `GET` | `/auth/confirmEmail` | Confirm email address | Query: `tenantId`, `email`, `token` | `ConfirmEmailResponse` |
| `POST` | `/auth/resendConfirmationEmail` | Resend confirmation | Body: `email`<br>Query: `useApiLinks` | `ResendConfirmationEmailResponse` |

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
The plugin uses a hybrid approach with separate endpoints for each authentication method:
- **Cookie Authentication** (`/auth/login`): Sets an authentication cookie directly, ideal for browser-based applications. Returns a `LoginResponse` with user information.
- **Bearer Token Authentication** (`/auth/token`): Returns bearer tokens (access token and refresh token) in the response body, ideal for SPAs and mobile apps. Returns an `AccessTokenResponse` with token details.

Both authentication methods use local token/cookie resolution and do not delegate to Identity middleware, providing full control over the authentication flow.

The `CookieOrBearer` policy automatically selects the scheme based on the `Authorization` header:
- If an `Authorization: Bearer <token>` header is present, bearer token authentication is used.
- Otherwise, cookie authentication is attempted.

#### Example: Cookie Authentication

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

Response:
```json
{
  "userId": "123e4567-e89b-12d3-a456-426614174000"
}
```

The authentication cookie is automatically set in the response.

#### Example: Bearer Token Authentication

```http
POST /auth/token
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

Response:
```json
{
  "accessToken": "CfDJ8...",
  "refreshToken": "CfDJ8...",
  "expiresIn": 3600,
  "tokenType": "Bearer"
}
```

Use the `accessToken` in subsequent requests:
```http
GET /auth/manage/info
Authorization: Bearer CfDJ8...
```
