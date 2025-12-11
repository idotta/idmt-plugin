# IDMT Plugin

Identity MultiTenant plugin library for ASP.NET Core that provides automatic identity management (authentication and authorization) and multi-tenancy support using Finbuckle.MultiTenant.

## Features

- **Multi-Tenant Support**: Built-in multi-tenancy using Finbuckle.MultiTenant
- **Identity Management**: ASP.NET Core Identity integration with JWT and cookie authentication
- **Vertical Slice Architecture**: Each identity endpoint has its own handler interface and implementation
- **Minimal APIs**: Modern endpoint routing with clean, composable APIs
- **Configurable**: Extensive configuration options for identity, JWT, and multi-tenancy
- **Database Agnostic**: Works with any Entity Framework Core provider

## Quick Start

### 1. Install the Package

```bash
dotnet add package Idmt.Plugin
```

### 2. Configure Services

```csharp
using Idmt.Plugin.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add IDMT services
builder.Services.AddIdmt(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline
app.UseIdmt();

// Ensure database is created and seeded
app.EnsureIdmtDatabase();
app.SeedIdmtData();

app.Run();
```

### 3. Configuration

Add configuration to your `appsettings.json`:

```json
{
  "Idmt": {
    "Jwt": {
      "SecretKey": "YourSecretKeyMustBeAtLeast256BitsLong",
      "Issuer": "YourIssuer",
      "Audience": "YourAudience",
      "ExpirationMinutes": 60
    },
    "Identity": {
      "Password": {
        "RequireDigit": true,
        "RequireLowercase": true,
        "RequireUppercase": false,
        "RequiredLength": 6
      },
      "SignIn": {
        "RequireConfirmedEmail": false
      }
    },
    "MultiTenant": {
      "DefaultTenantId": "default",
      "Strategy": "header",
      "StrategyOptions": {
        "HeaderName": "X-Tenant-ID"
      }
    }
  }
}
```

## Architecture

### Vertical Slice Pattern

The library implements a vertical slice architecture where each feature is self-contained:

- **Login Feature**: `LoginHandler`, `LoginRequest`, `LoginResponse`
- **Register Feature**: `RegisterHandler`, `RegisterRequest`, `RegisterResponse`
- **Logout Feature**: `LogoutHandler`, `LogoutRequest`, `LogoutResponse`

### Multi-Tenancy

Multi-tenancy is achieved through:
- Tenant-aware user and role models (`IdmtUser`, `IdmtRole`)
- Automatic tenant filtering in Entity Framework queries
- Tenant resolution strategies (header, subdomain, path, query)

### Database Context

The `IdmtDbContext` extends `IdentityDbContext` and integrates with Finbuckle.MultiTenant:

```csharp
public class IdmtDbContext : IdentityDbContext<IdmtUser, IdmtRole, string>, IMultiTenantDbContext
{
    public ITenantInfo TenantInfo { get; set; } = null!;
    // Multi-tenant configuration
}
```

## API Usage

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json
X-Tenant-ID: your-tenant

{
  "email": "user@example.com",
  "password": "SecurePassword123",
  "confirmPassword": "SecurePassword123",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json
X-Tenant-ID: your-tenant

{
  "email": "user@example.com",
  "password": "SecurePassword123"
}
```

#### Logout
```http
POST /api/auth/logout
Content-Type: application/json
Authorization: Bearer <your-jwt-token>

{
  "signOutEverywhere": false
}
```

### Protected Endpoints

Use the JWT token returned from login in the Authorization header:

```http
GET /api/users/me
Authorization: Bearer <your-jwt-token>
X-Tenant-ID: your-tenant
```

## Sample Application

See the `samples/Idmt.Sample` project for a complete working example that demonstrates:

- Service configuration
- API controllers using the vertical slice handlers
- Multi-tenant user management
- Swagger/OpenAPI documentation

### Running the Sample

```bash
cd samples/Idmt.Sample
dotnet run
```

The sample will be available at `http://localhost:5290` with Swagger UI at `http://localhost:5290/swagger`.

## Advanced Configuration

### Custom Database Provider

```csharp
builder.Services.AddIdmtWithEntityFramework<MyCustomDbContext>(
    builder.Configuration,
    options => options.UseSqlServer(connectionString)
);
```

### Custom Tenant Resolution

```csharp
builder.Services.AddIdmt(builder.Configuration, options =>
{
    options.MultiTenant.Strategy = "subdomain";
    options.MultiTenant.StrategyOptions["Domain"] = "example.com";
});
```

## Contributing

This library is designed to be extensible. You can:
- Add custom identity features using the vertical slice pattern
- Implement custom tenant resolution strategies
- Extend the user and role models
- Add custom authentication providers

## License

MIT License - see LICENSE file for details.
