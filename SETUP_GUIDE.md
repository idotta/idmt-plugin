# IDMT Plugin Setup Guide

## Overview

The IDMT Plugin provides a complete Identity and Multi-Tenant solution for ASP.NET Core applications. The `ServiceCollectionExtensions` has been configured to properly set up all required services following best practices.

## Architecture

The setup follows this sequence:

1. **Configuration** - IDMT options are loaded and configured
2. **Database** - DbContexts are registered (main application + tenant store)
3. **Multi-Tenant** - Finbuckle.MultiTenant with strategies
4. **Identity** - ASP.NET Core Identity with custom user/role models
5. **Authentication** - Cookie-based authentication with per-tenant isolation
6. **Services** - Application services (CurrentUser, TenantAccess)
7. **Features** - Vertical slice handlers (Login, Register, Logout)
8. **Middleware** - CurrentUserMiddleware for request context

## Key Features

### 1. ASP.NET Core Identity Configuration

- **User Management**: Full UserManager, SignInManager, and RoleManager
- **Password Policy**: Configurable via `IdmtOptions.Identity.Password`
- **Lockout Protection**: 5 failed attempts → 5 minutes lockout
- **Token Providers**: Default token providers for password reset, email confirmation, etc.

### 2. Multi-Tenant Support

Multiple tenant resolution strategies are supported:

- **Header**: Uses HTTP header (default: `__tenant__`)
- **Route**: Uses route parameter (default: `__tenant__`)
- **Claim**: Uses authentication claim (default: `tenant`)
- **Host**: Uses hostname pattern
- **BasePath**: Uses URL base path

Configure strategies in `appsettings.json`:

```json
{
  "Idmt": {
    "MultiTenant": {
      "Strategies": ["header", "route", "claim"],
      "StrategyOptions": {
        "HeaderName": "X-Tenant-ID",
        "RouteParameter": "tenant",
        "ClaimType": "tenant_id"
      }
    }
  }
}
```

### 3. Per-Tenant Authentication

Critical for security: Each tenant has isolated authentication contexts. A user authenticated for Tenant A cannot access Tenant B without re-authenticating.

### 4. Cookie Configuration

- **Name**: `.Idmt.Application`
- **Security**: HttpOnly, SameSite=Lax
- **Expiration**: 14 days with sliding expiration
- **Paths**: Configurable login/logout/access-denied paths

### 5. Database Agnostic

The library doesn't enforce a specific database provider. Configure your provider in your application:

```csharp
builder.Services.AddIdmt(builder.Configuration, options =>
{
    // Use SQL Server
    options.UseSqlServer(connectionString);
    
    // Or PostgreSQL
    // options.UseNpgsql(connectionString);
    
    // Or In-Memory for testing
    // options.UseInMemoryDatabase("TestDb");
});
```

## Usage

### Basic Setup

```csharp
var builder = WebApplication.CreateBuilder(args);

// Add IDMT services
builder.Services.AddIdmt(builder.Configuration, options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

var app = builder.Build();

// Use IDMT middleware
app.UseIdmt();

// Optionally ensure database and seed data
app.EnsureIdmtDatabase(autoMigrate: true);
app.SeedIdmtData();

app.Run();
```

### With Custom DbContext

```csharp
public class MyCustomDbContext : IdmtDbContext
{
    public MyCustomDbContext(
        IMultiTenantContextAccessor accessor,
        DbContextOptions<MyCustomDbContext> options)
        : base(accessor, options)
    {
    }
    
    // Add your custom DbSets here
    public DbSet<MyEntity> MyEntities { get; set; }
}

// In Program.cs
builder.Services.AddIdmt<MyCustomDbContext>(
    builder.Configuration,
    options => options.UseSqlServer(connectionString));
```

### Configuration Options

Complete `appsettings.json` example:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=MyApp;Trusted_Connection=true;"
  },
  "Idmt": {
    "Identity": {
      "Password": {
        "RequireDigit": true,
        "RequireLowercase": true,
        "RequireUppercase": true,
        "RequireNonAlphanumeric": false,
        "RequiredLength": 8,
        "RequiredUniqueChars": 1
      },
      "User": {
        "RequireUniqueEmail": true
      },
      "SignIn": {
        "RequireConfirmedEmail": false,
        "RequireConfirmedPhoneNumber": false
      }
    },
    "MultiTenant": {
      "DefaultTenantId": "default",
      "Strategies": ["header", "route"],
      "StrategyOptions": {
        "HeaderName": "X-Tenant-ID",
        "RouteParameter": "tenant"
      }
    },
    "Database": {
      "UseInMemory": false,
      "AutoMigrate": true
    }
  }
}
```

## Services Registered

### Identity Services
- `UserManager<IdmtUser>`
- `SignInManager<IdmtUser>`
- `RoleManager<IdmtRole>`

### Application Services
- `ICurrentUserService` - Access current user information
- `ITenantAccessService` - Manage tenant access permissions
- `IHttpContextAccessor` - Access HTTP context

### Feature Handlers (Vertical Slices)
- `ILoginHandler` - Login logic
- `IRegisterHandler` - Registration logic
- `ILogoutHandler` - Logout logic

### Database Contexts
- `TDbContext` (your custom context or `IdmtDbContext`)
- `IdmtTenantStoreDbContext` - Tenant information store

## Middleware Pipeline

The `UseIdmt()` extension method sets up the middleware in the correct order:

1. **UseMultiTenant()** - Resolves the current tenant
2. **UseAuthentication()** - Authenticates the user
3. **UseAuthorization()** - Authorizes access
4. **CurrentUserMiddleware** - Sets current user context

## Best Practices

### 1. Always Call UseIdmt()

```csharp
// ✅ Correct order
app.UseRouting();
app.UseIdmt(); // Sets up multi-tenant, auth, authz in correct order
app.MapControllers();

// ❌ Wrong - manual ordering can break per-tenant auth
app.UseMultiTenant();
app.UseAuthentication();
// Missing proper integration
```

### 2. Database Migrations

For multi-tenant databases, consider:

- **Shared Database, Shared Schema**: Single database, TenantId columns
- **Shared Database, Separate Schemas**: One schema per tenant
- **Separate Databases**: Connection string per tenant

Configure via `ConnectionStringTemplate` in `IdmtTenantInfo`.

### 3. Tenant Resolution

Choose strategies based on your architecture:

- **Header**: Good for APIs, microservices
- **Route**: Good for multi-tenant web apps with /tenant/path structure
- **Host**: Good for subdomain-based tenancy (tenant1.app.com)
- **Claim**: Good when tenant is in JWT token

### 4. Security Considerations

- **Per-Tenant Authentication** is enabled by default - critical for security
- **HTTPS**: Always use HTTPS in production
- **Cookie Security**: Configured with HttpOnly and SameSite
- **Lockout**: Enabled by default to prevent brute force attacks

## Testing

For testing, use in-memory database:

```csharp
builder.Services.AddIdmt(configuration, options =>
{
    options.UseInMemoryDatabase("TestDb");
});
```

## Troubleshooting

### Issue: Tenant not resolved

**Solution**: Ensure middleware order is correct. `UseMultiTenant()` must come before `UseAuthentication()`.

### Issue: User authenticated in wrong tenant

**Solution**: This shouldn't happen with `WithPerTenantAuthentication()`. Check that it's called in the configuration.

### Issue: Database migrations fail

**Solution**: Ensure your connection string is correct and the database server is accessible.

## Advanced Scenarios

### Custom Tenant Resolution Strategy

```csharp
public class CustomTenantStrategy : IMultiTenantStrategy
{
    public async Task<string?> GetIdentifierAsync(object context)
    {
        // Your custom logic
        return tenantIdentifier;
    }
}

// Register it
services.AddMultiTenant<IdmtTenantInfo>()
    .WithStrategy<CustomTenantStrategy>(ServiceLifetime.Scoped);
```

### Custom Identity Options

```csharp
builder.Services.AddIdmt(configuration, 
    configureDb: options => options.UseSqlServer(connectionString),
    configureOptions: idmtOptions =>
    {
        idmtOptions.Identity.Password.RequiredLength = 12;
        idmtOptions.Identity.Password.RequireNonAlphanumeric = true;
    });
```

## Migration from Previous Version

If you were using the old setup:

### Before
```csharp
services.AddMultiTenant<IdmtTenantInfo>()
    // TODO: Add strategies
    .WithEFCoreStore<IdmtTenantStoreDbContext, IdmtTenantInfo>()
    .WithPerTenantAuthentication();
```

### After
```csharp
// Now handled automatically by AddIdmt()
// Just configure strategies in appsettings.json
services.AddIdmt(configuration, options => 
    options.UseSqlServer(connectionString));
```

## References

- [ASP.NET Core Identity Documentation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- [Finbuckle.MultiTenant Documentation](https://www.finbuckle.com/MultiTenant/Docs/)
- [Authentication Best Practices](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/)

