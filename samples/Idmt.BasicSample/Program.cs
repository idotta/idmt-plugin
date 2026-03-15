// ============================================================
// Idmt.BasicSample — showcasing the full IDMT plugin feature set
//
// What this sample demonstrates:
//   - Cookie + Bearer dual-scheme authentication
//   - Multi-tenant resolution via header and claim strategies
//   - Role-based authorization (SysAdmin, TenantAdmin, custom roles)
//   - Rate limiting on auth endpoints (disabled in Development)
//   - Database initialization with EnsureCreated (SQLite)
//   - OpenAPI document with Bearer security scheme
//   - Seeding a default admin user on first run (SeedTestUser.cs)
//
// Default credentials (seeded on first run):
//   Email:    testadmin@example.com
//   Password: TestAdmin123!
// ============================================================

using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

// ----------------------------------------------------------
// OpenAPI — expose the Bearer security scheme in Swagger UI.
// IDMT does not configure OpenAPI itself; the host app owns it.
// ----------------------------------------------------------
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, _, _) =>
    {
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "opaque",
            Description = "Bearer token obtained from POST /auth/login/token"
        };
        return Task.CompletedTask;
    });
});

// ----------------------------------------------------------
// IDMT plugin registration
//
// AddIdmt parameters:
//   configureDb      — configure the EF Core provider (required)
//   configureOptions — override any IdmtOptions value in code,
//                      applied on top of appsettings.json bindings
//   customizeAuthentication / customizeAuthorization — extend
//                      the auth pipeline with additional schemes
//                      or policies without replacing the defaults
// ----------------------------------------------------------
builder.Services.AddSingleton<SeedDataAsync>(Idmt.BasicSample.SeedTestUser.SeedAsync);

builder.Services.AddIdmt(
    builder.Configuration,
    configureDb: db => db.UseSqlite("Data Source=Idmt.BasicSample.db"),
    configureOptions: options =>
    {
        // Code-level overrides run after appsettings.json is bound,
        // so they always win regardless of environment config files.

        // Example: add application-specific roles that IDMT will seed
        // alongside the built-in SysAdmin / TenantAdmin roles.
        // options.Identity.ExtraRoles = ["Editor", "Viewer"];
    });

// ----------------------------------------------------------
// HTTP pipeline
// ----------------------------------------------------------
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // /openapi/v1.json — excluded from multi-tenant resolution so it
    // is always reachable regardless of the active tenant strategy.
    app.MapOpenApi().ExcludeFromMultiTenantResolution();
}

// Serve the bundled HTML/CSS/JS frontend from wwwroot/.
app.UseDefaultFiles();
app.UseStaticFiles();

// Registers security headers, rate limiter (when enabled), multi-tenant
// middleware, authentication, authorization, and IDMT-specific middleware.
app.UseIdmt();

// ----------------------------------------------------------
// Endpoint routing
//
// When the "route" strategy is active the tenant identifier is
// embedded in the URL path (e.g. /acme/api/v1/auth/login), so
// the endpoint group must expose the {__tenant__} route parameter.
// All other strategies (header, claim, basepath) use a plain group.
// ----------------------------------------------------------
var idmtOptions = app.Services.GetRequiredService<IOptions<IdmtOptions>>().Value;

if (idmtOptions.MultiTenant.Strategies.Contains(IdmtMultiTenantStrategy.Route))
{
    app.MapGroup("/{__tenant__}").MapIdmtEndpoints();
}
else
{
    app.MapGroup("").MapIdmtEndpoints();
}

// ----------------------------------------------------------
// Database initialization and data seeding
//
// EnsureIdmtDatabaseAsync honours the DatabaseInitialization mode
// from configuration (EnsureCreated / Migrate / None).
// SeedIdmtDataAsync creates the default system tenant and then
// runs the optional custom seed delegate registered above.
// ----------------------------------------------------------
await app.EnsureIdmtDatabaseAsync();
await app.SeedIdmtDataAsync(app.Services.GetService<SeedDataAsync>());

app.Run();

// Required by integration tests (WebApplicationFactory<Program>).
public partial class Program;
