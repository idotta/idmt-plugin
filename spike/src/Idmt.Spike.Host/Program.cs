using System.Security.Claims;
using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Idmt.Spike.Host.Auth;
using Idmt.Spike.Host.Bff;
using Idmt.Spike.Host.Seeding;
using Idmt.Spike.Host.Server;
using Idmt.Spike.Host.Wiring;
using Microsoft.AspNetCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddIdmtSpike();
builder.Services.AddScoped<SupportTokenService>();
builder.Services.AddScoped<UserTokenMint>();
builder.Services.AddScoped<TokenRevocationHook>();

var app = builder.Build();

await IdmtSpikeSeeder.SeedAsync(app.Services);

// Finbuckle must resolve the tenant BEFORE authentication so the audience
// handler can read the resolved tenant (gate 3).
app.UseMultiTenant();
// Gate 7: resolve a BFF session cookie to its server-side reference token and set
// the bearer header BEFORE authentication, so the cookie path runs the exact same
// validation pipeline as a raw bearer request.
app.UseBffSessionResolver();
app.UseAuthentication();
app.UseAuthorization();

// Token endpoint: client-credentials passthrough. IDMT stamps the per-tenant
// audience from the request "tenant" parameter (gates 1, 3, 4).
app.MapPost("/connect/token", (HttpContext ctx) =>
{
    var request = ctx.GetOpenIddictServerRequest()
        ?? throw new InvalidOperationException("Not an OpenIddict token request.");

    if (!request.IsClientCredentialsGrantType())
    {
        return Results.Forbid(
            authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    var identity = new ClaimsIdentity(
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        Claims.Name,
        Claims.Role);

    identity.SetClaim(Claims.Subject, request.ClientId);
    identity.SetScopes(request.GetScopes());

    var tenant = (string?)request["tenant"];
    if (!string.IsNullOrEmpty(tenant))
    {
        identity.SetAudiences(TenantUrns.For(tenant));
    }

    identity.SetDestinations(static _ => [Destinations.AccessToken]);

    return Results.SignIn(
        new ClaimsPrincipal(identity),
        properties: null,
        authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
});

// Gate 4 (stamping half): writing a [MultiTenant] entity under the ambient
// tenant gets its TenantId stamped by Finbuckle, in the same database that hosts
// the (tenant-agnostic) OpenIddict stores. Requires an X-Tenant header.
app.MapPost("/api/widgets", async (Idmt.Spike.Host.Persistence.IdmtTenantDbContext db, string label) =>
{
    var widget = new Idmt.Spike.Host.Domain.TenantWidget { Label = label };
    db.Widgets.Add(widget);
    await db.SaveChangesAsync();
    return Results.Ok(new { widget.Id, widget.TenantId });
});

// Protected resource: requires a valid (non-revoked) reference token whose
// audience binds to the resolved tenant.
app.MapGet("/api/whoami", (ClaimsPrincipal user) =>
    Results.Ok(new
    {
        subject = user.GetClaim(Claims.Subject),
        audiences = user.GetAudiences(),
    }))
    .RequireAuthorization();

app.MapBffEndpoints();

app.Run();

public partial class Program;
