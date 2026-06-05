using System.Collections.Concurrent;
using System.Net.Http.Json;
using Idmt.Spike.Host.Auth;
using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Persistence;
using Idmt.Spike.Host.Seeding;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.DataProtection;

namespace Idmt.Spike.Host.Bff;

/// <summary>
/// Gate 7: a backend-for-frontend session. The browser never receives a token —
/// it gets only an opaque, httpOnly session-id cookie. The host keeps the
/// reference token in a server-side session store and, on each request, resolves
/// the cookie to that token and replays it through the SAME OpenIddict validation
/// pipeline (including the tenant audience handler) a raw bearer request uses.
/// A mutating endpoint additionally requires an anti-forgery token.
///
/// Stand-in scope (recorded for ADR §7.1): the session token is acquired by a
/// first-party client-credentials back-channel to the in-process token endpoint
/// (subject = client; user identity is carried by the server-side session, and
/// session revocation is by session deletion). A production BFF would complete
/// auth-code + PKCE and carry subject = user — deferred to §7.1.
/// </summary>
public static class BffEndpoints
{
    public const string CookieName = "bff_session";
    public const string ProtectorPurpose = "idmt.bff.session";

    public static IServiceCollection AddBff(this IServiceCollection services)
    {
        services.AddAntiforgery(o => o.HeaderName = "X-CSRF-TOKEN");
        services.AddSingleton<IBffSessionStore, InMemoryBffSessionStore>();
        // The self back-channel used to mint the session's reference token. Tests
        // route this client's handler at the in-memory TestServer.
        services.AddHttpClient(BffBackChannel.Name);
        return services;
    }

    /// <summary>
    /// Resolver: if a session cookie is present and there is no Authorization
    /// header, map the cookie to its server-side reference token and set the
    /// bearer header. Must run before UseAuthentication.
    /// </summary>
    public static IApplicationBuilder UseBffSessionResolver(this IApplicationBuilder app) =>
        app.Use(async (ctx, next) =>
        {
            if (!ctx.Request.Headers.ContainsKey("Authorization") &&
                ctx.Request.Cookies.TryGetValue(CookieName, out var protectedId))
            {
                var protector = ctx.RequestServices
                    .GetRequiredService<IDataProtectionProvider>().CreateProtector(ProtectorPurpose);
                var store = ctx.RequestServices.GetRequiredService<IBffSessionStore>();
                try
                {
                    var session = store.Get(protector.Unprotect(protectedId));
                    if (session is not null)
                    {
                        ctx.Request.Headers.Authorization = $"Bearer {session.ReferenceToken}";
                    }
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    // Tampered/stale cookie: ignore, request proceeds unauthenticated.
                }
            }

            await next();
        });

    public static void MapBffEndpoints(this WebApplication app)
    {
        // Login: validate password + TenantAccess gate, back-channel a reference
        // token, store it server-side, set the opaque session cookie. Returns the
        // anti-forgery request token but NO access token.
        app.MapPost("/bff/login", async (
            LoginRequest body,
            HttpContext ctx,
            UserManager<IdmtUser> users,
            ITenantAccessGate gate,
            IHttpClientFactory httpFactory,
            IBffSessionStore store,
            IDataProtectionProvider dp) =>
        {
            var user = await users.FindByEmailAsync(body.Email);
            if (user is null || !await users.CheckPasswordAsync(user, body.Password))
            {
                return Results.Unauthorized();
            }

            if (!await gate.CanAccessAsync(user.Id, body.Tenant, ctx.RequestAborted))
            {
                return Results.Forbid();
            }

            var token = await BackChannelTokenAsync(httpFactory, body.Tenant, ctx.RequestAborted);
            if (token is null)
            {
                return Results.Problem("Back-channel token acquisition failed.");
            }

            var sessionId = store.Create(user.Id, body.Tenant, token);
            var protectedId = dp.CreateProtector(ProtectorPurpose).Protect(sessionId);
            ctx.Response.Cookies.Append(CookieName, protectedId, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax, // Strict would drop on the deferred auth-code redirect-return (§7.1).
                Secure = false,              // spike runs HTTP
                IsEssential = true,
            });

            return Results.Ok(new LoginResponse());
        });

        // Anti-forgery token issuance. Cookie-authed so the token binds to the same
        // principal that /bff/widgets validates against (a real SPA fetches it the
        // same way). Sets the anti-forgery cookie and returns the request token.
        app.MapGet("/bff/csrf", (HttpContext ctx, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(ctx);
            return Results.Ok(new CsrfResponse(tokens.RequestToken!));
        }).RequireAuthorization();

        // Mutating, cookie-authed endpoint guarded by anti-forgery.
        app.MapPost("/bff/widgets", async (
            HttpContext ctx,
            IAntiforgery antiforgery,
            IdmtTenantDbContext db,
            [FromQuery] string label) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(ctx);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest("missing or invalid anti-forgery token");
            }

            var widget = new TenantWidget { Label = label };
            db.Widgets.Add(widget);
            await db.SaveChangesAsync();
            return Results.Ok(new { widget.Id, widget.TenantId });
        }).RequireAuthorization();
    }

    private static async Task<string?> BackChannelTokenAsync(
        IHttpClientFactory httpFactory, string tenant, CancellationToken ct)
    {
        var client = httpFactory.CreateClient(BffBackChannel.Name);
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"),
            new("client_id", IdmtSpikeSeeder.ClientId),
            new("client_secret", IdmtSpikeSeeder.ClientSecret),
            new("scope", "api"),
            new("tenant", tenant),
        ]), ct);

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var payload = await response.Content.ReadFromJsonAsync<TokenPayload>(ct);
        return payload?.AccessToken;
    }

    public sealed record LoginRequest(string Email, string Password, string Tenant);
    public sealed record LoginResponse();
    public sealed record CsrfResponse(string AntiforgeryToken);

    private sealed record TokenPayload(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken);
}

/// <summary>The name of the self back-channel HttpClient (tests route it at the TestServer).</summary>
public static class BffBackChannel
{
    public const string Name = "bff-self";
}

public sealed record BffSession(Guid UserId, string Tenant, string ReferenceToken);

public interface IBffSessionStore
{
    string Create(Guid userId, string tenant, string referenceToken);
    BffSession? Get(string sessionId);
}

/// <summary>In-memory session store. The reference token lives here, never in the browser.</summary>
public sealed class InMemoryBffSessionStore : IBffSessionStore
{
    private readonly ConcurrentDictionary<string, BffSession> _sessions = new(StringComparer.Ordinal);

    public string Create(Guid userId, string tenant, string referenceToken)
    {
        var sessionId = Guid.NewGuid().ToString("N");
        _sessions[sessionId] = new BffSession(userId, tenant, referenceToken);
        return sessionId;
    }

    public BffSession? Get(string sessionId) =>
        _sessions.TryGetValue(sessionId, out var session) ? session : null;
}
