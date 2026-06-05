using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Idmt.Spike.Host.Auth;
using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Seeding;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idmt.Spike.Host.Bff;

/// <summary>
/// Gate 8: real interactive browser login via authorization code + PKCE. The
/// authorization server hosts an interactive login session (the AuthServerLogin
/// cookie); the BFF drives the code flow, exchanges the code server-side, and
/// stores the resulting reference token in the same server-side session store the
/// raw bearer / gate-7 path uses. The browser only ever holds the opaque
/// bff_session cookie, and the token's subject is the authenticated user.
/// </summary>
public static class AuthServer
{
    public const string LoginScheme = "AuthServerLogin";

    public static IServiceCollection AddAuthCodeFlow(this IServiceCollection services)
    {
        services.AddSingleton<IPkceFlowStore, InMemoryPkceFlowStore>();
        return services;
    }

    public static void MapAuthCodeEndpoints(this WebApplication app)
    {
        // The authorization server's login page: establish the interactive session.
        app.MapPost("/auth/login", async (
            AuthLoginRequest body, HttpContext ctx, UserManager<IdmtUser> users) =>
        {
            var user = await users.FindByEmailAsync(body.Email);
            if (user is null || !await users.CheckPasswordAsync(user, body.Password))
            {
                return Results.Unauthorized();
            }

            var identity = new ClaimsIdentity(LoginScheme);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
            await ctx.SignInAsync(LoginScheme, new ClaimsPrincipal(identity));
            return Results.Ok();
        });

        // Authorization endpoint (OpenIddict passthrough). Issues a code bound to
        // the PKCE challenge for the interactively-authenticated user.
        app.MapMethods("/connect/authorize", ["GET", "POST"], async (HttpContext ctx) =>
        {
            var request = ctx.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("Not an OpenIddict authorization request.");

            var auth = await ctx.AuthenticateAsync(LoginScheme);
            if (!auth.Succeeded || auth.Principal?.FindFirstValue(ClaimTypes.NameIdentifier) is not { } userId)
            {
                // No interactive session: a real AS would render a login page. The
                // spike just refuses; the test logs in first.
                return Results.Challenge(authenticationSchemes: [LoginScheme]);
            }

            var identity = new ClaimsIdentity(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
            identity.SetClaim(Claims.Subject, userId);
            identity.SetScopes(request.GetScopes());

            // Tenant audience from a custom 'tenant' parameter (the same convention
            // the token endpoint uses), set directly so OpenIddict does not run its
            // RFC 8707 'resource' validation against an unregistered URN. Carried
            // into the code so the exchanged token is tenant-bound (gate 3 handler).
            var tenant = (string?)request["tenant"];
            if (!string.IsNullOrEmpty(tenant))
            {
                identity.SetAudiences(TenantUrns.For(tenant));
            }

            identity.SetDestinations(static _ => [Destinations.AccessToken]);

            return Results.SignIn(
                new ClaimsPrincipal(identity), properties: null,
                authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        });

        // BFF initiation: generate PKCE, stash the verifier server-side, redirect
        // the browser to the authorize endpoint.
        //
        // SPIKE LIMITATION (do not copy as-is): `state` is server-global and not
        // bound to the initiating browser, so this is open to OAuth login-CSRF —
        // any browser presenting a valid `state` at /bff/callback consumes the flow.
        // PRODUCTION (v2): bind `state` to the browser — set a short-lived
        // HttpOnly+Secure+SameSite=Lax `bff_oauth_state` cookie at initiation and,
        // in /bff/callback, require a constant-time match against the inbound
        // `state` (then clear the cookie) before consuming the flow. This gate
        // proves the auth-code+PKCE *composition*, not a hardened BFF.
        app.MapGet("/bff/login-pkce", (string tenant, IPkceFlowStore flows) =>
        {
            var verifier = NewCodeVerifier();
            var challenge = S256Challenge(verifier);
            var state = Guid.NewGuid().ToString("N");
            flows.Put(state, new PkceFlow(verifier, tenant));

            var url =
                "/connect/authorize" +
                "?response_type=code" +
                $"&client_id={IdmtSpikeSeeder.SpaClientId}" +
                $"&redirect_uri={Uri.EscapeDataString(IdmtSpikeSeeder.SpaRedirectUri)}" +
                "&scope=api" +
                $"&tenant={Uri.EscapeDataString(tenant)}" +
                $"&code_challenge={challenge}&code_challenge_method=S256" +
                $"&state={state}";

            return Results.Redirect(url);
        });

        // BFF callback: exchange the code (with the stored verifier) server-side,
        // store the token in the session, set only the opaque session cookie.
        app.MapGet("/bff/callback", async (
            string code, string state,
            HttpContext ctx,
            IPkceFlowStore flows,
            IHttpClientFactory httpFactory,
            IBffSessionStore sessions,
            IDataProtectionProvider dp) =>
        {
            var flow = flows.Take(state);
            if (flow is null)
            {
                return Results.BadRequest("unknown state");
            }

            var client = httpFactory.CreateClient(BffBackChannel.Name);
            var tokenResponse = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
            [
                new("grant_type", "authorization_code"),
                new("code", code),
                new("redirect_uri", IdmtSpikeSeeder.SpaRedirectUri),
                new("client_id", IdmtSpikeSeeder.SpaClientId),
                new("code_verifier", flow.Verifier),
            ]));

            if (!tokenResponse.IsSuccessStatusCode)
            {
                var bodyText = await tokenResponse.Content.ReadAsStringAsync();
                return Results.Problem($"code exchange failed: {(int)tokenResponse.StatusCode} {bodyText}");
            }

            var payload = await tokenResponse.Content.ReadFromJsonAsync<TokenPayload>();
            // The user identity is carried by the token's subject; the BFF session
            // need not know it, so userId stays empty here.
            var sessionId = sessions.Create(Guid.Empty, flow.Tenant, payload!.AccessToken);
            var protectedId = dp.CreateProtector(BffEndpoints.ProtectorPurpose).Protect(sessionId);

            BffEndpoints.AppendSessionCookie(ctx, protectedId);
            return Results.Redirect("/");
        });
    }

    private static string NewCodeVerifier() => Base64Url(RandomNumberGenerator.GetBytes(32));

    private static string S256Challenge(string verifier) =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public sealed record AuthLoginRequest(string Email, string Password);

    private sealed record TokenPayload(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken);
}

public sealed record PkceFlow(string Verifier, string Tenant);

public interface IPkceFlowStore
{
    void Put(string state, PkceFlow flow);
    PkceFlow? Take(string state);
}

/// <summary>In-memory, single-use PKCE flow store keyed by the OAuth state value.</summary>
public sealed class InMemoryPkceFlowStore : IPkceFlowStore
{
    private readonly ConcurrentDictionary<string, PkceFlow> _flows = new(StringComparer.Ordinal);

    public void Put(string state, PkceFlow flow) => _flows[state] = flow;

    public PkceFlow? Take(string state) => _flows.TryRemove(state, out var flow) ? flow : null;
}
