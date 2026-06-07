using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Idmt.AspNetCore.Tests.Server;

/// <summary>
/// Gate 1 (ADR 0002 §2.3): reference tokens with <c>EnableTokenEntryValidation</c>
/// revoke on the next request through the co-hosted local validation handler. This
/// closes audit finding C1.
/// </summary>
public sealed class ReferenceTokenRevocationTests(OpenIddictServerTestHost host)
    : IClassFixture<OpenIddictServerTestHost>
{
    [Fact]
    public async Task RevokedReferenceToken_returns_401_on_next_request()
    {
        var token = await GetClientTokenAsync();

        var client = host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Valid before revocation.
        var before = await client.GetAsync("/whoami");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        // Revoke the token entry server-side (a single row status update).
        using (var scope = host.Services.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
            await foreach (var entry in manager.FindBySubjectAsync(OpenIddictServerTestHost.ClientId))
            {
                await manager.TryRevokeAsync(entry);
            }
        }

        // Rejected on the next request, before the token's natural TTL expires.
        var after = await client.GetAsync("/whoami");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    private async Task<string> GetClientTokenAsync()
    {
        var client = host.CreateClient();
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"),
            new("client_id", OpenIddictServerTestHost.ClientId),
            new("client_secret", OpenIddictServerTestHost.ClientSecret),
            new("scope", "api"),
        ]));

        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<TokenResponse>();
        return payload!.AccessToken;
    }

    private sealed record TokenResponse(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken);
}
