using System.Net.Http.Headers;
using System.Net.Http.Json;
using Idmt.Spike.Host.Seeding;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Idmt.Spike.Tests;

/// <summary>Spins up the spike host (fresh in-memory SQLite + seed per factory).</summary>
public abstract class BaseSpikeIntegrationTest : IClassFixture<WebApplicationFactory<Program>>
{
    protected WebApplicationFactory<Program> Factory { get; }

    protected BaseSpikeIntegrationTest(WebApplicationFactory<Program> factory) => Factory = factory;

    /// <summary>Requests a client-credentials reference token audienced for the given tenant.</summary>
    protected async Task<string> GetClientTokenAsync(string tenant, string scope = "api")
    {
        var client = Factory.CreateClient();
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"),
            new("client_id", IdmtSpikeSeeder.ClientId),
            new("client_secret", IdmtSpikeSeeder.ClientSecret),
            new("scope", scope),
            new("tenant", tenant),
        ]));

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException($"Token request failed: {(int)response.StatusCode} {body}");
        }

        var payload = await response.Content.ReadFromJsonAsync<TokenResponse>();
        return payload!.AccessToken;
    }

    /// <summary>A client whose requests resolve to <paramref name="tenant"/> via the X-Tenant header.</summary>
    protected HttpClient ClientForTenant(string tenant, string? bearer = null)
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Tenant", tenant);
        if (bearer is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }
        return client;
    }

    protected sealed record TokenResponse(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("token_type")] string TokenType);
}
