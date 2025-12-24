using System.Net.Http.Headers;
using System.Net.Http.Json;
using Idmt.Plugin.Features.Auth;
using Moq;

namespace Idmt.BasicSample.Tests;

/// <summary>
/// Base class for integration tests with common helper methods.
/// </summary>
public abstract class BaseIntegrationTest : IClassFixture<IdmtApiFactory>, IDisposable
{
    protected readonly IdmtApiFactory Factory;

    protected BaseIntegrationTest(IdmtApiFactory factory)
    {
        Factory = factory;
        Factory.EmailSenderMock.Reset();
    }

    public virtual void Dispose()
    {
        Factory.EmailSenderMock.Reset();
    }

    /// <summary>
    /// Creates an authenticated HTTP client with the default sys admin credentials.
    /// </summary>
    protected async Task<HttpClient> CreateAuthenticatedClientAsync()
    {
        var client = Factory.CreateClientWithTenant();
        var loginResponse = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        await loginResponse.AssertSuccess();
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        return client;
    }

    /// <summary>
    /// Creates an authenticated HTTP client with a specific bearer token.
    /// </summary>
    protected HttpClient CreateClientWithToken(string? tenantId = null, string? token = null)
    {
        var client = Factory.CreateClientWithTenant(tenantId);
        if (!string.IsNullOrWhiteSpace(token))
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        return client;
    }

    /// <summary>
    /// Extracts an access token from a login response.
    /// </summary>
    protected static async Task<string?> ExtractAccessTokenAsync(HttpResponseMessage response)
    {
        var tokens = await response.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        return tokens?.AccessToken;
    }
}
