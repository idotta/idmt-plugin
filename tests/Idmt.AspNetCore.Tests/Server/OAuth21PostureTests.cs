using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idmt.AspNetCore.Tests.Server;

/// <summary>
/// OAuth 2.1 posture (ADR 0002 §4): the resource-owner password grant must be
/// neither configured nor exposed, and the three supported grants must be present.
/// </summary>
public sealed class OAuth21PostureTests(OpenIddictServerTestHost host)
    : IClassFixture<OpenIddictServerTestHost>
{
    [Fact]
    public void Password_grant_is_not_configured()
    {
        var options = host.Services.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;

        Assert.DoesNotContain(GrantTypes.Password, options.GrantTypes);
        Assert.Contains(GrantTypes.ClientCredentials, options.GrantTypes);
        Assert.Contains(GrantTypes.RefreshToken, options.GrantTypes);
        Assert.Contains(GrantTypes.AuthorizationCode, options.GrantTypes);
    }

    [Fact]
    public async Task Password_grant_is_not_exposed_at_the_token_endpoint()
    {
        var client = host.CreateClient();
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "password"),
            new("username", "someone"),
            new("password", "whatever"),
        ]));

        Assert.False(response.IsSuccessStatusCode);

        var payload = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        Assert.Equal(Errors.UnsupportedGrantType, payload!.Error);
    }

    private sealed record ErrorResponse(
        [property: System.Text.Json.Serialization.JsonPropertyName("error")] string Error);
}
