using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
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

    /// <summary>
    /// Registers a new user via the API and sets their password using UserManager to generate
    /// a password reset token directly (since the token is no longer returned in the response).
    /// Returns the user ID.
    /// </summary>
    protected async Task<(string UserId, string Email)> RegisterAndSetPasswordAsync(
        HttpClient authenticatedClient,
        string password,
        string? email = null,
        string? username = null,
        string role = IdmtDefaultRoleTypes.TenantAdmin,
        string? tenantIdentifier = null)
    {
        email ??= $"user-{Guid.NewGuid():N}@example.com";
        username ??= $"user{Guid.NewGuid():N}";
        tenantIdentifier ??= IdmtApiFactory.DefaultTenantIdentifier;

        // Register the user via the API
        var registerResponse = await authenticatedClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = username,
            Role = role,
        });
        await registerResponse.AssertSuccess();
        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var userId = registerResult!.UserId!;

        // Generate a password reset token directly via UserManager
        var resetToken = await GeneratePasswordResetTokenAsync(email, tenantIdentifier);

        // Set the password using the reset-password endpoint (body-based)
        // Token must be Base64URL-encoded as the endpoint expects encoded tokens
        using var publicClient = Factory.CreateClient();
        var resetResponse = await publicClient.PostAsJsonAsync(
            "/auth/reset-password",
            new { TenantIdentifier = tenantIdentifier, Email = email, Token = EncodeToken(resetToken), NewPassword = password });
        await resetResponse.AssertSuccess();

        return (userId, email);
    }

    /// <summary>
    /// Generates a password reset token for a user by accessing UserManager directly.
    /// This replaces the removed PasswordSetupToken from RegisterUserResponse.
    /// </summary>
    protected async Task<string> GeneratePasswordResetTokenAsync(string email, string? tenantIdentifier = null)
    {
        tenantIdentifier ??= IdmtApiFactory.DefaultTenantIdentifier;

        using var scope = Factory.Services.CreateScope();
        var provider = scope.ServiceProvider;

        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(tenantIdentifier)
            ?? throw new InvalidOperationException($"Tenant '{tenantIdentifier}' not found.");

        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);

        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
        var user = await userManager.FindByEmailAsync(email)
            ?? throw new InvalidOperationException($"User with email '{email}' not found.");

        return await userManager.GeneratePasswordResetTokenAsync(user);
    }

    /// <summary>
    /// Generates an email confirmation token for a user by accessing UserManager directly.
    /// </summary>
    protected async Task<string> GenerateEmailConfirmationTokenAsync(string email, string? tenantIdentifier = null)
    {
        tenantIdentifier ??= IdmtApiFactory.DefaultTenantIdentifier;

        using var scope = Factory.Services.CreateScope();
        var provider = scope.ServiceProvider;

        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(tenantIdentifier)
            ?? throw new InvalidOperationException($"Tenant '{tenantIdentifier}' not found.");

        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);

        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
        var user = await userManager.FindByEmailAsync(email)
            ?? throw new InvalidOperationException($"User with email '{email}' not found.");

        return await userManager.GenerateEmailConfirmationTokenAsync(user);
    }

    /// <summary>
    /// Base64URL-encodes a token for use with API endpoints that expect encoded tokens.
    /// </summary>
    protected static string EncodeToken(string token)
        => Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
}
