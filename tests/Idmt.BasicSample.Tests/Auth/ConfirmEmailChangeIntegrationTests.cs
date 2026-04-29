using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.BasicSample.Tests.Auth;

/// <summary>
/// Integration tests for POST /auth/confirm-email-change (Phase 1, Step 7).
/// </summary>
public class ConfirmEmailChangeIntegrationTests : BaseIntegrationTest
{
    public ConfirmEmailChangeIntegrationTests(IdmtApiFactory factory) : base(factory) { }

    [Fact]
    public async Task POST_ConfirmEmailChange_ValidToken_CommitsEmail_ClearsPendingEmail()
    {
        var (email, _, client) = await SetupAuthenticatedUserAsync();
        var newEmail = $"new-{Guid.NewGuid():N}@example.com";

        Factory.EmailSenderMock.Invocations.Clear();

        // Stage the email change
        var stageResponse = await client.PutAsJsonAsync("/manage/info", new { NewEmail = newEmail });
        Assert.Equal(HttpStatusCode.Accepted, stageResponse.StatusCode);

        var (capturedCurrent, capturedNew, capturedEncodedToken) = ExtractCapturedConfirmEmailChangeLink();
        Assert.Equal(email, capturedCurrent);
        Assert.Equal(newEmail, capturedNew);

        // Confirm
        using var publicClient = Factory.CreateClientWithTenant();
        var confirmResponse = await publicClient.PostAsJsonAsync("/auth/confirm-email-change", new
        {
            Email = email,
            NewEmail = newEmail,
            Token = capturedEncodedToken
        });

        await confirmResponse.AssertSuccess();

        // After confirmation: Email column = newEmail; PendingEmail = null.
        var (committedEmail, pendingEmail) = await GetUserEmailStateAsync(newEmail);
        Assert.Equal(newEmail, committedEmail);
        Assert.Null(pendingEmail);
    }

    [Fact]
    public async Task POST_ConfirmEmailChange_NoPendingEmail_Returns400_NoPendingChange()
    {
        var (email, _, _) = await SetupAuthenticatedUserAsync();

        using var publicClient = Factory.CreateClientWithTenant();
        var confirmResponse = await publicClient.PostAsJsonAsync("/auth/confirm-email-change", new
        {
            Email = email,
            NewEmail = $"unrelated-{Guid.NewGuid():N}@example.com",
            // Token is required by validation but won't be exercised since PendingEmail is null.
            Token = EncodeToken("any-token")
        });

        Assert.Equal(HttpStatusCode.BadRequest, confirmResponse.StatusCode);
    }

    [Fact]
    public async Task POST_ConfirmEmailChange_InvalidToken_Returns400_ConfirmationFailed_PendingEmailIntact()
    {
        var (email, _, client) = await SetupAuthenticatedUserAsync();
        var newEmail = $"new-{Guid.NewGuid():N}@example.com";

        Factory.EmailSenderMock.Invocations.Clear();

        // Stage the email change
        var stageResponse = await client.PutAsJsonAsync("/manage/info", new { NewEmail = newEmail });
        Assert.Equal(HttpStatusCode.Accepted, stageResponse.StatusCode);

        // Confirm with an invalid (but well-formed Base64URL) token
        using var publicClient = Factory.CreateClientWithTenant();
        var confirmResponse = await publicClient.PostAsJsonAsync("/auth/confirm-email-change", new
        {
            Email = email,
            NewEmail = newEmail,
            Token = EncodeToken("invalid-token-payload")
        });

        Assert.Equal(HttpStatusCode.BadRequest, confirmResponse.StatusCode);

        // PendingEmail must remain set (still staged) and Email column unchanged.
        var (committedEmail, pendingEmail) = await GetUserEmailStateAsync(email);
        Assert.Equal(email, committedEmail);
        Assert.Equal(newEmail, pendingEmail);
    }

    private async Task<(string Email, string Password, HttpClient Client)> SetupAuthenticatedUserAsync()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"emailchange-{Guid.NewGuid():N}@example.com";
        var password = "InitialP@ss1!";

        await RegisterAndSetPasswordAsync(
            sysClient,
            password,
            email: email,
            username: $"emailchange{Guid.NewGuid():N}",
            role: IdmtDefaultRoleTypes.TenantAdmin);

        await ConfirmEmailDirectAsync(email);

        var loginClient = Factory.CreateClientWithTenant();
        var loginResponse = await loginClient.PostAsJsonAsync("/auth/token", new { Email = email, Password = password });
        await loginResponse.AssertSuccess();
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        loginClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        return (email, password, loginClient);
    }

    private async Task ConfirmEmailDirectAsync(string email)
    {
        using var scope = Factory.Services.CreateScope();
        var provider = scope.ServiceProvider;
        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(IdmtApiFactory.DefaultTenantIdentifier)
            ?? throw new InvalidOperationException("Default tenant missing.");
        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);

        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
        var user = await userManager.FindByEmailAsync(email)
            ?? throw new InvalidOperationException($"User '{email}' not found.");
        if (!user.EmailConfirmed)
        {
            user.EmailConfirmed = true;
            await userManager.UpdateAsync(user);
        }
    }

    private async Task<(string? Email, string? PendingEmail)> GetUserEmailStateAsync(string lookupEmail)
    {
        using var scope = Factory.Services.CreateScope();
        var provider = scope.ServiceProvider;
        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(IdmtApiFactory.DefaultTenantIdentifier)
            ?? throw new InvalidOperationException("Default tenant missing.");
        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);

        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
        var user = await userManager.FindByEmailAsync(lookupEmail);
        return (user?.Email, user?.PendingEmail);
    }

    private (string CurrentEmail, string NewEmail, string EncodedToken) ExtractCapturedConfirmEmailChangeLink()
    {
        var invocation = Factory.EmailSenderMock.Invocations
            .Where(i => i.Method.Name == nameof(IEmailSender<IdmtUser>.SendConfirmationLinkAsync))
            .LastOrDefault()
            ?? throw new InvalidOperationException("No SendConfirmationLinkAsync invocation captured.");

        var link = (string)invocation.Arguments[2];
        var uri = new Uri(link);
        var query = QueryHelpers.ParseQuery(uri.Query);

        return (
            query["email"].ToString(),
            query["newEmail"].ToString(),
            query["token"].ToString());
    }
}
