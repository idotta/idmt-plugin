using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Idmt.BasicSample.Tests.Manage;

/// <summary>
/// Integration tests for PUT /manage/info email-change staging (Phase 1, Step 7).
/// </summary>
public class UpdateUserInfoEmailChangeTests : BaseIntegrationTest
{
    public UpdateUserInfoEmailChangeTests(IdmtApiFactory factory) : base(factory) { }

    [Fact]
    public async Task PUT_UpdateUserInfo_EmailChangeRequested_Returns202_StagesPendingEmail()
    {
        var (email, _, client) = await SetupAuthenticatedUserAsync();
        var newEmail = $"new-{Guid.NewGuid():N}@example.com";

        Factory.EmailSenderMock.Invocations.Clear();

        var response = await client.PutAsJsonAsync("/manage/info", new
        {
            NewEmail = newEmail
        });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        var pendingEmail = await GetPendingEmailAsync(email);
        Assert.Equal(newEmail, pendingEmail);
    }

    [Fact]
    public async Task PUT_UpdateUserInfo_EmailChangeRequested_SendsEmailToNewAddress()
    {
        var (_, _, client) = await SetupAuthenticatedUserAsync();
        var newEmail = $"new-{Guid.NewGuid():N}@example.com";

        Factory.EmailSenderMock.Invocations.Clear();

        var response = await client.PutAsJsonAsync("/manage/info", new
        {
            NewEmail = newEmail
        });

        await response.AssertSuccess();
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        // Confirmation link must be dispatched to the NEW address (not the current).
        Factory.EmailSenderMock.Verify(x => x.SendConfirmationLinkAsync(
            It.Is<IdmtUser>(u => u.PendingEmail == newEmail),
            newEmail,
            It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task PUT_UpdateUserInfo_EmailChangeRequested_DoesNotMutateEmailColumn()
    {
        var (email, _, client) = await SetupAuthenticatedUserAsync();
        var newEmail = $"new-{Guid.NewGuid():N}@example.com";

        var response = await client.PutAsJsonAsync("/manage/info", new
        {
            NewEmail = newEmail
        });

        await response.AssertSuccess();

        // Critical invariant: the user.Email column is NOT mutated until ConfirmEmailChange runs.
        var currentEmail = await GetEmailAsync(email);
        Assert.Equal(email, currentEmail);

        var pending = await GetPendingEmailAsync(email);
        Assert.Equal(newEmail, pending);
    }

    /// <summary>
    /// F25 integration regression: PUT with both new password + new email must produce a
    /// confirmation token that validates at the confirm endpoint AFTER ChangePasswordAsync
    /// rotated SecurityStamp (invariant 5a).
    /// </summary>
    [Fact]
    public async Task PUT_UpdateUserInfo_PasswordAndEmailChange_TokenValidAtConfirmTime()
    {
        var (email, oldPassword, client) = await SetupAuthenticatedUserAsync();
        var newEmail = $"new-{Guid.NewGuid():N}@example.com";
        var newPassword = "BrandNewP@ss1!";

        Factory.EmailSenderMock.Invocations.Clear();

        var response = await client.PutAsJsonAsync("/manage/info", new
        {
            OldPassword = oldPassword,
            NewPassword = newPassword,
            NewEmail = newEmail
        });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        // Extract token from captured email
        var (capturedCurrent, capturedNew, capturedEncodedToken) = ExtractCapturedConfirmEmailChangeLink();
        Assert.Equal(email, capturedCurrent);
        Assert.Equal(newEmail, capturedNew);

        // Confirm the staged change. If invariant 5a is broken, the token will be invalid.
        using var publicClient = Factory.CreateClientWithTenant();
        var confirmResponse = await publicClient.PostAsJsonAsync("/auth/confirm-email-change", new
        {
            Email = email,
            NewEmail = newEmail,
            Token = capturedEncodedToken
        });

        await confirmResponse.AssertSuccess();

        var finalEmail = await GetEmailByIdAsync(email, originalEmail: email, fallback: newEmail);
        Assert.Equal(newEmail, finalEmail);
    }

    /// <summary>
    /// F44 integration regression: same as above but with username + email change.
    /// </summary>
    [Fact]
    public async Task PUT_UpdateUserInfo_UsernameAndEmailChange_TokenValidAtConfirmTime()
    {
        var (email, _, client) = await SetupAuthenticatedUserAsync();
        var newEmail = $"new-{Guid.NewGuid():N}@example.com";
        var newUsername = $"newuser{Guid.NewGuid():N}";

        Factory.EmailSenderMock.Invocations.Clear();

        var response = await client.PutAsJsonAsync("/manage/info", new
        {
            NewUsername = newUsername,
            NewEmail = newEmail
        });

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        var (capturedCurrent, capturedNew, capturedEncodedToken) = ExtractCapturedConfirmEmailChangeLink();
        Assert.Equal(email, capturedCurrent);
        Assert.Equal(newEmail, capturedNew);

        using var publicClient = Factory.CreateClientWithTenant();
        var confirmResponse = await publicClient.PostAsJsonAsync("/auth/confirm-email-change", new
        {
            Email = email,
            NewEmail = newEmail,
            Token = capturedEncodedToken
        });

        await confirmResponse.AssertSuccess();
    }

    /// <summary>
    /// Sets up a fresh user with a known password and returns an authenticated client.
    /// </summary>
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

        // Confirm the email so SignIn requireConfirmedEmail passes.
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

    private async Task<string?> GetPendingEmailAsync(string email)
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
        return user.PendingEmail;
    }

    private async Task<string?> GetEmailAsync(string email)
    {
        using var scope = Factory.Services.CreateScope();
        var provider = scope.ServiceProvider;
        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(IdmtApiFactory.DefaultTenantIdentifier)
            ?? throw new InvalidOperationException("Default tenant missing.");
        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);

        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
        var user = await userManager.FindByEmailAsync(email);
        return user?.Email;
    }

    /// <summary>
    /// Looks up a user by either originalEmail or fallback (after a successful change).
    /// </summary>
    private async Task<string?> GetEmailByIdAsync(string idLookupEmail, string originalEmail, string fallback)
    {
        using var scope = Factory.Services.CreateScope();
        var provider = scope.ServiceProvider;
        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(IdmtApiFactory.DefaultTenantIdentifier)
            ?? throw new InvalidOperationException("Default tenant missing.");
        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);

        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
        var user = await userManager.FindByEmailAsync(fallback) ?? await userManager.FindByEmailAsync(originalEmail);
        return user?.Email;
    }

    /// <summary>
    /// Extracts (currentEmail, newEmail, encodedToken) from the most recent
    /// SendConfirmationLinkAsync invocation captured by the EmailSenderMock.
    /// </summary>
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
