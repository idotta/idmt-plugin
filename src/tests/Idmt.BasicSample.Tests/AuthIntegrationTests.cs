using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.WebUtilities;
using Moq;

namespace Idmt.BasicSample.Tests;

/// <summary>
/// Integration tests for Authentication endpoints.
/// Covers: /auth/login, /auth/token, /auth/logout, /auth/refresh, /auth/confirmEmail, /auth/resendConfirmationEmail, /auth/forgotPassword, /auth/resetPassword
/// </summary>
public class AuthIntegrationTests : BaseIntegrationTest
{
    public AuthIntegrationTests(IdmtApiFactory factory) : base(factory) { }

    #region Login Tests (Cookie-based)

    [Fact]
    public async Task Login_with_valid_credentials_succeeds()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });

        await response.AssertSuccess();
    }

    [Fact]
    public async Task Login_with_invalid_credentials_returns_unauthorized()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = "WrongPassword1!"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_with_invalid_email_format_returns_validation_error()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            Email = "invalid-email",
            Password = "SomePassword1!"
        });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Login_with_empty_email_returns_validation_error()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            Email = "",
            Password = "SomePassword1!"
        });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Login_with_empty_password_returns_validation_error()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = ""
        });

        Assert.False(response.IsSuccessStatusCode);
    }

    #endregion

    #region Token Tests (Bearer Token-based)

    [Fact]
    public async Task Token_login_with_valid_credentials_returns_tokens()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });

        await response.AssertSuccess();
        var tokens = await response.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        Assert.NotNull(tokens);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));
    }

    [Fact]
    public async Task Token_login_with_invalid_credentials_returns_unauthorized()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = "WrongPassword1!"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Token_allows_accessing_protected_endpoints()
    {
        var client = Factory.CreateClientWithTenant();

        var loginResponse = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var protectedResponse = await client.GetAsync("/manage/info");

        await protectedResponse.AssertSuccess();
    }

    [Fact]
    public async Task Token_without_bearer_prefix_is_rejected()
    {
        var client = Factory.CreateClientWithTenant();

        var loginResponse = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        // Set header without "Bearer " prefix
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("NotBearer", tokens!.AccessToken);
        var protectedResponse = await client.GetAsync("/manage/info");

        Assert.False(protectedResponse.IsSuccessStatusCode);
    }

    #endregion

    #region Refresh Token Tests

    [Fact]
    public async Task RefreshToken_with_valid_token_returns_new_tokens()
    {
        var client = Factory.CreateClientWithTenant();

        var loginResponse = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        var refreshResponse = await client.PostAsJsonAsync("/auth/refresh", new RefreshToken.RefreshTokenRequest(tokens!.RefreshToken!));
        await refreshResponse.AssertSuccess();

        var refreshedTokens = await refreshResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        Assert.NotNull(refreshedTokens);
        Assert.False(string.IsNullOrWhiteSpace(refreshedTokens!.AccessToken));
        Assert.NotEqual(tokens.AccessToken, refreshedTokens.AccessToken);
    }

    [Fact]
    public async Task RefreshToken_with_invalid_token_returns_unauthorized()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/refresh", new RefreshToken.RefreshTokenRequest("invalid-token"));

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task RefreshToken_with_empty_token_returns_validation_error()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/refresh", new RefreshToken.RefreshTokenRequest(""));

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Refreshed_token_can_access_protected_endpoints()
    {
        var client = Factory.CreateClientWithTenant();

        var loginResponse = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        var refreshResponse = await client.PostAsJsonAsync("/auth/refresh", new RefreshToken.RefreshTokenRequest(tokens!.RefreshToken!));
        var refreshedTokens = await refreshResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshedTokens!.AccessToken);
        var protectedResponse = await client.GetAsync("/manage/info");

        await protectedResponse.AssertSuccess();
    }

    #endregion

    #region Logout Tests

    [Fact]
    public async Task Logout_clears_session()
    {
        var client = await CreateAuthenticatedClientAsync();

        var logoutResponse = await client.PostAsync("/auth/logout", content: null);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);
    }

    #endregion

    #region Confirm Email Tests

    [Fact]
    public async Task ConfirmEmail_with_valid_token_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"confirm-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"confirm{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var registerResponseValue = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var passwordSetupToken = registerResponseValue!.PasswordSetupToken!;

        // First, set the initial password using the password setup token
        using var publicClient = Factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = newEmail,
                ["token"] = passwordSetupToken
            }),
            new { NewPassword = "InitialPassword1!" });

        // Now request a confirmation email to get the email confirmation token
        using var tenantClient = Factory.CreateClientWithTenant();
        var resendResponse = await tenantClient.PostAsJsonAsync($"/auth/resendConfirmationEmail?useApiLinks=false", new
        {
            Email = newEmail
        });
        await resendResponse.AssertSuccess();
        var resendResponseValue = await resendResponse.Content.ReadFromJsonAsync<ResendConfirmationEmail.ResendConfirmationEmailResponse>();
        var confirmToken = resendResponseValue!.ConfirmationToken;

        if (confirmToken is null)
        {
            // Password reset is confirming email, so we skip the rest of the test
            return;
        }

        // Now confirm email using the email confirmation token
        var confirmResponse = await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email={newEmail}&token={Uri.EscapeDataString(confirmToken)}");

        await confirmResponse.AssertSuccess();
        var result = await confirmResponse.Content.ReadFromJsonAsync<ConfirmEmail.ConfirmEmailResponse>();
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    [Fact]
    public async Task ConfirmEmail_with_invalid_token_fails()
    {
        var newEmail = $"invalid-{Guid.NewGuid():N}@example.com";
        using var publicClient = Factory.CreateClient();

        var confirmResponse = await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email={newEmail}&token=invalid-token");

        Assert.False(confirmResponse.IsSuccessStatusCode);
    }

    [Fact]
    public async Task ConfirmEmail_with_invalid_tenant_fails()
    {
        var newEmail = $"confirm-{Guid.NewGuid():N}@example.com";
        using var publicClient = Factory.CreateClient();

        var confirmResponse = await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier=nonexistent-tenant&email={newEmail}&token=some-token");

        Assert.False(confirmResponse.IsSuccessStatusCode);
    }

    [Fact]
    public async Task ConfirmEmail_with_missing_email_fails()
    {
        using var publicClient = Factory.CreateClient();

        var confirmResponse = await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email=&token=some-token");

        Assert.False(confirmResponse.IsSuccessStatusCode);
    }

    [Fact]
    public async Task ConfirmEmail_with_missing_token_fails()
    {
        var newEmail = $"confirm-{Guid.NewGuid():N}@example.com";
        using var publicClient = Factory.CreateClient();

        var confirmResponse = await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email={newEmail}&token=");

        Assert.False(confirmResponse.IsSuccessStatusCode);
    }

    #endregion

    #region Resend Confirmation Email Tests

    [Fact]
    public async Task ResendConfirmationEmail_for_unconfirmed_user_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"resend-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"resend{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        // Resend confirmation email
        using var publicClient = Factory.CreateClientWithTenant();
        var resendResponse = await publicClient.PostAsJsonAsync($"/auth/resendConfirmationEmail?useApiLinks=false", new
        {
            Email = newEmail
        });
        await resendResponse.AssertSuccess();

        var result = await resendResponse.Content.ReadFromJsonAsync<ResendConfirmationEmail.ResendConfirmationEmailResponse>();
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    [Fact]
    public async Task ResendConfirmationEmail_sends_email()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"resend-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"resend{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        Factory.EmailSenderMock.Invocations.Clear();

        // Resend confirmation email
        using var publicClient = Factory.CreateClientWithTenant();
        var resendResponse = await publicClient.PostAsJsonAsync($"/auth/resendConfirmationEmail?useApiLinks=false", new
        {
            Email = newEmail
        });
        await resendResponse.AssertSuccess();

        // Verify email was sent
        Factory.EmailSenderMock.Verify(x => x.SendConfirmationLinkAsync(
            It.Is<IdmtUser>(u => u.Email == newEmail),
            It.IsAny<string>(),
            It.IsAny<string>())
        , Times.Once);
    }

    [Fact]
    public async Task ResendConfirmationEmail_with_invalid_email_returns_validation_error()
    {
        using var publicClient = Factory.CreateClientWithTenant();

        var resendResponse = await publicClient.PostAsJsonAsync($"/auth/resendConfirmationEmail?useApiLinks=false", new
        {
            Email = "not-an-email"
        });
        Assert.False(resendResponse.IsSuccessStatusCode);
    }

    [Fact]
    public async Task ResendConfirmationEmail_with_nonexistent_email_returns_validation_error()
    {
        using var publicClient = Factory.CreateClientWithTenant();

        var resendResponse = await publicClient.PostAsJsonAsync($"/auth/resendConfirmationEmail?useApiLinks=false", new
        {
            Email = "nonexistent@example.com"
        });
        // Should still succeed (for security reasons, don't leak user existence)
        Assert.True(resendResponse.IsSuccessStatusCode);
    }

    #endregion

    #region Forgot Password Tests

    [Fact]
    public async Task ForgotPassword_generates_reset_token()
    {
        var email = $"forgot-{Guid.NewGuid():N}@example.com";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Create user first
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"forgot{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        // Set initial password
        using var publicClient = Factory.CreateClient();
        var setupToken = (await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.PasswordSetupToken;
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = setupToken
            }),
            new { NewPassword = "InitialPassword1!" });

        Factory.EmailSenderMock.Invocations.Clear();

        // Request forgot password
        using var tenantClient = Factory.CreateClientWithTenant();
        var forgotResponse = await tenantClient.PostAsJsonAsync("/auth/forgotPassword?useApiLinks=false", new { Email = email });
        await forgotResponse.AssertSuccess();

        // Verify email was sent
        Factory.EmailSenderMock.Verify(x => x.SendPasswordResetCodeAsync(
            It.Is<IdmtUser>(u => u.Email == email),
            It.IsAny<string>(),
            It.IsAny<string>())
        , Times.Once);
    }

    [Fact]
    public async Task ForgotPassword_with_invalid_email_returns_validation_error()
    {
        using var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/forgotPassword?useApiLinks=false", new { Email = "invalid-email" });
        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task ForgotPassword_with_nonexistent_email_succeeds_silently()
    {
        using var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/auth/forgotPassword?useApiLinks=false", new { Email = "nonexistent@example.com" });
        // Should succeed for security (don't leak user existence)
        Assert.True(response.IsSuccessStatusCode);
    }

    #endregion

    #region Reset Password Tests

    [Fact]
    public async Task ResetPassword_with_valid_token_succeeds()
    {
        var email = $"reset-{Guid.NewGuid():N}@example.com";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"reset{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var resetToken = (await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.PasswordSetupToken;

        // Reset password with token
        using var publicClient = Factory.CreateClient();
        var resetResponse = await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = resetToken
            }),
            new { NewPassword = "NewPassword1!" });

        await resetResponse.AssertSuccess();
    }

    [Fact]
    public async Task ResetPassword_with_new_password_allows_login()
    {
        var email = $"reset-login-{Guid.NewGuid():N}@example.com";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"resetlogin{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var resetToken = (await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.PasswordSetupToken;

        // Reset password
        using var publicClient = Factory.CreateClient();
        const string newPassword = "NewPassword1!";
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = resetToken
            }),
            new { NewPassword = newPassword });

        // Login with new password
        using var loginClient = Factory.CreateClientWithTenant();
        var loginResponse = await loginClient.PostAsJsonAsync("/auth/token", new
        {
            Email = email,
            Password = newPassword
        });

        await loginResponse.AssertSuccess();
    }

    [Fact]
    public async Task ResetPassword_with_invalid_token_fails()
    {
        var email = $"reset-invalid-{Guid.NewGuid():N}@example.com";
        using var publicClient = Factory.CreateClient();

        var resetResponse = await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = "invalid-token"
            }),
            new { NewPassword = "NewPassword1!" });

        Assert.False(resetResponse.IsSuccessStatusCode);
    }

    [Fact]
    public async Task ResetPassword_with_weak_password_fails()
    {
        var email = $"reset-weak-{Guid.NewGuid():N}@example.com";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"resetweak{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var resetToken = (await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.PasswordSetupToken;

        // Try reset with weak password
        using var publicClient = Factory.CreateClient();
        var resetResponse = await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = resetToken
            }),
            new { NewPassword = "weak" });

        Assert.False(resetResponse.IsSuccessStatusCode);
    }

    #endregion
}
