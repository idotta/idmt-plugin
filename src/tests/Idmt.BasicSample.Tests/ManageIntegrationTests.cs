using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.WebUtilities;

namespace Idmt.BasicSample.Tests;

/// <summary>
/// Integration tests for User Management endpoints.
/// Covers: /manage/users (register), /manage/users/{userId} (update/delete), /manage/info (get/update)
/// </summary>
public class ManageIntegrationTests : BaseIntegrationTest
{
    public ManageIntegrationTests(IdmtApiFactory factory) : base(factory) { }

    #region Register User Tests

    [Fact]
    public async Task RegisterUser_with_valid_data_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"user-{Guid.NewGuid():N}@example.com";

        var response = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"user{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        await response.AssertSuccess();
        var result = await response.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        Assert.NotNull(result);
        Assert.NotNull(result!.UserId);
        Assert.NotNull(result.PasswordSetupToken);
    }

    [Fact]
    public async Task RegisterUser_returns_setup_token()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"token-{Guid.NewGuid():N}@example.com";

        var response = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"token{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        var result = await response.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        Assert.False(string.IsNullOrWhiteSpace(result!.PasswordSetupToken));
    }

    [Fact]
    public async Task RegisterUser_with_duplicate_email_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"duplicate-{Guid.NewGuid():N}@example.com";

        // Register first user
        await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"user1{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        // Try to register with same email
        var response = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"user2{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task RegisterUser_with_duplicate_username_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var username = $"dupuser{Guid.NewGuid():N}";

        // Register first user
        await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = $"email1-{Guid.NewGuid():N}@example.com",
            Username = username,
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        // Try to register with same username
        var response = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = $"email2-{Guid.NewGuid():N}@example.com",
            Username = username,
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task RegisterUser_with_invalid_email_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = "not-an-email",
            Username = $"user{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task RegisterUser_with_empty_email_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = "",
            Username = $"user{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task RegisterUser_with_empty_username_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = $"user-{Guid.NewGuid():N}@example.com",
            Username = "",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task RegisterUser_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = $"user-{Guid.NewGuid():N}@example.com",
            Username = $"user{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });

        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region Unregister User Tests

    [Fact]
    public async Task UnregisterUser_with_valid_id_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"unregister-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"unreg{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Unregister user
        var deleteResponse = await sysClient.DeleteAsync($"/manage/users/{userId}");
        await deleteResponse.AssertSuccess();
    }

    [Fact]
    public async Task UnregisterUser_with_nonexistent_id_returns_error()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.DeleteAsync($"/manage/users/{Guid.NewGuid()}");
        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task UnregisterUser_prevents_login_after_deletion()
    {
        var email = $"deleted-{Guid.NewGuid():N}@example.com";
        var password = "TempPassword1!";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"deleted{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var registerResponseValue = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var resetToken = registerResponseValue!.PasswordSetupToken;
        var userId = Guid.Parse(registerResponseValue!.UserId!);

        // Set password
        using var publicClient = Factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = resetToken
            }),
            new { NewPassword = password });

        // Verify login works
        var loginClient = Factory.CreateClientWithTenant();
        var loginBefore = await loginClient.PostAsJsonAsync("/auth/token", new { Email = email, Password = password });
        await loginBefore.AssertSuccess();

        // Unregister user
        await sysClient.DeleteAsync($"/manage/users/{userId}");

        // Verify login fails
        var loginAfter = await loginClient.PostAsJsonAsync("/auth/token", new { Email = email, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, loginAfter.StatusCode);
    }

    [Fact]
    public async Task UnregisterUser_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.DeleteAsync($"/manage/users/{Guid.NewGuid()}");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region Update User Tests

    [Fact]
    public async Task UpdateUser_deactivate_user_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"deactivate-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"deact{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Deactivate user
        var updateResponse = await sysClient.PutAsJsonAsync($"/manage/users/{userId}", new { IsActive = false });
        await updateResponse.AssertSuccess();
    }

    [Fact]
    public async Task UpdateUser_reactivate_user_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"reactivate-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"reactiv{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Deactivate
        await sysClient.PutAsJsonAsync($"/manage/users/{userId}", new { IsActive = false });

        // Reactivate
        var reactivateResponse = await sysClient.PutAsJsonAsync($"/manage/users/{userId}", new { IsActive = true });
        await reactivateResponse.AssertSuccess();
    }

    [Fact]
    public async Task UpdateUser_prevents_login_when_deactivated()
    {
        var email = $"deactivated-login-{Guid.NewGuid():N}@example.com";
        var password = "TempPassword1!";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"deactlogin{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var registerResponseValue = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var resetToken = registerResponseValue!.PasswordSetupToken;
        var userId = Guid.Parse(registerResponseValue!.UserId!);

        // Set password
        using var publicClient = Factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = resetToken
            }),
            new { NewPassword = password });

        // Deactivate user
        await sysClient.PutAsJsonAsync($"/manage/users/{userId}", new { IsActive = false });

        // Try to login
        var loginClient = Factory.CreateClientWithTenant();
        var loginResponse = await loginClient.PostAsJsonAsync("/auth/token", new { Email = email, Password = password });
        Assert.False(loginResponse.IsSuccessStatusCode);
    }

    [Fact]
    public async Task UpdateUser_with_nonexistent_id_returns_error()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.PutAsJsonAsync($"/manage/users/{Guid.NewGuid()}", new { IsActive = false });
        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task UpdateUser_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PutAsJsonAsync($"/manage/users/{Guid.NewGuid()}", new { IsActive = false });
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region Get User Info Tests

    [Fact]
    public async Task GetUserInfo_returns_authenticated_user_details()
    {
        var client = await CreateAuthenticatedClientAsync();

        var response = await client.GetAsync("/manage/info");
        await response.AssertSuccess();

        var userInfo = await response.Content.ReadFromJsonAsync<GetUserInfo.GetUserInfoResponse>();
        Assert.NotNull(userInfo);
        Assert.Equal(IdmtApiFactory.SysAdminEmail, userInfo!.Email);
        Assert.NotEmpty(userInfo.Id);
        Assert.NotEmpty(userInfo.Role);
        Assert.NotEmpty(userInfo.TenantIdentifier);
    }

    [Fact]
    public async Task GetUserInfo_returns_correct_role()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"role-{Guid.NewGuid():N}@example.com";

        // Register user with TenantAdmin role
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"role{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var resetToken = (await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.PasswordSetupToken;

        // Set password and login
        using var publicClient = Factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = resetToken
            }),
            new { NewPassword = "Password1!" });

        var loginClient = Factory.CreateClientWithTenant();
        var loginResponse = await loginClient.PostAsJsonAsync("/auth/token", new { Email = email, Password = "Password1!" });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        loginClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var infoResponse = await loginClient.GetAsync("/manage/info");
        var info = await infoResponse.Content.ReadFromJsonAsync<GetUserInfo.GetUserInfoResponse>();

        Assert.Equal(IdmtDefaultRoleTypes.TenantAdmin, info!.Role);
    }

    [Fact]
    public async Task GetUserInfo_requires_authentication()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.GetAsync("/manage/info");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    #endregion

    #region Update User Info Tests

    [Fact]
    public async Task UpdateUserInfo_change_password_succeeds()
    {
        var email = $"pwd-change-{Guid.NewGuid():N}@example.com";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Register and setup user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"pwdchange{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var setupToken = (await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.PasswordSetupToken;

        using var publicClient = Factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = setupToken
            }),
            new { NewPassword = "OldPassword1!" });

        // Login and change password
        var loginClient = Factory.CreateClientWithTenant();
        var loginResponse = await loginClient.PostAsJsonAsync("/auth/token", new { Email = email, Password = "OldPassword1!" });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        loginClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var updateResponse = await loginClient.PutAsJsonAsync("/manage/info", new
        {
            OldPassword = "OldPassword1!",
            NewPassword = "NewPassword1!"
        });
        await updateResponse.AssertSuccess();

        // Verify new password works
        using var newLoginClient = Factory.CreateClientWithTenant();
        var newLoginResponse = await newLoginClient.PostAsJsonAsync("/auth/token", new
        {
            Email = email,
            Password = "NewPassword1!"
        });
        await newLoginResponse.AssertSuccess();
    }

    [Fact]
    public async Task UpdateUserInfo_change_password_requires_old_password()
    {
        var email = $"pwd-verify-{Guid.NewGuid():N}@example.com";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Register and setup user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"pwdverify{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var setupToken = (await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.PasswordSetupToken;

        using var publicClient = Factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = setupToken
            }),
            new { NewPassword = "CurrentPassword1!" });

        // Login
        var loginClient = Factory.CreateClientWithTenant();
        var loginResponse = await loginClient.PostAsJsonAsync("/auth/token", new { Email = email, Password = "CurrentPassword1!" });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        // Try to change password with wrong old password
        loginClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var updateResponse = await loginClient.PutAsJsonAsync("/manage/info", new
        {
            OldPassword = "WrongPassword1!",
            NewPassword = "NewPassword1!"
        });
        Assert.False(updateResponse.IsSuccessStatusCode);
    }

    [Fact]
    public async Task UpdateUserInfo_change_username_succeeds()
    {
        var email = $"username-{Guid.NewGuid():N}@example.com";
        var oldUsername = $"user{Guid.NewGuid():N}";
        var newUsername = $"user{Guid.NewGuid():N}";
        var sysClient = await CreateAuthenticatedClientAsync();

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = oldUsername,
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        var setupToken = (await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.PasswordSetupToken;

        using var publicClient = Factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = setupToken
            }),
            new { NewPassword = "Password1!" });

        // Login and change username
        var loginClient = Factory.CreateClientWithTenant();
        var loginResponse = await loginClient.PostAsJsonAsync("/auth/token", new { Email = email, Password = "Password1!" });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        loginClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var updateResponse = await loginClient.PutAsJsonAsync("/manage/info", new { NewUsername = newUsername });
        await updateResponse.AssertSuccess();
    }

    [Fact]
    public async Task UpdateUserInfo_requires_authentication()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PutAsJsonAsync("/manage/info", new { OldPassword = "Old1!", NewPassword = "New1!" });
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    #endregion
}
