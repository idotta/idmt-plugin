using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Auth.Manage;
using Idmt.Plugin.Features.Sys;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Moq;

namespace Idmt.BasicSample.Tests;

public class IdmtStandardIntegrationTests : IClassFixture<IdmtApiFactory>, IDisposable
{
    private readonly IdmtApiFactory _factory;

    public IdmtStandardIntegrationTests(IdmtApiFactory factory)
    {
        _factory = factory;
        _factory.EmailSenderMock.Reset();
    }

    public void Dispose()
    {
        _factory.EmailSenderMock.Reset();
    }

    [Fact]
    public async Task Healthz_requires_authentication()
    {
        var client = _factory.CreateClientWithTenant();
        var response = await client.GetAsync("/healthz");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    [Fact]
    public async Task Healthz_allows_sys_user()
    {
        var client = await CreateAuthenticatedClientAsync();
        var response = await client.GetAsync("/healthz");
        await response.AssertSuccess();
    }

    [Fact]
    public async Task Sys_info_returns_current_tenant()
    {
        var client = await CreateAuthenticatedClientAsync();
        var systemInfo = await client.GetFromJsonAsync<SystemInfoResponse>("/sys/info");

        Assert.NotNull(systemInfo);
        Assert.NotNull(systemInfo!.CurrentTenant);
        Assert.Equal(IdmtApiFactory.DefaultTenantId, systemInfo.CurrentTenant!.Identifier);
    }

    [Fact]
    public async Task Auth_login_with_invalid_credentials_returns_unauthorized()
    {
        var client = _factory.CreateClientWithTenant();
        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            EmailOrUsername = IdmtApiFactory.SysAdminEmail,
            Password = "WrongPassword1!"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Auth_login_and_refresh_issue_tokens()
    {
        var client = _factory.CreateClientWithTenant();

        var loginResponse = await client.PostAsJsonAsync("/auth/login", new
        {
            EmailOrUsername = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        await loginResponse.AssertSuccess();

        var tokens = await loginResponse.Content.ReadFromJsonAsync<AccessTokenResponse>();
        Assert.NotNull(tokens);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var selfInfo = await client.GetAsync("/auth/manage/info");
        await selfInfo.AssertSuccess();

        var refreshResponse = await client.PostAsJsonAsync("/auth/refresh", new RefreshToken.RefreshTokenRequest(tokens.RefreshToken!));
        await refreshResponse.AssertSuccess();

        var refreshed = await refreshResponse.Content.ReadFromJsonAsync<AccessTokenResponse>();
        Assert.NotNull(refreshed);
        Assert.False(string.IsNullOrWhiteSpace(refreshed!.AccessToken));
        Assert.NotEqual(tokens.AccessToken, refreshed.AccessToken);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.AccessToken);
        var refreshedSelfInfo = await client.GetAsync("/auth/manage/info");
        await refreshedSelfInfo.AssertSuccess();
    }

    [Fact]
    public async Task User_lifecycle_flow_works()
    {
        // 1. Register User (as Admin)
        var newEmail = $"user-{Guid.NewGuid():N}@example.com";
        var newUsername = $"user{Guid.NewGuid():N}";
        
        using var sysClient = await CreateAuthenticatedClientAsync();
        var registerResponse = await sysClient.PostAsJsonAsync("/auth/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = newUsername,
            Role = IdmtDefaultRoleTypes.TenantUser
        });
        await registerResponse.AssertSuccess();
        
        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        Assert.NotNull(registerResult);
        
        // 2. Verify Email (Capture token from Mock)
        var setupToken = registerResult!.PasswordSetupToken;
        Assert.NotNull(setupToken);

        // 3. Set Password (Reset Password)
        using var userClient = _factory.CreateClient(); // No auth
        var resetPasswordUrl = QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
        {
            ["tenantId"] = IdmtApiFactory.DefaultTenantId,
            ["email"] = newEmail,
            ["token"] = setupToken
        });

        var resetResponse = await userClient.PostAsJsonAsync(resetPasswordUrl, new { NewPassword = "NewUserPassword1!" });
        await resetResponse.AssertSuccess();

        // 4. Login with new password
        using var userClientWithTenant = _factory.CreateClientWithTenant();
        var loginResponse = await userClientWithTenant.PostAsJsonAsync("/auth/login", new
        {
            EmailOrUsername = newEmail,
            Password = "NewUserPassword1!"
        });
        await loginResponse.AssertSuccess();
        var tokens = await loginResponse.Content.ReadFromJsonAsync<AccessTokenResponse>();
        userClientWithTenant.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        // 5. Update Info
        var updateResponse = await userClientWithTenant.PutAsJsonAsync("/auth/manage/info", new
        {
            OldPassword = "NewUserPassword1!",
            NewPassword = "NewUserPassword2!"
        });
        await updateResponse.AssertSuccess();

        // 6. Verify new password
        var reLoginResponse = await userClientWithTenant.PostAsJsonAsync("/auth/login", new
        {
            EmailOrUsername = newEmail,
            Password = "NewUserPassword2!"
        });
        await reLoginResponse.AssertSuccess();

        // 7. Unregister (Delete)
        var deleteResponse = await sysClient.DeleteAsync($"/auth/manage/users/{registerResult.UserId}");
        await deleteResponse.AssertSuccess();

        // 8. Verify deletion
        var failLogin = await userClientWithTenant.PostAsJsonAsync("/auth/login", new
        {
            EmailOrUsername = newEmail,
            Password = "NewUserPassword2!"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, failLogin.StatusCode);
    }

    [Fact]
    public async Task Forgot_password_flow_works()
    {
        // 1. Setup User
        var email = $"forgot-{Guid.NewGuid():N}@example.com";
        using var sysClient = await CreateAuthenticatedClientAsync();
        var registerResponse = await sysClient.PostAsJsonAsync("/auth/manage/users?useApiLinks=true", new
        {
            Email = email,
            Username = $"forgot{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantUser
        });
        await registerResponse.AssertSuccess();
        var reg = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();

        // Set initial password
        using var publicClient = _factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantId"] = IdmtApiFactory.DefaultTenantId,
                ["email"] = email,
                ["token"] = reg!.PasswordSetupToken
            }), 
            new { NewPassword = "InitialPassword1!" });

        // 2. Request Forgot Password
        _factory.EmailSenderMock.Invocations.Clear(); // Clear previous emails
        using var tenantClient = _factory.CreateClientWithTenant();
        var forgotResponse = await tenantClient.PostAsJsonAsync("/auth/forgotPassword?useApiLinks=true", new { Email = email });
        await forgotResponse.AssertSuccess();

        // 3. Verify Email Sent and Capture Token
        _factory.EmailSenderMock.Verify(x => x.SendPasswordResetCodeAsync(
            It.Is<IdmtUser>(u => u.Email == email), 
            It.IsAny<string>(), 
            It.IsAny<string>())
        , Times.Once);

        var invocation = _factory.EmailSenderMock.Invocations.First(i => i.Method.Name == nameof(IEmailSender<IdmtUser>.SendPasswordResetCodeAsync));
        var resetLinkEncoded = invocation.Arguments[2] as string; // The generated link (passed as code)
        var resetLink = WebUtility.HtmlDecode(resetLinkEncoded);
        Assert.NotNull(resetLink);
        
        // Extract token and params from link
        var uri = new Uri(resetLink!);
        var query = QueryHelpers.ParseQuery(uri.Query);
        var token = query["token"].ToString();
        var tenantId = query["tenantId"].ToString();

        // 4. Reset Password
        var resetResponse = await publicClient.PostAsJsonAsync(
             QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
             {
                 ["tenantId"] = tenantId,
                 ["email"] = email,
                 ["token"] = token
             }), 
             new { NewPassword = "ResetPassword1!" });
        await resetResponse.AssertSuccess();

        // 5. Login with new password
        var loginResponse = await tenantClient.PostAsJsonAsync("/auth/login", new
        {
            EmailOrUsername = email,
            Password = "ResetPassword1!"
        });
        await loginResponse.AssertSuccess();
    }

    [Fact]
    public async Task Sys_endpoints_grant_and_revoke_tenant_access()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var targetEmail = $"tenant-{Guid.NewGuid():N}@example.com";

        var registerResponse = await sysClient.PostAsJsonAsync("/auth/manage/users?useApiLinks=false", new
        {
            Email = targetEmail,
            Username = $"tenant{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        await registerResponse.AssertSuccess();

        var register = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        Assert.NotNull(register);
        var userId = Guid.Parse(register!.UserId!);

        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantId}",
            new { ExpiresAt = (DateTime?)null });
        await grantResponse.AssertSuccess();

        var tenants = await sysClient.GetFromJsonAsync<SysEndpoints.TenantInfoResponse[]>($"/sys/users/{userId}/tenants");
        Assert.NotNull(tenants);
        Assert.Contains(tenants!, t => t.Identifier == IdmtApiFactory.DefaultTenantId);

        var revokeResponse = await sysClient.DeleteAsync($"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantId}");
        await revokeResponse.AssertSuccess();

        tenants = await sysClient.GetFromJsonAsync<SysEndpoints.TenantInfoResponse[]>($"/sys/users/{userId}/tenants");
        Assert.NotNull(tenants);
        Assert.DoesNotContain(tenants!, t => t.Identifier == IdmtApiFactory.DefaultTenantId);
    }

    [Fact]
    public async Task Logout_clears_session()
    {
        var client = await CreateAuthenticatedClientAsync();

        var logoutResponse = await client.PostAsync("/auth/logout", content: null);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

        // Verify that the user is logged out, selfInfo should return a 401 or 302 (Redirect to login)
        var selfInfo = await client.GetAsync("/auth/manage/info");
        Assert.False(selfInfo.IsSuccessStatusCode);
        Assert.Contains(selfInfo.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Found, HttpStatusCode.SeeOther });
    }

    private async Task<HttpClient> CreateAuthenticatedClientAsync()
    {
        var client = _factory.CreateClientWithTenant();
        var loginResponse = await client.PostAsJsonAsync("/auth/login?useCookies=true", new
        {
            EmailOrUsername = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        await loginResponse.AssertSuccess();
        return client;
    }
}
