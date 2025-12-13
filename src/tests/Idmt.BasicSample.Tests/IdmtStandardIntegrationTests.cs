using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Auth.Manage;
using Idmt.Plugin.Features.Sys;
using Idmt.Plugin.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.WebUtilities;

namespace Idmt.BasicSample.Tests;

public class IdmtStandardIntegrationTests : IClassFixture<IdmtApiFactory>
{
    private readonly IdmtApiFactory _factory;

    public IdmtStandardIntegrationTests(IdmtApiFactory factory)
    {
        _factory = factory;
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

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.AccessToken);
        var refreshedSelfInfo = await client.GetAsync("/auth/manage/info");
        await refreshedSelfInfo.AssertSuccess();
    }

    [Fact]
    public async Task Register_reset_login_and_update_user_flow_works()
    {
        var newEmail = $"user-{Guid.NewGuid():N}@example.com";
        var newUsername = $"user{Guid.NewGuid():N}";
        RegisterUser.RegisterUserResponse? register = null;
        {
            using var sysClient = await CreateAuthenticatedClientAsync();

            var registerResponse = await sysClient.PostAsJsonAsync("/auth/manage/users", new
            {
                Email = newEmail,
                Username = newUsername,
                Role = IdmtDefaultRoleTypes.TenantAdmin
            });
            await registerResponse.AssertSuccess();

            register = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
            Assert.NotNull(register);
            Assert.True(register!.Success);
            Assert.False(string.IsNullOrWhiteSpace(register.UserId));
            Assert.False(string.IsNullOrWhiteSpace(register.PasswordSetupToken));
        }
        Assert.NotNull(register);
        {
            using var userClient = _factory.CreateClient();

            var resetPasswordUrl = QueryHelpers.AddQueryString(
                "/auth/resetPassword",
                new Dictionary<string, string?>
                {
                    ["tenantId"] = IdmtApiFactory.DefaultTenantId,
                    ["email"] = newEmail,
                    ["token"] = register.PasswordSetupToken,
                });
            var resetResponse = await userClient.PostAsJsonAsync(resetPasswordUrl, new
            {
                NewPassword = "UserPassword1!"
            });
            await resetResponse.AssertSuccess();
        }
        {
            using var userClient = _factory.CreateClientWithTenant();
            var userLogin = await userClient.PostAsJsonAsync("/auth/login?useCookies=true", new
            {
                EmailOrUsername = newEmail,
                Password = "UserPassword1!"
            });
            await userLogin.AssertSuccess();

            var userInfo = await userClient.GetFromJsonAsync<GetUserInfo.GetUserInfoResponse>("/auth/manage/info");
            Assert.NotNull(userInfo);
            Assert.Equal(newEmail, userInfo!.Email);
            Assert.Equal(IdmtDefaultRoleTypes.TenantAdmin, userInfo.Role);

            var updateResponse = await userClient.PutAsJsonAsync("/auth/manage/info", new
            {
                OldPassword = "UserPassword1!",
                NewPassword = "UserPassword2!"
            });
            await updateResponse.AssertSuccess();

            var reLogin = await userClient.PostAsJsonAsync("/auth/login?useCookies=true", new
            {
                EmailOrUsername = newEmail,
                Password = "UserPassword2!"
            });
            await reLogin.AssertSuccess();

            var unregisterResponse = await userClient.DeleteAsync($"/auth/manage/users/{Uri.EscapeDataString(register.UserId)}");
            await unregisterResponse.AssertSuccess();
        }
    }

    [Fact]
    public async Task Sys_endpoints_grant_and_revoke_tenant_access()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var targetEmail = $"tenant-{Guid.NewGuid():N}@example.com";

        var registerResponse = await sysClient.PostAsJsonAsync("/auth/manage/users", new
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

        // Verify that the user is logged out, selfInfo should return a 401
        var selfInfo = await client.GetAsync("/auth/manage/info");
        Assert.False(selfInfo.IsSuccessStatusCode);
    }

    private async Task<HttpClient> CreateAuthenticatedClientAsync()
    {
        var client = _factory.CreateClientWithTenant();
        await AssertDefaultTenantExistsAsync();
        Assert.Contains("__tenant__", client.DefaultRequestHeaders.Select(h => h.Key));
        var loginResponse = await client.PostAsJsonAsync("/auth/login?useCookies=true", new
        {
            EmailOrUsername = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        await loginResponse.AssertSuccess();
        return client;
    }

    private async Task AssertDefaultTenantExistsAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var tenantStore = scope.ServiceProvider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await tenantStore.TryGetAsync(IdmtApiFactory.DefaultTenantId);
        Assert.NotNull(tenant);
    }
}
