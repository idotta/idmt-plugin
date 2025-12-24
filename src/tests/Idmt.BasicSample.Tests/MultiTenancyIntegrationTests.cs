using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Features.Sys;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.BasicSample.Tests;

/// <summary>
/// Integration tests for Multi-Tenancy isolation and security.
/// Ensures users cannot access or interfere with other tenants' data.
/// </summary>
public class MultiTenancyIntegrationTests : BaseIntegrationTest
{
    private const string TenantA = "tenant-a";
    private const string TenantB = "tenant-b";

    public MultiTenancyIntegrationTests(IdmtApiFactory factory) : base(factory) { }

    private async Task EnsureTenantsExistAsync()
    {
        using var scope = Factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();

        await handler.HandleAsync(new CreateTenant.CreateTenantRequest(TenantA, TenantA, "Tenant A"));
        await handler.HandleAsync(new CreateTenant.CreateTenantRequest(TenantB, TenantB, "Tenant B"));
    }

    private async Task CreateUserInTenantAsync(string tenantIdentifier, string email, string password, string role = IdmtDefaultRoleTypes.TenantAdmin)
    {
        using var scope = Factory.Services.CreateScope();
        var provider = scope.ServiceProvider;

        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(tenantIdentifier);

        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant!);

        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
        var user = new IdmtUser { UserName = email, Email = email, TenantId = tenant!.Id, EmailConfirmed = true };
        await userManager.CreateAsync(user, password);
        await userManager.AddToRoleAsync(user, role);
    }

    #region Login Isolation Tests

    [Fact]
    public async Task User_in_tenant_A_cannot_login_to_tenant_B()
    {
        await EnsureTenantsExistAsync();

        // Create user in Tenant A
        var email = $"user-{Guid.NewGuid():N}@example.com";
        var password = "UserPassword1!";
        await CreateUserInTenantAsync(TenantA, email, password);

        // Login to Tenant A (Success)
        var clientA = Factory.CreateClientWithTenant(TenantA);
        var loginA = await clientA.PostAsJsonAsync("/auth/login", new { Email = email, Password = password });
        await loginA.AssertSuccess();

        // Login to Tenant B (Fail)
        var clientB = Factory.CreateClientWithTenant(TenantB);
        var loginB = await clientB.PostAsJsonAsync("/auth/login", new { Email = email, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, loginB.StatusCode);
    }

    [Fact]
    public async Task User_in_tenant_A_cannot_get_token_for_tenant_B()
    {
        await EnsureTenantsExistAsync();

        // Create user in Tenant A
        var email = $"token-{Guid.NewGuid():N}@example.com";
        var password = "UserPassword1!";
        await CreateUserInTenantAsync(TenantA, email, password);

        // Get token for Tenant A (Success)
        var clientA = Factory.CreateClientWithTenant(TenantA);
        var tokenResponseA = await clientA.PostAsJsonAsync("/auth/token", new { Email = email, Password = password });
        await tokenResponseA.AssertSuccess();

        // Try to get token for Tenant B (Fail)
        var clientB = Factory.CreateClientWithTenant(TenantB);
        var tokenResponseB = await clientB.PostAsJsonAsync("/auth/token", new { Email = email, Password = password });
        Assert.Equal(HttpStatusCode.Unauthorized, tokenResponseB.StatusCode);
    }

    #endregion

    #region Token Isolation Tests

    [Fact]
    public async Task Token_from_tenant_A_cannot_access_tenant_B_resources()
    {
        await EnsureTenantsExistAsync();

        // Create user in Tenant A
        var email = $"tokenaccess-{Guid.NewGuid():N}@example.com";
        var password = "UserPassword1!";
        await CreateUserInTenantAsync(TenantA, email, password);

        // Login to Tenant A
        var clientA = Factory.CreateClientWithTenant(TenantA);
        var loginA = await clientA.PostAsJsonAsync("/auth/token", new { Email = email, Password = password });
        var tokens = await loginA.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        // Access Tenant A protected resource (Success)
        clientA.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var infoA = await clientA.GetAsync("/manage/info");
        await infoA.AssertSuccess();

        // Access Tenant B protected resource with Tenant A token (Fail)
        var clientB = Factory.CreateClientWithTenant(TenantB);
        clientB.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var infoB = await clientB.GetAsync("/manage/info");

        Assert.Contains(infoB.StatusCode, new[] { HttpStatusCode.NotFound, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    [Fact]
    public async Task Token_from_tenant_A_cannot_modify_tenant_B_resources()
    {
        await EnsureTenantsExistAsync();

        // Create users
        var emailA = $"userA-{Guid.NewGuid():N}@example.com";
        var emailB = $"userB-{Guid.NewGuid():N}@example.com";
        await CreateUserInTenantAsync(TenantA, emailA, "PasswordA1!");
        await CreateUserInTenantAsync(TenantB, emailB, "PasswordB1!");

        // Get Tenant A user token
        var clientA = Factory.CreateClientWithTenant(TenantA);
        var loginA = await clientA.PostAsJsonAsync("/auth/token", new { Email = emailA, Password = "PasswordA1!" });
        var tokens = await loginA.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        // Get Tenant B user ID
        using var scope = Factory.Services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenantB = await store.GetByIdentifierAsync(TenantB);
        var setter = scope.ServiceProvider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantB!);
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdmtUser>>();
        var userB = await userManager.FindByEmailAsync(emailB);

        // Try to delete Tenant B user with Tenant A token
        var clientB = Factory.CreateClientWithTenant(TenantB);
        clientB.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var deleteResponse = await clientB.DeleteAsync($"/manage/users/{userB!.Id}");

        Assert.Contains(deleteResponse.StatusCode, new[] { HttpStatusCode.NotFound, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region User Data Isolation Tests

    [Fact]
    public async Task User_can_only_see_their_own_tenant_info()
    {
        await EnsureTenantsExistAsync();

        // Create user in Tenant A
        var emailA = $"infoA-{Guid.NewGuid():N}@example.com";
        var passwordA = "PasswordA1!";
        await CreateUserInTenantAsync(TenantA, emailA, passwordA);

        // Login and get user info
        var clientA = Factory.CreateClientWithTenant(TenantA);
        var loginA = await clientA.PostAsJsonAsync("/auth/token", new { Email = emailA, Password = passwordA });
        var tokens = await loginA.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        clientA.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var infoResponse = await clientA.GetAsync("/manage/info");
        var info = await infoResponse.Content.ReadFromJsonAsync<GetUserInfo.GetUserInfoResponse>();

        Assert.NotNull(info);
        Assert.Equal(TenantA, info!.TenantIdentifier);
    }

    [Fact]
    public async Task User_in_other_tenant_cannot_see_system_info_for_current_tenant()
    {
        await EnsureTenantsExistAsync();

        // Create user in Tenant A
        var emailA = $"sysinfo-{Guid.NewGuid():N}@example.com";
        var passwordA = "PasswordA1!";
        await CreateUserInTenantAsync(TenantA, emailA, passwordA, IdmtDefaultRoleTypes.SysSupport);

        // Get system info for Tenant A
        var clientA = Factory.CreateClientWithTenant(TenantA);
        var loginA = await clientA.PostAsJsonAsync("/auth/token", new { Email = emailA, Password = passwordA });
        var tokens = await loginA.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();

        clientA.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var infoResponseA = await clientA.GetAsync("/sys/info");
        var infoA = await infoResponseA.Content.ReadFromJsonAsync<GetSystemInfo.SystemInfoResponse>();

        // Try to access Tenant B with Tenant A token
        var clientB = Factory.CreateClientWithTenant(TenantB);
        clientB.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var infoResponseB = await clientB.GetAsync("/sys/info");

        Assert.Contains(infoResponseB.StatusCode, new[] { HttpStatusCode.NotFound, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region Route Strategy Tests

    [Fact]
    public async Task Auth_login_via_route_strategy()
    {
        var factory = new IdmtApiFactory(new[] { IdmtMultiTenantStrategy.Route });
        try
        {
            var client = factory.CreateClientWithTenant();

            var loginResponse = await client.PostAsJsonAsync("auth/login", new
            {
                Email = IdmtApiFactory.SysAdminEmail,
                Password = IdmtApiFactory.SysAdminPassword
            });

            await loginResponse.AssertSuccess();
        }
        finally
        {
            factory.Dispose();
        }
    }

    [Fact]
    public async Task Endpoints_are_not_accessible_at_root_with_route_strategy()
    {
        var factory = new IdmtApiFactory(new[] { IdmtMultiTenantStrategy.Route });
        try
        {
            // When route strategy is enabled, endpoints are moved to /{tenant}/...
            // So root endpoints should not exist (404)
            var client = factory.CreateClient(); // No tenant, no route base address

            var response = await client.GetAsync("/healthz");
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
        finally
        {
            factory.Dispose();
        }
    }

    [Fact]
    public async Task Healthz_accessible_via_route_strategy()
    {
        var factory = new IdmtApiFactory(new[] { IdmtMultiTenantStrategy.Route });
        try
        {
            var client = factory.CreateClientWithTenant();

            var response = await client.GetAsync("healthz");
            Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found, HttpStatusCode.OK });
            Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
        }
        finally
        {
            factory.Dispose();
        }
    }

    #endregion

    #region Complete User Lifecycle Tests

    [Fact]
    public async Task Complete_user_lifecycle_flow_across_tenants()
    {
        await EnsureTenantsExistAsync();

        var initialAdminEmail = $"lifecycle-admin-{Guid.NewGuid():N}@example.com";
        var initialAdminPassword = "InitialAdminPassword1!";

        await CreateUserInTenantAsync(TenantA, initialAdminEmail, initialAdminPassword, IdmtDefaultRoleTypes.TenantAdmin);

        // 1. Register User in Tenant A (as admin)
        var emailA = $"lifecycle-{Guid.NewGuid():N}@example.com";
        var usernameA = $"user{Guid.NewGuid():N}";

        using var adminClientA = Factory.CreateClientWithTenant(TenantA);
        var admin = await CreateAdminForTenantAsync(adminClientA, TenantA, initialAdminEmail, initialAdminPassword);

        var registerResponse = await admin.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = emailA,
            Username = usernameA,
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();
        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();

        // 2. Set Password
        const string setupPassword = "SetupPassword1!";
        using var publicClient = Factory.CreateClient();
        var resetResponse = await publicClient.PostAsJsonAsync(
            $"/auth/resetPassword?tenantIdentifier={TenantA}&email={emailA}&token={Uri.EscapeDataString(registerResult!.PasswordSetupToken!)}",
            new { NewPassword = setupPassword });
        await resetResponse.AssertSuccess();

        // 3. Login in Tenant A (Success)
        using var userClientA = Factory.CreateClientWithTenant(TenantA);
        var loginA = await userClientA.PostAsJsonAsync("/auth/token", new { Email = emailA, Password = setupPassword });
        await loginA.AssertSuccess();

        // 4. Try Login in Tenant B (Fail)
        using var userClientB = Factory.CreateClientWithTenant(TenantB);
        var loginB = await userClientB.PostAsJsonAsync("/auth/token", new { Email = emailA, Password = setupPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, loginB.StatusCode);
    }

    #endregion

    private async Task<HttpClient> CreateAdminForTenantAsync(HttpClient client, string tenantId, string email, string password)
    {
        var loginResponse = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = email,
            Password = password
        });
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        return client;
    }
}
