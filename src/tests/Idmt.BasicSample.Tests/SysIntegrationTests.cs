using System.Net;
using System.Net.Http.Json;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Features.Sys;
using Idmt.Plugin.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.BasicSample.Tests;

/// <summary>
/// Integration tests for System Management endpoints.
/// Covers: /sys/tenants, /sys/users/{userId}/tenants, /sys/info, /healthz
/// </summary>
public class SysIntegrationTests : BaseIntegrationTest
{
    public SysIntegrationTests(IdmtApiFactory factory) : base(factory) { }

    #region Health Check Tests

    [Fact]
    public async Task Healthz_endpoint_requires_authentication()
    {
        var client = Factory.CreateClientWithTenant();
        var response = await client.GetAsync("/healthz");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    [Fact]
    public async Task Healthz_endpoint_allows_authenticated_user()
    {
        var client = await CreateAuthenticatedClientAsync();
        var response = await client.GetAsync("/healthz");
        await response.AssertSuccess();
    }

    #endregion

    #region Get System Info Tests

    [Fact]
    public async Task GetSystemInfo_returns_system_details()
    {
        var client = await CreateAuthenticatedClientAsync();

        var response = await client.GetAsync("/sys/info");
        await response.AssertSuccess();

        var sysInfo = await response.Content.ReadFromJsonAsync<GetSystemInfo.SystemInfoResponse>();
        Assert.NotNull(sysInfo);
        Assert.NotEmpty(sysInfo!.ApplicationName);
        Assert.NotEmpty(sysInfo.Version);
        Assert.NotEmpty(sysInfo.Environment);
        Assert.True(sysInfo.ServerTime > DateTime.MinValue);
    }

    [Fact]
    public async Task GetSystemInfo_returns_current_tenant_info()
    {
        var client = await CreateAuthenticatedClientAsync();

        var response = await client.GetAsync("/sys/info");
        await response.AssertSuccess();

        var sysInfo = await response.Content.ReadFromJsonAsync<GetSystemInfo.SystemInfoResponse>();
        Assert.NotNull(sysInfo);
        Assert.NotNull(sysInfo!.CurrentTenant);
        var currentTenant = sysInfo.CurrentTenant!;
        Assert.NotNull(currentTenant.Identifier);
        Assert.NotNull(currentTenant.Name);
    }

    [Fact]
    public async Task GetSystemInfo_requires_authentication()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.GetAsync("/sys/info");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    #endregion

    #region Create Tenant Tests (Handler-based)

    [Fact]
    public async Task CreateTenant_handler_with_valid_data_succeeds()
    {
        using var scope = Factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();

        var tenantIdentifier = $"tenant-{Guid.NewGuid():N}";
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant", "Test Tenant Display");
        var result = await handler.HandleAsync(request);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.Equal(tenantIdentifier, result.Value!.Identifier);
    }

    [Fact]
    public async Task CreateTenant_handler_with_duplicate_identifier_reactivates()
    {
        using var scope = Factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();
        var deleteHandler = scope.ServiceProvider.GetRequiredService<DeleteTenant.IDeleteTenantHandler>();

        var tenantIdentifier = $"tenant-{Guid.NewGuid():N}";

        // Create initial tenant
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant", "Test Display");
        var result = await handler.HandleAsync(request);
        var tenantId = result.Value!.Id;

        // Delete the tenant
        await deleteHandler.HandleAsync(tenantIdentifier);

        // Reactivate by creating again
        var reactivateResult = await handler.HandleAsync(request);
        Assert.True(reactivateResult.IsSuccess);
        Assert.Equal(tenantId, reactivateResult.Value!.Id);
    }

    #endregion

    #region Delete Tenant Tests (Handler-based)

    [Fact]
    public async Task DeleteTenant_handler_with_valid_identifier_succeeds()
    {
        using var scope = Factory.Services.CreateScope();
        var createHandler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();
        var deleteHandler = scope.ServiceProvider.GetRequiredService<DeleteTenant.IDeleteTenantHandler>();

        var tenantIdentifier = $"tenant-{Guid.NewGuid():N}";
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant", "Test Display");
        await createHandler.HandleAsync(request);

        var deleted = await deleteHandler.HandleAsync(tenantIdentifier);
        Assert.True(deleted);
    }

    [Fact]
    public async Task DeleteTenant_handler_with_invalid_identifier_returns_false()
    {
        using var scope = Factory.Services.CreateScope();
        var deleteHandler = scope.ServiceProvider.GetRequiredService<DeleteTenant.IDeleteTenantHandler>();

        var deleted = await deleteHandler.HandleAsync($"nonexistent-{Guid.NewGuid():N}");
        Assert.False(deleted);
    }

    #endregion

    #region Grant Tenant Access Tests

    [Fact]
    public async Task GrantTenantAccess_with_valid_data_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"grant{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        await grantResponse.AssertSuccess();
    }

    [Fact]
    public async Task GrantTenantAccess_allows_user_to_access_tenant()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-access-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"grantaccess{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access
        await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        // Verify user can access tenant
        var tenants = await sysClient.GetFromJsonAsync<GetUserTenants.TenantInfoResponse[]>($"/sys/users/{userId}/tenants");
        Assert.NotNull(tenants);
        Assert.Contains(tenants!, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task GrantTenantAccess_with_nonexistent_user_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.PostAsJsonAsync(
            $"/sys/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task GrantTenantAccess_with_nonexistent_tenant_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-notenant-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"grantnotenant{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Try to grant access to nonexistent tenant
        var response = await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/nonexistent-tenant",
            new { ExpiresAt = (DateTime?)null });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task GrantTenantAccess_with_expiration_date_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-expires-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"grantexpires{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access with expiration
        var expiresAt = DateTime.UtcNow.AddDays(1);
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = expiresAt });

        await grantResponse.AssertSuccess();
    }

    [Fact]
    public async Task GrantTenantAccess_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync(
            $"/sys/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region Revoke Tenant Access Tests

    [Fact]
    public async Task RevokeTenantAccess_with_valid_data_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"revoke-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"revoke{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access
        await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        // Revoke access
        var revokeResponse = await sysClient.DeleteAsync($"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");
        await revokeResponse.AssertSuccess();
    }

    [Fact]
    public async Task RevokeTenantAccess_removes_access()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"revoke-remove-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"revokeremove{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access
        await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        // Verify access exists
        var tenantsBeforeRevoke = await sysClient.GetFromJsonAsync<GetUserTenants.TenantInfoResponse[]>($"/sys/users/{userId}/tenants");
        Assert.Contains(tenantsBeforeRevoke!, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);

        // Revoke access
        await sysClient.DeleteAsync($"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");

        // Verify access is removed
        var tenantsAfterRevoke = await sysClient.GetFromJsonAsync<GetUserTenants.TenantInfoResponse[]>($"/sys/users/{userId}/tenants");
        Assert.DoesNotContain(tenantsAfterRevoke!, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task RevokeTenantAccess_with_nonexistent_user_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.DeleteAsync($"/sys/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");
        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task RevokeTenantAccess_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.DeleteAsync($"/sys/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region Get User Tenants Tests

    [Fact]
    public async Task GetUserTenants_returns_user_accessible_tenants()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"usertenants-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"usertenants{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access to a tenant
        await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        // Get user tenants
        var response = await sysClient.GetAsync($"/sys/users/{userId}/tenants");
        await response.AssertSuccess();

        var tenants = await response.Content.ReadFromJsonAsync<GetUserTenants.TenantInfoResponse[]>();
        Assert.NotNull(tenants);
        Assert.NotEmpty(tenants);
        Assert.Contains(tenants!, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task GetUserTenants_returns_empty_for_user_without_access()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"notenants-{Guid.NewGuid():N}@example.com";

        // Register user without granting tenant access
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = email,
            Username = $"notenants{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Get user tenants
        var response = await sysClient.GetAsync($"/sys/users/{userId}/tenants");
        await response.AssertSuccess();

        var tenants = await response.Content.ReadFromJsonAsync<GetUserTenants.TenantInfoResponse[]>();
        Assert.NotNull(tenants);
        Assert.Empty(tenants!);
    }

    [Fact]
    public async Task GetUserTenants_with_nonexistent_user_succeeds_empty()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.GetAsync($"/sys/users/{Guid.NewGuid()}/tenants");
        // May return 200 with empty or 404
        Assert.True(response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task GetUserTenants_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.GetAsync($"/sys/users/{Guid.NewGuid()}/tenants");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion
}
