using System.Net;
using System.Net.Http.Json;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.BasicSample.Tests;

/// <summary>
/// Integration tests for System Management endpoints.
/// Covers: /admin/tenants, /admin/users/{userId}/tenants, /admin/info, /healthz
/// </summary>
public class AdminIntegrationTests : BaseIntegrationTest
{
    public AdminIntegrationTests(IdmtApiFactory factory) : base(factory) { }

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

    #region Create Tenant Tests (Handler-based)

    [Fact]
    public async Task CreateTenant_handler_with_valid_data_succeeds()
    {
        using var scope = Factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();

        var tenantIdentifier = $"tenant-{Guid.NewGuid():N}";
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant");
        var result = await handler.HandleAsync(request);

        Assert.False(result.IsError);
        Assert.Equal(tenantIdentifier, result.Value.Identifier);
    }

    [Fact]
    public async Task CreateTenant_handler_with_duplicate_identifier_reactivates()
    {
        using var scope = Factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();
        var deleteHandler = scope.ServiceProvider.GetRequiredService<DeleteTenant.IDeleteTenantHandler>();

        var tenantIdentifier = $"tenant-{Guid.NewGuid():N}";

        // Create initial tenant
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant");
        var result = await handler.HandleAsync(request);
        var tenantId = result.Value!.Id;

        // Delete the tenant
        await deleteHandler.HandleAsync(tenantIdentifier);

        // Reactivate by creating again
        var reactivateResult = await handler.HandleAsync(request);
        Assert.False(reactivateResult.IsError);
        Assert.Equal(tenantId, reactivateResult.Value.Id);
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
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant");
        await createHandler.HandleAsync(request);

        var deleted = await deleteHandler.HandleAsync(tenantIdentifier);
        Assert.False(deleted.IsError);
    }

    [Fact]
    public async Task DeleteTenant_handler_with_invalid_identifier_returns_false()
    {
        using var scope = Factory.Services.CreateScope();
        var deleteHandler = scope.ServiceProvider.GetRequiredService<DeleteTenant.IDeleteTenantHandler>();

        var deleted = await deleteHandler.HandleAsync($"nonexistent-{Guid.NewGuid():N}");
        Assert.True(deleted.IsError);
    }

    #endregion

    #region Grant Tenant Access Tests

    [Fact]
    public async Task GrantTenantAccess_with_valid_data_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"grant{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        await grantResponse.AssertSuccess();
    }

    [Fact]
    public async Task GrantTenantAccess_allows_user_to_access_tenant()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-access-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"grantaccess{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access
        await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        // Verify user can access tenant
        var paginated = await sysClient.GetFromJsonAsync<PaginatedResponse<TenantInfoResponse>>($"/admin/users/{userId}/tenants");
        Assert.NotNull(paginated);
        Assert.Contains(paginated!.Items, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task GrantTenantAccess_with_nonexistent_user_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.PostAsJsonAsync(
            $"/admin/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task GrantTenantAccess_with_nonexistent_tenant_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-notenant-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"grantnotenant{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Try to grant access to nonexistent tenant
        var response = await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/nonexistent-tenant",
            new { ExpiresAt = (DateTime?)null });

        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task GrantTenantAccess_with_expiration_date_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-expires-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"grantexpires{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access with expiration
        var expiresAt = DateTime.UtcNow.AddDays(1);
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = expiresAt });

        await grantResponse.AssertSuccess();
    }

    [Fact]
    public async Task GrantTenantAccess_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.PostAsJsonAsync(
            $"/admin/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region Revoke Tenant Access Tests

    [Fact]
    public async Task RevokeTenantAccess_with_valid_data_returns_no_content()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"revoke-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"revoke{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access
        await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        // Revoke access
        var revokeResponse = await sysClient.DeleteAsync($"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");
        Assert.Equal(HttpStatusCode.NoContent, revokeResponse.StatusCode);
    }

    [Fact]
    public async Task RevokeTenantAccess_removes_access()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"revoke-remove-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"revokeremove{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access
        await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        // Verify access exists
        var beforeRevoke = await sysClient.GetFromJsonAsync<PaginatedResponse<TenantInfoResponse>>($"/admin/users/{userId}/tenants");
        Assert.Contains(beforeRevoke!.Items, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);

        // Revoke access
        var revokeResp = await sysClient.DeleteAsync($"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");
        Assert.Equal(HttpStatusCode.NoContent, revokeResp.StatusCode);

        // Verify access is removed
        var afterRevoke = await sysClient.GetFromJsonAsync<PaginatedResponse<TenantInfoResponse>>($"/admin/users/{userId}/tenants");
        Assert.DoesNotContain(afterRevoke!.Items, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task RevokeTenantAccess_with_nonexistent_user_fails()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.DeleteAsync($"/admin/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");
        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task RevokeTenantAccess_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.DeleteAsync($"/admin/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");
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
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"usertenants{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access to a tenant
        await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        // Get user tenants
        var response = await sysClient.GetAsync($"/admin/users/{userId}/tenants");
        await response.AssertSuccess();

        var paginated = await response.Content.ReadFromJsonAsync<PaginatedResponse<TenantInfoResponse>>();
        Assert.NotNull(paginated);
        Assert.NotEmpty(paginated!.Items);
        Assert.Contains(paginated.Items, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task GetUserTenants_returns_empty_for_user_without_access()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"notenants-{Guid.NewGuid():N}@example.com";

        // Register user without granting tenant access
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"notenants{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Get user tenants
        var response = await sysClient.GetAsync($"/admin/users/{userId}/tenants");
        await response.AssertSuccess();

        var paginated = await response.Content.ReadFromJsonAsync<PaginatedResponse<TenantInfoResponse>>();
        Assert.NotNull(paginated);
        Assert.Empty(paginated!.Items);
    }

    [Fact]
    public async Task GetUserTenants_with_nonexistent_user_returns_ok_empty()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.GetAsync($"/admin/users/{Guid.NewGuid()}/tenants");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var paginated = await response.Content.ReadFromJsonAsync<PaginatedResponse<TenantInfoResponse>>();
        Assert.NotNull(paginated);
        Assert.Empty(paginated!.Items);
    }

    [Fact]
    public async Task GetUserTenants_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.GetAsync($"/admin/users/{Guid.NewGuid()}/tenants");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region Get All Tenants Tests

    [Fact]
    public async Task GetAllTenants_returns_ok_with_tenant_list()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.GetAsync("/admin/tenants");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var paginated = await response.Content.ReadFromJsonAsync<PaginatedResponse<TenantInfoResponse>>();
        Assert.NotNull(paginated);
    }

    [Fact]
    public async Task GetAllTenants_requires_authorization()
    {
        var client = Factory.CreateClientWithTenant();

        var response = await client.GetAsync("/admin/tenants");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    [Fact]
    public async Task GetAllTenants_DoesNotReturnDefaultSystemTenant()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var response = await sysClient.GetAsync("/admin/tenants");
        await response.AssertSuccess();

        var paginated = await response.Content.ReadFromJsonAsync<PaginatedResponse<TenantInfoResponse>>();
        Assert.NotNull(paginated);
        Assert.DoesNotContain(paginated!.Items, t =>
            string.Equals(t.Identifier, IdmtApiFactory.DefaultTenantIdentifier, StringComparison.OrdinalIgnoreCase));
    }

    #endregion

    #region Create Tenant Conflict Tests

    [Fact]
    public async Task CreateTenant_Returns409_WhenActiveTenantAlreadyExists()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var tenantIdentifier = $"conflict-{Guid.NewGuid():N}";

        // Create tenant the first time
        var createResponse1 = await sysClient.PostAsJsonAsync("/admin/tenants", new
        {
            Identifier = tenantIdentifier,
            Name = "Conflict Tenant"
        });
        await createResponse1.AssertSuccess();

        // Try to create the same active tenant again
        var createResponse2 = await sysClient.PostAsJsonAsync("/admin/tenants", new
        {
            Identifier = tenantIdentifier,
            Name = "Conflict Tenant Again"
        });

        Assert.Equal(HttpStatusCode.Conflict, createResponse2.StatusCode);
    }

    #endregion

    #region Delete Default Tenant Tests

    [Fact]
    public async Task DeleteTenant_ReturnsForbidden_WhenDeletingDefaultTenant()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        var deleteResponse = await sysClient.DeleteAsync($"/admin/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");

        // The handler returns ErrorType.Forbidden which maps to TypedResults.Forbid()
        Assert.Contains(deleteResponse.StatusCode, new[] { HttpStatusCode.Forbidden, HttpStatusCode.InternalServerError });
    }

    #endregion

    #region Grant Tenant Access Validation Tests

    [Fact]
    public async Task GrantTenantAccess_Returns400_WhenExpiresAtIsInPast()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"grant-past-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"grantpast{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Grant access with a past expiration date
        var pastDate = DateTime.UtcNow.AddDays(-1);
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = pastDate });

        Assert.Equal(HttpStatusCode.BadRequest, grantResponse.StatusCode);
    }

    #endregion
}
