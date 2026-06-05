using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.BasicSample.Tests.Admin;

/// <summary>
/// Phase 1 (canonical identity) integration tests for <c>DELETE /admin/users/{userId}/tenants/{tenantIdentifier}</c>.
/// Asserts the handler flips <c>TenantAccess.IsActive = false</c> in a single SaveChangesAsync, surfaces 404 when
/// no access record exists, and rejects SysSupport callers (Phase 0 policy regression).
/// </summary>
public class RevokeTenantAccessIntegrationTests : BaseIntegrationTest
{
    public RevokeTenantAccessIntegrationTests(IdmtApiFactory factory) : base(factory) { }

    [Fact]
    public async Task POST_RevokeTenantAccess_AsSysAdmin_FlipsIsActiveFalse()
    {
        // Arrange
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"phase1-revoke-{Guid.NewGuid():N}@example.com";

        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"phase1revoke{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        await registerResponse.AssertSuccess();
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Fresh tenant so the access row is unambiguous.
        var targetTenant = $"phase1-revoke-tenant-{Guid.NewGuid():N}";
        var createTenantResponse = await sysClient.PostAsJsonAsync("/admin/tenants", new
        {
            Identifier = targetTenant,
            Name = "Phase 1 Revoke Tenant"
        });
        await createTenantResponse.AssertSuccess();

        // Grant access first.
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{targetTenant}",
            new { ExpiresAt = (DateTime?)null });
        await grantResponse.AssertSuccess();

        // Act
        var revokeResponse = await sysClient.DeleteAsync($"/admin/users/{userId}/tenants/{targetTenant}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, revokeResponse.StatusCode);

        using var scope = Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdmtDbContext>();
        var store = scope.ServiceProvider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenantInfo = await store.GetByIdentifierAsync(targetTenant);
        Assert.NotNull(tenantInfo);

        var ta = await db.TenantAccess.FirstOrDefaultAsync(x => x.UserId == userId && x.TenantId == tenantInfo!.Id);
        Assert.NotNull(ta);
        Assert.False(ta!.IsActive);
    }

    [Fact]
    public async Task POST_RevokeTenantAccess_AsSysAdmin_NoExistingAccess_Returns404()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"phase1-revoke-noaccess-{Guid.NewGuid():N}@example.com";

        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"phase1revokenoaccess{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        await registerResponse.AssertSuccess();
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Fresh tenant — no grant performed.
        var targetTenant = $"phase1-revoke-noaccess-tenant-{Guid.NewGuid():N}";
        var createTenantResponse = await sysClient.PostAsJsonAsync("/admin/tenants", new
        {
            Identifier = targetTenant,
            Name = "Phase 1 Revoke NoAccess Tenant"
        });
        await createTenantResponse.AssertSuccess();

        var revokeResponse = await sysClient.DeleteAsync($"/admin/users/{userId}/tenants/{targetTenant}");

        Assert.Equal(HttpStatusCode.NotFound, revokeResponse.StatusCode);
    }

    [Fact]
    public async Task POST_RevokeTenantAccess_AsSysSupport_Returns403()
    {
        // Phase 0 admin policy: SysSupport must not reach the SysAdmin-gated revoke endpoint.
        var sysAdminClient = await CreateAuthenticatedClientAsync();

        var ssEmail = $"phase1-revoke-ss-{Guid.NewGuid():N}@example.com";
        var ssPassword = "Phase1Ss1!";
        var (_, _) = await RegisterAndSetPasswordAsync(
            sysAdminClient,
            ssPassword,
            email: ssEmail,
            username: $"phase1revokess{Guid.NewGuid():N}",
            role: IdmtDefaultRoleTypes.SysSupport);

        var ssClient = Factory.CreateClientWithTenant();
        var loginResponse = await ssClient.PostAsJsonAsync("/auth/token", new
        {
            Email = ssEmail,
            Password = ssPassword
        });
        await loginResponse.AssertSuccess();
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        ssClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        var response = await ssClient.DeleteAsync(
            $"/admin/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
