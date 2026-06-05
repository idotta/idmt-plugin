using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.BasicSample.Tests.Admin;

/// <summary>
/// Phase 1 (canonical identity) integration tests for <c>POST /admin/users/{userId}/tenants/{tenantIdentifier}</c>.
/// Asserts the handler writes ONLY a TenantAccess row (no shadow IdmtUser created), self-target is rejected,
/// and unknown tenants return 404.
/// </summary>
public class GrantTenantAccessIntegrationTests : BaseIntegrationTest
{
    public GrantTenantAccessIntegrationTests(IdmtApiFactory factory) : base(factory) { }

    [Fact]
    public async Task POST_GrantTenantAccess_AsSysAdmin_CreatesZeroIdmtUserRows()
    {
        // Arrange
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"phase1-grant-{Guid.NewGuid():N}@example.com";

        // Register user (canonical, global)
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"phase1grant{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        await registerResponse.AssertSuccess();
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        // Create a fresh target tenant so the TenantAccess insert is observable.
        var targetTenant = $"phase1-grant-tenant-{Guid.NewGuid():N}";
        var createTenantResponse = await sysClient.PostAsJsonAsync("/admin/tenants", new
        {
            Identifier = targetTenant,
            Name = "Phase 1 Grant Tenant"
        });
        await createTenantResponse.AssertSuccess();

        // Snapshot canonical Users + TenantAccess counts before the grant.
        int beforeUserCount;
        int beforeTaCount;
        using (var scope = Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdmtDbContext>();
            beforeUserCount = await db.Users.CountAsync();
            beforeTaCount = await db.TenantAccess.CountAsync();
        }

        // Act
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{targetTenant}",
            new { ExpiresAt = (DateTime?)null });

        // Assert
        await grantResponse.AssertSuccess();

        using (var scope = Factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdmtDbContext>();
            var afterUserCount = await db.Users.CountAsync();
            var afterTaCount = await db.TenantAccess.CountAsync();

            // No shadow IdmtUser rows were created.
            Assert.Equal(beforeUserCount, afterUserCount);

            // Exactly one new TenantAccess row.
            Assert.Equal(beforeTaCount + 1, afterTaCount);

            // Resolve target tenant id, then verify the row by (UserId, TenantId).
            var store = scope.ServiceProvider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            var tenantInfo = await store.GetByIdentifierAsync(targetTenant);
            Assert.NotNull(tenantInfo);

            var ta = await db.TenantAccess.FirstOrDefaultAsync(x => x.UserId == userId && x.TenantId == tenantInfo!.Id);
            Assert.NotNull(ta);
            Assert.True(ta!.IsActive);
        }
    }

    [Fact]
    public async Task POST_GrantTenantAccess_AsSysAdmin_TenantNotFound_Returns404()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var email = $"phase1-grant-nt-{Guid.NewGuid():N}@example.com";

        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users", new
        {
            Email = email,
            Username = $"phase1grantnt{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        await registerResponse.AssertSuccess();
        var userId = Guid.Parse((await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>())!.UserId!);

        var bogusTenant = $"phase1-no-such-tenant-{Guid.NewGuid():N}";
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/admin/users/{userId}/tenants/{bogusTenant}",
            new { ExpiresAt = (DateTime?)null });

        Assert.Equal(HttpStatusCode.NotFound, grantResponse.StatusCode);
    }

    [Fact]
    public async Task POST_GrantTenantAccess_AsSysAdmin_SelfTarget_Returns403_SelfTargetError()
    {
        var sysClient = await CreateAuthenticatedClientAsync();

        // Resolve sysadmin user id directly.
        Guid sysAdminId;
        using (var scope = Factory.Services.CreateScope())
        {
            var provider = scope.ServiceProvider;
            var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            var tenant = await store.GetByIdentifierAsync(IdmtApiFactory.DefaultTenantIdentifier)
                ?? throw new InvalidOperationException("Default tenant not found");
            var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
            setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);

            var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
            var sysAdmin = await userManager.FindByEmailAsync(IdmtApiFactory.SysAdminEmail)
                ?? throw new InvalidOperationException("Sysadmin not found");
            sysAdminId = sysAdmin.Id;
        }

        var response = await sysClient.PostAsJsonAsync(
            $"/admin/users/{sysAdminId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task POST_GrantTenantAccess_AsSysSupport_Returns403()
    {
        // Phase 0 admin policy: SysSupport must not reach the SysAdmin-gated grant endpoint.
        var sysAdminClient = await CreateAuthenticatedClientAsync();

        var ssEmail = $"phase1-grant-ss-{Guid.NewGuid():N}@example.com";
        var ssPassword = "Phase1Ss1!";
        var (_, _) = await RegisterAndSetPasswordAsync(
            sysAdminClient,
            ssPassword,
            email: ssEmail,
            username: $"phase1grantss{Guid.NewGuid():N}",
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

        var response = await ssClient.PostAsJsonAsync(
            $"/admin/users/{Guid.NewGuid()}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
