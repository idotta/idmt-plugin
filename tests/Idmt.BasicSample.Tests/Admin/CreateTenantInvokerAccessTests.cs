using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.BasicSample.Tests.Admin;

/// <summary>
/// Phase 1 / Step 9: invoker auto-TenantAccess on tenant creation (HS-4 / V2-CRIT-2).
/// Asserts the SysAdmin who creates a tenant gets a TenantAccess row in the new tenant inside the
/// same inner transaction as role seeding, and that SysAdmin/SysSupport are NOT seeded as
/// per-tenant IdentityRole rows in fresh tenants.
/// </summary>
public class CreateTenantInvokerAccessTests : BaseIntegrationTest
{
    public CreateTenantInvokerAccessTests(IdmtApiFactory factory) : base(factory) { }

    [Fact]
    public async Task POST_CreateTenant_AsSysAdmin_InvokerCanAccessNewTenant()
    {
        // Arrange
        var sysClient = await CreateAuthenticatedClientAsync();
        var newTenant = $"step9-access-{Guid.NewGuid():N}";

        // Act: create the tenant.
        var createResponse = await sysClient.PostAsJsonAsync("/admin/tenants", new
        {
            Identifier = newTenant,
            Name = "Step 9 Access Tenant"
        });
        await createResponse.AssertSuccess();

        // Bearer tokens carry a tenant claim — the existing sysadmin token is bound to the default
        // tenant, so we issue a fresh bearer against the new tenant. SysAdmin must be able to log
        // in there (login doesn't yet enforce TenantAccess — Step 10) and reach the protected
        // endpoint, demonstrating that the auto-inserted TenantAccess row admits the invoker.
        var newTenantClient = Factory.CreateClientWithTenant(newTenant);
        var loginResponse = await newTenantClient.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        await loginResponse.AssertSuccess();
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Idmt.Plugin.Features.Auth.Login.AccessTokenResponse>();
        newTenantClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        var infoResponse = await newTenantClient.GetAsync("/manage/info");

        // Assert
        await infoResponse.AssertSuccess();
        var info = await infoResponse.Content.ReadFromJsonAsync<GetUserInfo.GetUserInfoResponse>();
        Assert.NotNull(info);
        Assert.Equal(newTenant, info!.TenantIdentifier);
    }

    [Fact]
    public async Task POST_CreateTenant_AsSysAdmin_InsertsTenantAccessRow()
    {
        // Arrange
        var sysClient = await CreateAuthenticatedClientAsync();
        var newTenant = $"step9-row-{Guid.NewGuid():N}";

        // Resolve sysadmin user id.
        Guid sysAdminId;
        using (var scope = Factory.Services.CreateScope())
        {
            var provider = scope.ServiceProvider;
            var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            var defaultTenant = await store.GetByIdentifierAsync(IdmtApiFactory.DefaultTenantIdentifier)
                ?? throw new InvalidOperationException("Default tenant missing");
            var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
            setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(defaultTenant);

            var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
            var sysAdmin = await userManager.FindByEmailAsync(IdmtApiFactory.SysAdminEmail)
                ?? throw new InvalidOperationException("Sysadmin missing");
            sysAdminId = sysAdmin.Id;
        }

        // Act: create the tenant.
        var createResponse = await sysClient.PostAsJsonAsync("/admin/tenants", new
        {
            Identifier = newTenant,
            Name = "Step 9 Row Tenant"
        });
        await createResponse.AssertSuccess();

        // Assert: TenantAccess row exists for the invoker against the new tenant id.
        using (var scope = Factory.Services.CreateScope())
        {
            var provider = scope.ServiceProvider;
            var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            var newTenantInfo = await store.GetByIdentifierAsync(newTenant);
            Assert.NotNull(newTenantInfo);

            var db = provider.GetRequiredService<IdmtDbContext>();
            var ta = await db.TenantAccess
                .SingleOrDefaultAsync(x => x.UserId == sysAdminId && x.TenantId == newTenantInfo!.Id);
            Assert.NotNull(ta);
            Assert.True(ta!.IsActive);
            Assert.Null(ta.ExpiresAt);
        }
    }

    [Fact]
    public async Task POST_CreateTenant_RoleSeeding_DoesNotIncludeSysAdminOrSysSupport()
    {
        // Arrange
        var sysClient = await CreateAuthenticatedClientAsync();
        var newTenant = $"step9-roles-{Guid.NewGuid():N}";

        // Act
        var createResponse = await sysClient.PostAsJsonAsync("/admin/tenants", new
        {
            Identifier = newTenant,
            Name = "Step 9 Roles Tenant"
        });
        await createResponse.AssertSuccess();

        // Assert: per-tenant IdmtRole rows for the new tenant must NOT include SysAdmin/SysSupport.
        using var scope = Factory.Services.CreateScope();
        var provider = scope.ServiceProvider;
        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var newTenantInfo = await store.GetByIdentifierAsync(newTenant);
        Assert.NotNull(newTenantInfo);

        // Switch tenant context so RoleManager queries scope to the new tenant.
        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(newTenantInfo!);

        var roleManager = provider.GetRequiredService<RoleManager<IdmtRole>>();
        var rolesForTenant = await roleManager.Roles
            .Where(r => r.TenantId == newTenantInfo!.Id)
            .Select(r => r.Name!)
            .ToListAsync();

        Assert.DoesNotContain(IdmtDefaultRoleTypes.SysAdmin, rolesForTenant);
        Assert.DoesNotContain(IdmtDefaultRoleTypes.SysSupport, rolesForTenant);
        Assert.Contains(IdmtDefaultRoleTypes.TenantAdmin, rolesForTenant);
    }
}
