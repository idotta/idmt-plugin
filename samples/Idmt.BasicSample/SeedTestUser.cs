using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;

namespace Idmt.BasicSample;

public static class SeedTestUser
{
    public const string TestUserEmail = "testadmin@example.com";
    public const string TestUserPassword = "TestAdmin123!";

    public static async Task SeedAsync(IServiceProvider services)
    {
        // Get tenant store and set context
        var tenantStore = services.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await tenantStore.GetByIdentifierAsync(MultiTenantOptions.DefaultTenantIdentifier);

        if (tenant == null)
        {
            return; // Tenant doesn't exist yet
        }

        // Set tenant context
        var tenantContextSetter = services.GetRequiredService<IMultiTenantContextSetter>();
        tenantContextSetter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);

        var userManager = services.GetRequiredService<UserManager<IdmtUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdmtRole>>();

        // Ensure roles exist
        var roles = new[] { IdmtDefaultRoleTypes.SysAdmin, IdmtDefaultRoleTypes.TenantAdmin };
        foreach (var roleName in roles)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new IdmtRole(roleName));
            }
        }

        // Check if test user already exists
        var existingUser = await userManager.FindByEmailAsync(TestUserEmail);
        if (existingUser != null)
        {
            return; // User already exists
        }

        // Create test user
        var user = new IdmtUser
        {
            Email = TestUserEmail,
            UserName = "testadmin",
            EmailConfirmed = true,
            IsActive = true,
            TenantId = tenant.Id!
        };

        var result = await userManager.CreateAsync(user, TestUserPassword);
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(user, IdmtDefaultRoleTypes.SysAdmin);
        }
    }
}
