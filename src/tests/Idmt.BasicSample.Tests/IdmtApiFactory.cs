using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Idmt.BasicSample.Tests;

public class IdmtApiFactory : WebApplicationFactory<Program>
{
    public const string DefaultTenantId = MultiTenantOptions.DefaultTenantId;
    public const string SysAdminEmail = "sysadmin@example.com";
    public const string SysAdminPassword = "SysAdmin1!";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureServices(services =>
        {
            services.RemoveAll(typeof(DbContextOptions<IdmtDbContext>));
            services.RemoveAll(typeof(DbContextOptions<IdmtTenantStoreDbContext>));

            var databaseName = $"IdmtTests-{Guid.NewGuid()}";
            services.AddDbContext<IdmtDbContext>(options => options
                .UseInMemoryDatabase(databaseName)
                .ConfigureWarnings(builder => builder.Ignore(InMemoryEventId.TransactionIgnoredWarning)));
            services.AddDbContext<IdmtTenantStoreDbContext>(options => options.UseInMemoryDatabase(databaseName));

            services.AddTransient<TestDataSeeder>();

            using var provider = services.BuildServiceProvider();
            using var scope = provider.CreateScope();
            var seeder = scope.ServiceProvider.GetRequiredService<TestDataSeeder>();
            seeder.EnsureSeedAsync().GetAwaiter().GetResult();
        });
    }

    public HttpClient CreateClientWithTenant(bool allowAutoRedirect = false)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = allowAutoRedirect
        });
        client.DefaultRequestHeaders.TryAddWithoutValidation("__tenant__", DefaultTenantId);
        return client;
    }
}

internal sealed class TestDataSeeder(IServiceProvider services)
{
    public async Task EnsureSeedAsync()
    {
        using var scope = services.CreateScope();
        var provider = scope.ServiceProvider;

        var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenantContextSetter = provider.GetRequiredService<IMultiTenantContextSetter>();
        var tenantContextAccessor = provider.GetRequiredService<IMultiTenantContextAccessor>();
        var tenant = await EnsureDefaultTenantAsync(tenantStore);

        var previousContext = tenantContextAccessor.MultiTenantContext;
        tenantContextSetter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo> { TenantInfo = tenant };

        var dbContext = provider.GetRequiredService<IdmtDbContext>();
        var tenantStoreDbContext = provider.GetRequiredService<IdmtTenantStoreDbContext>();
        var roleManager = provider.GetRequiredService<RoleManager<IdmtRole>>();
        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();

        await dbContext.Database.EnsureCreatedAsync();
        await tenantStoreDbContext.Database.EnsureCreatedAsync();

        var previousMode = dbContext.TenantMismatchMode;
        dbContext.TenantMismatchMode = TenantMismatchMode.Ignore;

        try
        {
            await EnsureRolesAsync(roleManager);
            await EnsureSysAdminAsync(dbContext, userManager, tenant.Id!);
        }
        finally
        {
            dbContext.TenantMismatchMode = previousMode;
            tenantContextSetter.MultiTenantContext = previousContext;
        }
    }

    private static async Task EnsureRolesAsync(RoleManager<IdmtRole> roleManager)
    {
        var roles = new[]
        {
            IdmtDefaultRoleTypes.SysAdmin,
            IdmtDefaultRoleTypes.SysSupport,
            IdmtDefaultRoleTypes.TenantAdmin,
            IdmtDefaultRoleTypes.TenantUser
        };

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdmtRole(role));
            }
        }
    }

    private static async Task EnsureSysAdminAsync(IdmtDbContext dbContext, UserManager<IdmtUser> userManager, string tenantId)
    {
        var existing = await dbContext.Users.IgnoreQueryFilters()
            .SingleOrDefaultAsync(u => u.Email == IdmtApiFactory.SysAdminEmail);

        var user = existing ?? new IdmtUser
        {
            Email = IdmtApiFactory.SysAdminEmail,
            UserName = "sysadmin",
            EmailConfirmed = true,
            IsActive = true,
            TenantId = tenantId
        };

        if (existing is null)
        {
            var createResult = await userManager.CreateAsync(user, IdmtApiFactory.SysAdminPassword);
            if (!createResult.Succeeded)
            {
                var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
                throw new InvalidOperationException($"Failed to seed sysadmin user: {errors}");
            }
        }

        await userManager.AddToRoleAsync(user, IdmtDefaultRoleTypes.SysAdmin);

        var hasAccess = await dbContext.TenantAccess.AnyAsync(ta => ta.UserId == user.Id && ta.TenantId == tenantId);
        if (!hasAccess)
        {
            dbContext.TenantAccess.Add(new TenantAccess
            {
                UserId = user.Id,
                TenantId = tenantId,
                IsActive = true,
                ExpiresAt = null
            });
            await dbContext.SaveChangesAsync();
        }
    }

    private static async Task<IdmtTenantInfo> EnsureDefaultTenantAsync(IMultiTenantStore<IdmtTenantInfo> tenantStore)
    {
        var tenant = await tenantStore.TryGetAsync(MultiTenantOptions.DefaultTenantId);
        if (tenant != null)
        {
            return tenant;
        }

        tenant = new IdmtTenantInfo
        {
            Id = MultiTenantOptions.DefaultTenantId,
            Identifier = MultiTenantOptions.DefaultTenantId,
            Name = "System Tenant",
            DisplayName = "System",
            IsActive = true
        };

        await tenantStore.TryAddAsync(tenant);
        return tenant;
    }
}
