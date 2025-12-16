using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.Abstractions;
using Finbuckle.MultiTenant.EntityFrameworkCore;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Extensions;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Idmt.BasicSample.Tests;

public class IdmtApiFactory : WebApplicationFactory<Program>
{
    public const string DefaultTenantId = MultiTenantOptions.DefaultTenantId;
    public const string SysAdminEmail = "sysadmin@example.com";
    public const string SysAdminPassword = "SysAdmin1!";
    
    private readonly string[] _strategies;
    private SqliteConnection? _connection;

    public Mock<IEmailSender<IdmtUser>> EmailSenderMock { get; } = new();

    public IdmtApiFactory()
    {
        _strategies = [IdmtMultiTenantStrategy.Header, IdmtMultiTenantStrategy.Claim];
    }

    internal IdmtApiFactory(string[] strategies)
    {
        _strategies = strategies;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("SkipDbConfig", "true");
        builder.UseSetting("Idmt:Application:ClientUrl", "http://localhost");

        IConfiguration configuration = new ConfigurationBuilder()
            .AddEnvironmentVariables()
            .Build();
        builder.UseConfiguration(configuration);

        builder.ConfigureServices(services =>
        {
            // Remove existing DbContext options
            var dbContextDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<IdmtDbContext>));
            if (dbContextDescriptor != null) services.Remove(dbContextDescriptor);

            var tenantStoreDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<IdmtTenantStoreDbContext>));
            if (tenantStoreDescriptor != null) services.Remove(tenantStoreDescriptor);

            // Create shared in-memory connection
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();

            // Add Sqlite DbContexts sharing the same connection
            services.AddDbContext<IdmtDbContext>(options => options.UseSqlite(_connection));
            services.AddDbContext<IdmtTenantStoreDbContext>(options => options.UseSqlite(_connection));

            // Replace EmailSender with Mock
            var emailSenderDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IEmailSender<IdmtUser>));
            if (emailSenderDescriptor != null) services.Remove(emailSenderDescriptor);
            
            services.AddSingleton(EmailSenderMock.Object);

            // Configure Strategies
            services.PostConfigure<IdmtOptions>(options =>
            {
                options.MultiTenant.Strategies = _strategies;
            });

            services.AddSingleton<SeedDataAsync>(new SeedDataAsync(SeedAsync));
        });
    }

    public HttpClient CreateClientWithTenant(string? tenantId = null, bool allowAutoRedirect = false)
    {
        tenantId ??= DefaultTenantId;
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = allowAutoRedirect
        });

        if (_strategies.Contains(IdmtMultiTenantStrategy.Route))
        {
            client.BaseAddress = new Uri($"http://localhost/{tenantId}/");
        }
        if (_strategies.Contains(IdmtMultiTenantStrategy.Header))
        {
            client.DefaultRequestHeaders.TryAddWithoutValidation("__tenant__", tenantId);
        }
        return client;
    }

    private static async Task SeedAsync(IServiceProvider services)
    {
        // Scope 1: Ensure DB and Store are ready
        using (var scope = services.CreateScope())
        {
            var provider = scope.ServiceProvider;
            var dbContext = provider.GetRequiredService<IdmtDbContext>();
            var tenantStoreContext = provider.GetRequiredService<IdmtTenantStoreDbContext>();
            
            await tenantStoreContext.Database.EnsureCreatedAsync();
            await dbContext.Database.EnsureCreatedAsync();

            var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            if (await tenantStore.TryGetAsync(DefaultTenantId) == null)
            {
                await tenantStore.TryAddAsync(new IdmtTenantInfo 
                { 
                    Id = DefaultTenantId, 
                    Identifier = DefaultTenantId, 
                    Name = "System Tenant",
                    IsActive = true 
                });
            }
        }

        // Scope 2: Seed Data with Tenant Context
        using (var scope = services.CreateScope())
        {
            var provider = scope.ServiceProvider;
            var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            var tenant = await tenantStore.TryGetAsync(DefaultTenantId)
                ?? throw new InvalidOperationException("Default tenant was not seeded.");

            // Set Tenant Context BEFORE resolving DbContext/Managers
            var tenantContextSetter = provider.GetRequiredService<IMultiTenantContextSetter>();
            var tenantContext = new MultiTenantContext<IdmtTenantInfo> { TenantInfo = tenant };
            tenantContextSetter.MultiTenantContext = tenantContext;

            var dbContext = provider.GetRequiredService<IdmtDbContext>();
            var roleManager = provider.GetRequiredService<RoleManager<IdmtRole>>();
            var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();

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
            }
        }
    }

    private static async Task EnsureRolesAsync(RoleManager<IdmtRole> roleManager)
    {
        var roles = new[]
        {
            IdmtDefaultRoleTypes.SysAdmin,
            IdmtDefaultRoleTypes.SysSupport,
            IdmtDefaultRoleTypes.TenantAdmin,
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
        // Here we use IgnoreQueryFilters to find the user regardless of current tenant context
        // BUT when creating, we rely on the context being set correctly.
        var existing = await dbContext.Users.IgnoreQueryFilters()
            .SingleOrDefaultAsync(u => u.Email == SysAdminEmail && u.TenantId == tenantId);

        var user = existing ?? new IdmtUser
        {
            Email = SysAdminEmail,
            NormalizedEmail = SysAdminEmail.ToUpperInvariant(),
            UserName = "sysadmin",
            NormalizedUserName = "SYSADMIN",
            EmailConfirmed = true,
            IsActive = true,
            TenantId = tenantId
        };

        if (existing is null)
        {
            var createResult = await userManager.CreateAsync(user, SysAdminPassword);
            if (!createResult.Succeeded)
            {
                var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
                throw new InvalidOperationException($"Failed to seed sysadmin user: {errors}");
            }
        }

        if (!await userManager.IsInRoleAsync(user, IdmtDefaultRoleTypes.SysAdmin))
        {
            await userManager.AddToRoleAsync(user, IdmtDefaultRoleTypes.SysAdmin);
        }

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

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (_connection != null)
        {
            await _connection.DisposeAsync();
            _connection = null;
        }
    }
}
