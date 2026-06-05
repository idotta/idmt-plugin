using Finbuckle.MultiTenant.Abstractions;
using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Persistence;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idmt.Spike.Host.Seeding;

/// <summary>Idempotent bring-up: schema, OpenIddict client + scopes, tenants, and a seeded sys admin.</summary>
public static class IdmtSpikeSeeder
{
    public const string ClientId = "spike-client";
    public const string ClientSecret = "spike-secret";

    public const string TenantA = "acme";
    public const string TenantB = "globex";

    public const string SysAdminEmail = "sysadmin@example.com";

    public static async Task SeedAsync(IServiceProvider sp, CancellationToken ct = default)
    {
        await using var scope = sp.CreateAsyncScope();
        var s = scope.ServiceProvider;

        await s.GetRequiredService<IdmtIdentityDbContext>().Database.EnsureCreatedAsync(ct);
        await s.GetRequiredService<IdmtTenantDbContext>().Database.EnsureCreatedAsync(ct);
        await s.GetRequiredService<IdmtOpenIddictDbContext>().Database.EnsureCreatedAsync(ct);
        await s.GetRequiredService<IdmtTenantStoreDbContext>().Database.EnsureCreatedAsync(ct);

        // Tenants
        var store = s.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        foreach (var id in new[] { TenantA, TenantB })
        {
            if (await store.GetByIdentifierAsync(id) is null)
            {
                await store.AddAsync(new IdmtTenantInfo(id, id));
            }
        }

        // OpenIddict client (client-credentials + token endpoint + scopes)
        var apps = s.GetRequiredService<IOpenIddictApplicationManager>();
        if (await apps.FindByClientIdAsync(ClientId, ct) is null)
        {
            await apps.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                ClientType = ClientTypes.Confidential,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + "api",
                    Permissions.Prefixes.Scope + "support",
                },
            }, ct);
        }

        // Sys admin user with TenantAccess to tenant A.
        var users = s.GetRequiredService<UserManager<IdmtUser>>();
        var idDb = s.GetRequiredService<IdmtIdentityDbContext>();
        var admin = await users.FindByEmailAsync(SysAdminEmail);
        if (admin is null)
        {
            admin = new IdmtUser
            {
                UserName = SysAdminEmail,
                Email = SysAdminEmail,
                SysRole = SysRoleKind.SysAdmin,
            };
            await users.CreateAsync(admin, "SysAdmin1!");

            idDb.TenantAccess.Add(new TenantAccess { UserId = admin.Id, TenantId = TenantA });
            await idDb.SaveChangesAsync(ct);
        }
    }
}
