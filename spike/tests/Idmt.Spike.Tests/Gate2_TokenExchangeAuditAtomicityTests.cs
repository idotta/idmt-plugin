using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Persistence;
using Idmt.Spike.Host.Seeding;
using Idmt.Spike.Host.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Idmt.Spike.Tests;

/// <summary>
/// Gate 2: the support-token mint runs the TenantAccess gate and writes its audit
/// row in the SAME transaction as the OpenIddict token-store insert. A failed
/// audit leaves neither a token nor an audit row.
/// </summary>
public sealed class Gate2_TokenExchangeAuditAtomicityTests(WebApplicationFactory<Program> factory)
    : BaseSpikeIntegrationTest(factory)
{
    [Fact]
    public async Task Success_WritesTokenAndAudit_TogetherAfterGate()
    {
        var adminId = await AdminIdAsync();
        var (tokens, audits) = await CountsAsync();

        using (var scope = Factory.Services.CreateScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<SupportTokenService>();
            var result = await svc.IssueAsync(adminId, IdmtSpikeSeeder.TenantA, "investigating ticket 42", failAudit: false, default);
            Assert.True(result.Allowed);
        }

        var (tokensAfter, auditsAfter) = await CountsAsync();
        Assert.Equal(tokens + 1, tokensAfter);
        Assert.Equal(audits + 1, auditsAfter);
    }

    [Fact]
    public async Task AuditFailure_RollsBack_AlreadyPersistedToken()
    {
        var adminId = await AdminIdAsync();
        var (tokens, audits) = await CountsAsync();

        // The token is persisted by CreateAsync inside the transaction; the audit
        // write then fails at the database (NOT NULL violation). Because the
        // transaction never commits, the already-written token is rolled back.
        using (var scope = Factory.Services.CreateScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<SupportTokenService>();
            await Assert.ThrowsAnyAsync<DbUpdateException>(() =>
                svc.IssueAsync(adminId, IdmtSpikeSeeder.TenantA, "boom", failAudit: true, default));
        }

        // Read committed state from a FRESH scope: neither the token nor the audit survived.
        var (tokensAfter, auditsAfter) = await CountsAsync();
        Assert.Equal(tokens, tokensAfter);
        Assert.Equal(audits, auditsAfter);
    }

    [Fact]
    public async Task Gate_DeniesTenant_WithoutAccess()
    {
        var adminId = await AdminIdAsync();

        using var scope = Factory.Services.CreateScope();
        var svc = scope.ServiceProvider.GetRequiredService<SupportTokenService>();

        // The seeded admin has access to tenant A only.
        var result = await svc.IssueAsync(adminId, IdmtSpikeSeeder.TenantB, "no access", failAudit: false, default);

        Assert.False(result.Allowed);
        Assert.Equal("no_tenant_access", result.Denied);
    }

    private async Task<Guid> AdminIdAsync()
    {
        using var scope = Factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdmtUser>>();
        var admin = await users.FindByEmailAsync(IdmtSpikeSeeder.SysAdminEmail);
        return admin!.Id;
    }

    private async Task<(long Tokens, int Audits)> CountsAsync()
    {
        using var scope = Factory.Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var oidb = scope.ServiceProvider.GetRequiredService<IdmtOpenIddictDbContext>();
        return (await manager.CountAsync(), await oidb.SupportAudits.CountAsync());
    }
}
