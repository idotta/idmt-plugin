using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Idmt.Plugin.Features.Health;

public class BasicHealthCheck(IdmtDbContext dbContext, IMultiTenantContextAccessor tenantAccessor) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var currentTenant = tenantAccessor.MultiTenantContext?.TenantInfo;

        try
        {
            // Check database connectivity
            var canConnect = await dbContext.Database.CanConnectAsync();

            // Get user count for current tenant
            var tenantId = currentTenant?.Id ?? "default";
            var userCount = await dbContext.Users
                .Where(u => u.TenantId == tenantId)
                .CountAsync(cancellationToken: cancellationToken);


            return HealthCheckResult.Healthy("Database and tenant user count are healthy",
                new Dictionary<string, object>
                {
                    { "database_connected", canConnect },
                    { "current_tenant", currentTenant?.Id ?? "No tenant" },
                    { "tenant_user_count", userCount },
                    { "timestamp", DT.UtcNow }
                });
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database and tenant user count are unhealthy", ex,
                new Dictionary<string, object>
                {
                    { "error", ex.Message },
                    { "timestamp", DT.UtcNow }
                });
        }
    }
}