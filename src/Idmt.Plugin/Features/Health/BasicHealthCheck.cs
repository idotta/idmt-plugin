using Idmt.Plugin.Persistence;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Idmt.Plugin.Features.Health;

public class BasicHealthCheck(IdmtDbContext dbContext, TimeProvider timeProvider) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            // Check database connectivity
            var canConnect = await dbContext.Database.CanConnectAsync();

            return HealthCheckResult.Healthy("Database is healthy",
                new Dictionary<string, object>
                {
                    { "database_connected", canConnect },
                    { "timestamp", timeProvider.GetUtcNow().UtcDateTime }
                });
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database is unhealthy", ex,
                new Dictionary<string, object>
                {
                    { "timestamp", timeProvider.GetUtcNow().UtcDateTime }
                });
        }
    }
}