using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Services;

internal sealed class TokenRevocationCleanupService(
    IServiceScopeFactory scopeFactory,
    ILogger<TokenRevocationCleanupService> logger,
    TimeSpan? interval = null) : BackgroundService
{
    private readonly TimeSpan _interval = interval ?? TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, stoppingToken);

                using var scope = scopeFactory.CreateScope();
                var revocationService = scope.ServiceProvider.GetRequiredService<ITokenRevocationService>();
                await revocationService.CleanupExpiredAsync(stoppingToken);

                logger.LogDebug("Token revocation cleanup completed");
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // Graceful shutdown
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during token revocation cleanup");
            }
        }
    }
}
