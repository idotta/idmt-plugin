using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;

namespace Idmt.Plugin.Features.Health;

/// <summary>
/// Health and status endpoints using minimal APIs
/// </summary>
public static class HealthEndpoints
{
    /// <summary>
    /// Maps health check endpoints
    /// </summary>
    /// <param name="app">The web application</param>
    /// <returns>The route group builder</returns>
    public static RouteGroupBuilder MapHealthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/health")
            .WithTags("Health")
            ;

        // Basic health check
        group.MapGet("/", GetHealthAsync)
            .WithName("GetHealth")
            .WithSummary("Basic health check endpoint")
            .Produces<HealthResponse>(200);

        // System information
        group.MapGet("/info", GetSystemInfoAsync)
            .WithName("GetSystemInfo")
            .WithSummary("Detailed system information")
            .Produces<SystemInfoResponse>(200);

        return group;
    }

    /// <summary>
    /// Basic health check endpoint
    /// </summary>
    /// <param name="dbContext">Database context from DI</param>
    /// <param name="tenantAccessor">Tenant accessor from DI</param>
    /// <returns>Health status</returns>
    private static async Task<IResult> GetHealthAsync(
        [FromServices] IdmtDbContext dbContext,
        [FromServices] IMultiTenantContextAccessor tenantAccessor)
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
                .CountAsync();

            var healthResponse = new HealthResponse
            {
                Status = "Healthy",
                DatabaseConnected = canConnect,
                CurrentTenant = currentTenant?.Id ?? "No tenant",
                TenantUserCount = userCount,
                Timestamp = DT.UtcNow
            };

            return Results.Ok(healthResponse);
        }
        catch (Exception ex)
        {
            var healthResponse = new HealthResponse
            {
                Status = "Unhealthy",
                DatabaseConnected = false,
                CurrentTenant = currentTenant?.Id ?? "No tenant",
                TenantUserCount = 0,
                Timestamp = DT.UtcNow,
                Error = ex.Message
            };

            return Results.Ok(healthResponse);
        }
    }

    /// <summary>
    /// Detailed system information
    /// </summary>
    /// <param name="tenantAccessor">Tenant accessor from DI</param>
    /// <returns>System information</returns>
    private static IResult GetSystemInfoAsync(
        [FromServices] IMultiTenantContextAccessor tenantAccessor)
    {
        var currentTenant = tenantAccessor.MultiTenantContext?.TenantInfo;
        
        var systemInfo = new SystemInfoResponse
        {
            ApplicationName = "IDMT Sample API",
            Version = "1.0.0",
            Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production",
            CurrentTenant = currentTenant != null ? new TenantInfo
            {
                Id = currentTenant.Id,
                Name = currentTenant.Name,
                Identifier = currentTenant.Identifier
            } : null,
            ServerTime = DT.UtcNow,
            Features =
            [
                "Multi-Tenant Support",
                "Vertical Slice Architecture",
                "Minimal APIs",
                "OpenAPI/Swagger Documentation"
            ]
        };

        return Results.Ok(systemInfo);
    }
}

/// <summary>
/// Health check response
/// </summary>
public class HealthResponse
{
    public string Status { get; set; } = string.Empty;
    public bool DatabaseConnected { get; set; }
    public string CurrentTenant { get; set; } = string.Empty;
    public int TenantUserCount { get; set; }
    public DateTime Timestamp { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// System information response
/// </summary>
public class SystemInfoResponse
{
    public string ApplicationName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Environment { get; set; } = string.Empty;
    public TenantInfo? CurrentTenant { get; set; }
    public DateTime ServerTime { get; set; }
    public List<string> Features { get; set; } = [];
}

/// <summary>
/// Tenant information for responses
/// </summary>
public class TenantInfo
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public string? Identifier { get; set; }
}