using Microsoft.AspNetCore.Mvc;
using Finbuckle.MultiTenant;
using Idotta.Idmt.Plugin.Models;
using Microsoft.EntityFrameworkCore;

namespace Idotta.Idmt.Sample.Controllers;

/// <summary>
/// Health and status controller
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class HealthController : ControllerBase
{
    private readonly IdmtDbContext _dbContext;
    private readonly IMultiTenantContextAccessor _tenantAccessor;

    public HealthController(
        IdmtDbContext dbContext,
        IMultiTenantContextAccessor tenantAccessor)
    {
        _dbContext = dbContext;
        _tenantAccessor = tenantAccessor;
    }

    /// <summary>
    /// Basic health check endpoint
    /// </summary>
    /// <returns>Health status</returns>
    [HttpGet]
    [ProducesResponseType(typeof(HealthResponse), 200)]
    public async Task<ActionResult<HealthResponse>> GetHealth()
    {
        var currentTenant = _tenantAccessor.MultiTenantContext?.TenantInfo;
        
        try
        {
            // Check database connectivity
            var canConnect = await _dbContext.Database.CanConnectAsync();
            
            // Get user count for current tenant
            var tenantId = currentTenant?.Id ?? "default";
            var userCount = await _dbContext.Users
                .Where(u => u.TenantId == tenantId)
                .CountAsync();

            return Ok(new HealthResponse
            {
                Status = "Healthy",
                DatabaseConnected = canConnect,
                CurrentTenant = currentTenant?.Id ?? "No tenant",
                TenantUserCount = userCount,
                Timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            return Ok(new HealthResponse
            {
                Status = "Unhealthy",
                DatabaseConnected = false,
                CurrentTenant = currentTenant?.Id ?? "No tenant",
                TenantUserCount = 0,
                Timestamp = DateTime.UtcNow,
                Error = ex.Message
            });
        }
    }

    /// <summary>
    /// Detailed system information
    /// </summary>
    /// <returns>System information</returns>
    [HttpGet("info")]
    [ProducesResponseType(typeof(SystemInfoResponse), 200)]
    public ActionResult<SystemInfoResponse> GetSystemInfo()
    {
        var currentTenant = _tenantAccessor.MultiTenantContext?.TenantInfo;
        
        return Ok(new SystemInfoResponse
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
            ServerTime = DateTime.UtcNow,
            Features = new List<string>
            {
                "Multi-Tenant Support",
                "JWT Authentication", 
                "ASP.NET Core Identity",
                "Vertical Slice Architecture",
                "OpenAPI/Swagger Documentation"
            }
        });
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
    public List<string> Features { get; set; } = new();
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