using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features.Sys;

public static class GetSystemInfo
{
    public sealed record SystemInfoResponse
    {
        public string ApplicationName { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Environment { get; set; } = string.Empty;
        public TenantInfo? CurrentTenant { get; set; }
        public DateTime ServerTime { get; set; }
        public List<string> Features { get; set; } = [];
    }

    public sealed record TenantInfo
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public string? Identifier { get; set; }
    }

    public static RouteHandlerBuilder MapGetSystemInfoEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/info", Task<Ok<SystemInfoResponse>> (
            [FromServices] IMultiTenantContextAccessor tenantAccessor) =>
        {
            var currentTenant = tenantAccessor.MultiTenantContext?.TenantInfo;

            var systemInfo = new SystemInfoResponse
            {
                ApplicationName = "IDMT Sample API",
                Version = "1.0.0",
                Environment = System.Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production",
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

            return Task.FromResult(TypedResults.Ok(systemInfo));
        })
        .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
        .WithSummary("Detailed system information");
    }
}
