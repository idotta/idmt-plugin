using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features.System;

public static class SystemEndpoints
{
    public static void MapSystemEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/health", GetSystemInfoAsync)
            .WithTags("Health")
            .WithOpenApi()
            .WithSummary("Get system info")
            .WithDescription("Get system information");
    }

    private static Ok<SystemInfo> GetSystemInfoAsync(HttpContext context)
    {
        var systemInfo = new SystemInfo
        {
            Name = "Idmt Plugin",
            Version = "1.0.0",
            Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production",
            Features = [
                "Multi-Tenant Support",
                "Vertical Slice Architecture",
                "Minimal APIs",
                "OpenAPI/Swagger Documentation"
            ],
            ServerTime = DateTime.UtcNow
        };
        return TypedResults.Ok(systemInfo);
    }

    public sealed record SystemInfo
    {
        public string Name { get; init; } = string.Empty;
        public string Version { get; init; } = string.Empty;
        public string Environment { get; init; } = string.Empty;
        public List<string> Features { get; init; } = [];
        public DateTime ServerTime { get; init; } = DateTime.UtcNow;
    }
}