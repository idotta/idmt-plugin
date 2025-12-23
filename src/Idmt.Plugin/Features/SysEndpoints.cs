using Idmt.Plugin.Features.Sys;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features;

public static class SysEndpoints
{
    public static void MapSysEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var sys = endpoints.MapGroup("/sys")
            .WithTags("System");

        sys.MapCreateTenantEndpoint();
        sys.MapDeleteTenantEndpoint();
        sys.MapGetUserTenantsEndpoint();
        sys.MapGrantTenantAccessEndpoint();
        sys.MapRevokeTenantAccessEndpoint();
        sys.MapGetSystemInfoEndpoint();
    }
}