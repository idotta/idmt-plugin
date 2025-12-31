using Idmt.Plugin.Features.Admin;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features;

public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var admin = endpoints.MapGroup("/admin")
            .WithTags("Admin");

        admin.MapCreateTenantEndpoint();
        admin.MapDeleteTenantEndpoint();
        admin.MapGetUserTenantsEndpoint();
        admin.MapGrantTenantAccessEndpoint();
        admin.MapRevokeTenantAccessEndpoint();
        admin.MapGetSystemInfoEndpoint();
        admin.MapGetAllTenantsEndpoint();
    }
}