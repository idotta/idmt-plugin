using Idmt.Plugin.Features.Manage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features;

public static class ManageEndpoints
{
    public static void MapAuthManageEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var manage = endpoints.MapGroup("/manage")
            .RequireAuthorization()
            .WithTags("Authentication", "Management");

        manage.MapRegisterUserEndpoint();
        manage.MapUnregisterUserEndpoint();
        manage.MapUpdateUserEndpoint();
        manage.MapGetUserInfoEndpoint();
        manage.MapUpdateUserInfoEndpoint();
    }
}