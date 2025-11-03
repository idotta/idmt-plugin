using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features.Auth.Manage;

public static class ManageEndpoints
{
    public static void MapAuthManage(this IEndpointRouteBuilder endpoints)
    {
        var manage = endpoints.MapGroup("/manage")
            .RequireAuthorization()
            .WithTags("Authentication", "Management")
            .WithOpenApi();

        manage.MapPost("/register", RegisterUserAsync)
            .RequireAuthorization(policy => policy.RequireRole(IdmtDefaultRoleTypes.SysAdmin, IdmtDefaultRoleTypes.SysSupport, IdmtDefaultRoleTypes.TenantAdmin))
            .WithSummary("Register user")
            .WithDescription("Register a new user for a tenant (Admin/System only)");
    }

    private static async Task<Results<Ok<RegisterUser.RegisterUserResponse>, ProblemHttpResult, ValidationProblem>> RegisterUserAsync(
        [FromBody] RegisterUser.RegisterUserRequest request,
        [FromServices] RegisterUser.IRegisterUserHandler handler,
        HttpContext context)
    {
        // Validate request data (email format, username length, role presence)
        if (request.Validate() is { } validationErrors)
        {
            return TypedResults.ValidationProblem(validationErrors);
        }

        var response = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
        if (!response.Success)
        {
            return TypedResults.Problem(response.ErrorMessage, statusCode: response.StatusCode);
        }
        return TypedResults.Ok(response);
    }
}