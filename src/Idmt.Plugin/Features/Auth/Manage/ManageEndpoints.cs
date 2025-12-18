using System.Security.Claims;
using Idmt.Plugin.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Auth.Manage;

public static class ManageEndpoints
{
    public static void MapAuthManage(this IEndpointRouteBuilder endpoints)
    {
        var manage = endpoints.MapGroup("/manage")
            .RequireAuthorization()
            .WithTags("Authentication", "Management")
            .WithOpenApi();

        manage.MapPost("/users", RegisterUserAsync)
            .RequireAuthorization(AuthOptions.RequireSysUserPolicy)
            .WithSummary("Register user")
            .WithDescription("Register a new user for a tenant (Admin/System only)");

        manage.MapDelete("/users/{userId:guid}", UnregisterUserAsync)
            .RequireAuthorization(AuthOptions.RequireTenantManagerPolicy)
            .WithSummary("Delete user")
            .WithDescription("Delete a user within the same tenant (Admin/System only)");

        manage.MapPut("/users/{userId:guid}", UpdateUserAsync)
            .RequireAuthorization(AuthOptions.RequireTenantManagerPolicy)
            .WithSummary("Activate/Deactivate user")
            .WithDescription("Activate/Deactivate a user within the same tenant (Admin/System only)");

        manage.MapGet("/info", GetUserInfoAsync)
            .WithSummary("Get user info")
            .WithDescription("Get current user authentication info");

        manage.MapPut("/info", UpdateUserInfoAsync)
            .WithSummary("Update user info")
            .WithDescription("Update current user authentication info");
    }

    private static async Task<Results<Ok<RegisterUser.RegisterUserResponse>, ProblemHttpResult, ValidationProblem>> RegisterUserAsync(
        [FromQuery] bool useApiLinks,
        [FromBody] RegisterUser.RegisterUserRequest request,
        [FromServices] RegisterUser.IRegisterUserHandler handler,
        HttpContext context)
    {
        // Validate request data (email format, username length, role presence)
        if (request.Validate() is { } validationErrors)
        {
            return TypedResults.ValidationProblem(validationErrors);
        }

        var response = await handler.HandleAsync(useApiLinks, request, cancellationToken: context.RequestAborted);
        if (!response.Success)
        {
            return TypedResults.Problem(response.ErrorMessage, statusCode: response.StatusCode);
        }
        return TypedResults.Ok(response);
    }

    private static async Task<Results<Ok<UnregisterUser.UnregisterUserResponse>, ProblemHttpResult>> UnregisterUserAsync(
        [FromRoute] Guid userId,
        ClaimsPrincipal user,
        [FromServices] UnregisterUser.IUnregisterUserHandler handler,
        HttpContext context)
    {
        var result = await handler.HandleAsync(userId, cancellationToken: context.RequestAborted);
        if (!result.Success)
        {
            var errorMessage = result.Errors is not null ? string.Join("; ", result.Errors) : "Failed to unregister user";
            return TypedResults.Problem(errorMessage, statusCode: result.StatusCode);
        }
        return TypedResults.Ok(result);
    }

    private static async Task<Results<Ok, NotFound, ProblemHttpResult>> UpdateUserAsync(
        [FromRoute] Guid userId,
        [FromBody] UpdateUser.UpdateUserRequest request,
        [FromServices] UpdateUser.IUpdateUserHandler handler,
        HttpContext context)
    {
        var result = await handler.HandleAsync(userId, request, cancellationToken: context.RequestAborted);
        if (!result.Success)
        {
            return TypedResults.Problem(result.ErrorMessage, statusCode: StatusCodes.Status403Forbidden);
        }
        return TypedResults.Ok();
    }

    private static async Task<Results<Ok<GetUserInfo.GetUserInfoResponse>, NotFound>> GetUserInfoAsync(
        ClaimsPrincipal user,
        [FromServices] GetUserInfo.IGetUserInfoHandler handler,
        HttpContext context)
    {
        var result = await handler.HandleAsync(user, cancellationToken: context.RequestAborted);
        if (result == null)
        {
            return TypedResults.NotFound();
        }
        return TypedResults.Ok(result);
    }

    private static async Task<Results<Ok, ProblemHttpResult, ValidationProblem>> UpdateUserInfoAsync(
        [FromBody] UpdateUserInfo.UpdateUserInfoRequest request,
        ClaimsPrincipal user,
        [FromServices] UpdateUserInfo.IUpdateUserInfoHandler handler,
        [FromServices] IOptions<IdmtOptions> options,
        HttpContext context)
    {
        if (request.Validate(options.Value.Identity.Password) is { } errors)
        {
            return TypedResults.ValidationProblem(errors);
        }

        var result = await handler.HandleAsync(request, user, cancellationToken: context.RequestAborted);
        if (!result)
        {
            return TypedResults.Problem("Failed to update user info");
        }
        return TypedResults.Ok();
    }
}