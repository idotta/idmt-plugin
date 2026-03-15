using System.Security.Claims;
using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Idmt.Plugin.Features.Manage;

public static class GetUserInfo
{
    public sealed record GetUserInfoResponse(
        string Id,
        string Email,
        string UserName,
        IReadOnlyList<string> Roles,
        string TenantIdentifier,
        string TenantName
    );

    public interface IGetUserInfoHandler
    {
        Task<ErrorOr<GetUserInfoResponse>> HandleAsync(ClaimsPrincipal user, CancellationToken cancellationToken = default);
    }

    internal sealed class GetUserInfoHandler(UserManager<IdmtUser> userManager, IMultiTenantStore<IdmtTenantInfo> tenantStore) : IGetUserInfoHandler
    {
        public async Task<ErrorOr<GetUserInfoResponse>> HandleAsync(ClaimsPrincipal user, CancellationToken cancellationToken = default)
        {
            var userEmail = user.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(userEmail))
            {
                return IdmtErrors.User.ClaimsNotFound;
            }

            var appUser = await userManager.FindByEmailAsync(userEmail);
            if (appUser == null || !appUser.IsActive)
            {
                return IdmtErrors.User.NotFound;
            }

            var roles = (await userManager.GetRolesAsync(appUser)).OrderBy(r => r).ToList();
            if (roles.Count == 0) return IdmtErrors.User.NoRolesAssigned;

            var tenant = await tenantStore.GetAsync(appUser.TenantId);
            if (tenant is null) return IdmtErrors.Tenant.NotFound;

            return new GetUserInfoResponse(
                appUser.Id.ToString(),
                appUser.Email ?? string.Empty,
                appUser.UserName ?? string.Empty,
                roles,
                tenant.Identifier ?? string.Empty,
                tenant.Name ?? string.Empty
            );
        }
    }

    public static RouteHandlerBuilder MapGetUserInfoEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/info", async Task<Results<Ok<GetUserInfoResponse>, NotFound, BadRequest, ProblemHttpResult>> (
            ClaimsPrincipal user,
            [FromServices] IGetUserInfoHandler handler,
            HttpContext context) =>
        {
            var result = await handler.HandleAsync(user, cancellationToken: context.RequestAborted);
            if (result.IsError)
            {
                return result.FirstError.Type switch
                {
                    ErrorType.NotFound => TypedResults.NotFound(),
                    ErrorType.Validation => TypedResults.BadRequest(),
                    _ => TypedResults.Problem(result.FirstError.Description, statusCode: StatusCodes.Status500InternalServerError),
                };
            }
            return TypedResults.Ok(result.Value);
        })
        .WithSummary("Get user info")
        .WithDescription("Get current user authentication info")
        .RequireAuthorization();
    }
}
