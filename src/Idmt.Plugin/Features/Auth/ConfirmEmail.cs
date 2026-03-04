using ErrorOr;
using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Auth;

public static class ConfirmEmail
{
    public sealed record ConfirmEmailRequest(string TenantIdentifier, string Email, string Token);

    public interface IConfirmEmailHandler
    {
        Task<ErrorOr<Success>> HandleAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ConfirmEmailHandler(ITenantOperationService tenantOps, ILogger<ConfirmEmailHandler> logger) : IConfirmEmailHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default)
        {
            return await tenantOps.ExecuteInTenantScopeAsync(request.TenantIdentifier, async provider =>
            {
                var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
                try
                {
                    var user = await userManager.FindByEmailAsync(request.Email);
                    if (user == null)
                    {
                        return IdmtErrors.Email.ConfirmationFailed;
                    }

                    var result = await userManager.ConfirmEmailAsync(user, request.Token!);

                    if (!result.Succeeded)
                    {
                        return IdmtErrors.Email.ConfirmationFailed;
                    }

                    return Result.Success;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error confirming email for {Email} in tenant {TenantIdentifier}", request.Email, request.TenantIdentifier);
                    return IdmtErrors.General.Unexpected;
                }
            });
        }
    }

    public static RouteHandlerBuilder MapConfirmEmailEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/confirm-email", async Task<Results<Ok, ValidationProblem, BadRequest, InternalServerError>> (
            [FromQuery] string tenantIdentifier,
            [FromQuery] string email,
            [FromQuery] string token,
            [FromServices] IConfirmEmailHandler handler,
            [FromServices] IValidator<ConfirmEmailRequest> validator,
            HttpContext context) =>
        {
            var request = new ConfirmEmailRequest(tenantIdentifier, email, token);
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var result = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);

            if (result.IsError)
            {
                return result.FirstError.Type switch
                {
                    ErrorType.NotFound => TypedResults.BadRequest(),
                    ErrorType.Failure => TypedResults.BadRequest(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.Ok();
        })
        .WithName(ApplicationOptions.ConfirmEmailEndpointName)
        .WithSummary("Confirm email")
        .WithDescription("Confirm user email address");
    }
}
