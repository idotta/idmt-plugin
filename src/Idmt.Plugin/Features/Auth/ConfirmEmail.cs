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
                    logger.LogError(ex, "Error confirming email for {Email} in tenant {TenantIdentifier}", PiiMasker.MaskEmail(request.Email), request.TenantIdentifier);
                    return IdmtErrors.General.Unexpected;
                }
            });
        }
    }

    public static RouteHandlerBuilder MapConfirmEmailEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/confirm-email", async Task<Results<Ok, ValidationProblem, BadRequest, InternalServerError>> (
            [FromBody] ConfirmEmailRequest request,
            [FromServices] IConfirmEmailHandler handler,
            [FromServices] IValidator<ConfirmEmailRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            // Decode Base64URL-encoded token
            string decodedToken;
            try
            {
                decodedToken = Base64Service.DecodeBase64UrlToken(request.Token);
            }
            catch (FormatException)
            {
                return TypedResults.BadRequest();
            }

            var decodedRequest = request with { Token = decodedToken };
            var result = await handler.HandleAsync(decodedRequest, cancellationToken: context.RequestAborted);

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
        .WithName(IdmtEndpointNames.ConfirmEmail)
        .WithSummary("Confirm email")
        .WithDescription("Confirm user email address");
    }

    public static RouteHandlerBuilder MapConfirmEmailDirectEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/confirm-email", async Task<Results<Ok, BadRequest>> (
            [FromQuery] string tenantIdentifier,
            [FromQuery] string email,
            [FromQuery] string token,
            [FromServices] IConfirmEmailHandler handler,
            HttpContext context) =>
        {
            // Decode Base64URL-encoded token
            string decodedToken;
            try
            {
                decodedToken = Base64Service.DecodeBase64UrlToken(token);
            }
            catch (FormatException)
            {
                return TypedResults.BadRequest();
            }

            var request = new ConfirmEmailRequest(tenantIdentifier, email, decodedToken);
            var result = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);

            if (result.IsError)
            {
                return TypedResults.BadRequest();
            }

            return TypedResults.Ok();
        })
        .WithName(IdmtEndpointNames.ConfirmEmailDirect)
        .WithSummary("Confirm email directly")
        .WithDescription("Directly confirms user email address via GET link from email");
    }
}
