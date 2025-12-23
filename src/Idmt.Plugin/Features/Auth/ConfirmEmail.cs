using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.Plugin.Features.Auth;

public static class ConfirmEmail
{
    public sealed record ConfirmEmailRequest(string TenantIdentifier, string Email, string Token);

    public sealed record ConfirmEmailResponse(bool Success, string? Message = null);

    public interface IConfirmEmailHandler
    {
        Task<ConfirmEmailResponse> HandleAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ConfirmEmailHandler(IServiceProvider serviceProvider) : IConfirmEmailHandler
    {
        public async Task<ConfirmEmailResponse> HandleAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default)
        {
            using var scope = serviceProvider.CreateScope();
            var provider = scope.ServiceProvider;

            var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            var tenantInfo = await tenantStore.GetByIdentifierAsync(request.TenantIdentifier);
            if (tenantInfo is null || !tenantInfo.IsActive)
            {
                return new ConfirmEmailResponse(false, "Invalid tenant");
            }
            // Set Tenant Context BEFORE resolving DbContext/Managers
            var tenantContextSetter = provider.GetRequiredService<IMultiTenantContextSetter>();
            var tenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);
            tenantContextSetter.MultiTenantContext = tenantContext;

            var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
            try
            {
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user == null)
                {
                    return new ConfirmEmailResponse(false, "User not found");
                }

                // Reset password using the token
                var result = await userManager.ConfirmEmailAsync(user, request.Token!);

                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return new ConfirmEmailResponse(false, errors);
                }

                return new ConfirmEmailResponse(true, null);
            }
            catch (Exception ex)
            {
                return new ConfirmEmailResponse(false, ex.Message);
            }
        }
    }

    public static Dictionary<string, string[]>? Validate(this ConfirmEmailRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrEmpty(request.TenantIdentifier))
        {
            errors["TenantIdentifier"] = ["Tenant identifier is required"];
        }
        if (string.IsNullOrEmpty(request.Email))
        {
            errors["Email"] = ["Email is required"];
        }
        if (!Validators.IsValidEmail(request.Email))
        {
            errors["Email"] = ["Invalid email address"];
        }
        if (string.IsNullOrEmpty(request.Token))
        {
            errors["Token"] = ["Token is required"];
        }

        return errors.Count == 0 ? null : errors;
    }

    public static RouteHandlerBuilder MapConfirmEmailEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/confirmEmail", async Task<Results<Ok<ConfirmEmailResponse>, ValidationProblem, ForbidHttpResult>> (
            [FromQuery] string tenantIdentifier,
            [FromQuery] string email,
            [FromQuery] string token,
            [FromServices] IConfirmEmailHandler handler,
            IServiceProvider sp,
            HttpContext context) =>
        {
            var request = new ConfirmEmailRequest(tenantIdentifier, email, token);
            if (request.Validate() is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var result = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);

            if (!result.Success)
            {
                return TypedResults.Forbid();
            }
            return TypedResults.Ok(result);
        })
        .WithName(ApplicationOptions.ConfirmEmailEndpointName)
        .WithSummary("Confirm email")
        .WithDescription("Confirm user email address");
    }
}
