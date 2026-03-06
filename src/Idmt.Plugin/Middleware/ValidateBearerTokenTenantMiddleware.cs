using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Middleware;

public class ValidateBearerTokenTenantMiddleware(
    IMultiTenantContextAccessor tenantContextAccessor,
    IOptions<IdmtOptions> idmtOptions,
    ILogger<ValidateBearerTokenTenantMiddleware> logger) : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // Validate tenant isolation on bearer token authentication.
        // When a bearer token is used, ensure the token's tenant claim matches the current
        // tenant context so that a token issued for Tenant A cannot be used against Tenant B.
        if (context.User.Identity?.IsAuthenticated == true &&
            context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            if (!await ValidateTokenTenantAsync(context, tenantContextAccessor))
            {
                return; // Tenant validation failed, response already set, don't call next
            }
        }

        await next(context);
    }

    /// <summary>
    /// Validates that the tenant in the bearer token matches the currently resolved tenant.
    /// This prevents users from using a token from Tenant A to access Tenant B resources.
    /// Returns false if validation fails and writes a ProblemDetails JSON body, true if
    /// validation passes.
    /// </summary>
    private async Task<bool> ValidateTokenTenantAsync(
        HttpContext context,
        IMultiTenantContextAccessor tenantContextAccessor)
    {
        try
        {
            var currentTenant = tenantContextAccessor.MultiTenantContext?.TenantInfo;
            if (currentTenant is null)
            {
                logger.LogWarning("Bearer token authentication used but no tenant context was resolved. Rejecting request.");
                await WriteProblemDetailsAsync(
                    context,
                    StatusCodes.Status401Unauthorized,
                    "Unauthorized",
                    "No tenant context could be resolved for this request.");
                return false;
            }

            // Get the tenant claim type from configuration
            var tenantClaimType = idmtOptions.Value.MultiTenant.StrategyOptions.GetValueOrDefault(
                IdmtMultiTenantStrategy.Claim,
                IdmtMultiTenantStrategy.DefaultClaim);

            // Extract tenant claim from token
            var tokenTenantClaim = context.User.FindFirst(tenantClaimType)?.Value;

            // If no tenant claim is present in the token, reject the request for security
            if (string.IsNullOrEmpty(tokenTenantClaim))
            {
                await WriteProblemDetailsAsync(
                    context,
                    StatusCodes.Status401Unauthorized,
                    "Unauthorized",
                    "The bearer token does not contain a required tenant claim.");
                return false;
            }

            // Validate that the token's tenant identifier matches the current request's tenant
            // identifier. The factory adds tenantInfo.Identifier to the claim, so we compare
            // with Identifier, not Id.
            if (!tokenTenantClaim.Equals(currentTenant.Identifier, StringComparison.Ordinal))
            {
                await WriteProblemDetailsAsync(
                    context,
                    StatusCodes.Status403Forbidden,
                    "Forbidden",
                    "The bearer token was not issued for the requested tenant.");
                return false;
            }

            return true; // Validation passed
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Error validating bearer token tenant");
            await WriteProblemDetailsAsync(
                context,
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "An error occurred while validating the bearer token tenant.");
            return false;
        }
    }

    private static async Task WriteProblemDetailsAsync(
        HttpContext context,
        int statusCode,
        string title,
        string detail)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/problem+json";
        var problemDetails = new ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Detail = detail
        };
        await context.Response.WriteAsJsonAsync(problemDetails, problemDetails.GetType(),
            options: null, contentType: "application/problem+json",
            cancellationToken: context.RequestAborted);
    }
}
