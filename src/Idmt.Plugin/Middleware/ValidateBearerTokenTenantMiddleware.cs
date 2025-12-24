using Finbuckle.MultiTenant.Abstractions;
using Microsoft.AspNetCore.Http;

namespace Idmt.Plugin.Middleware;

public class ValidateBearerTokenTenantMiddleware(IMultiTenantContextAccessor tenantContextAccessor) : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // Validate tenant isolation on bearer token authentication
        // When a bearer token is used, ensure the token's tenant claim matches the current tenant context
        if (context.User.Identity?.IsAuthenticated == true &&
            context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            if (!ValidateTokenTenant(context, tenantContextAccessor))
            {
                return; // Tenant validation failed, response already set, don't call next
            }
        }

        await next(context);
    }

    /// <summary>
    /// Validates that the tenant in the bearer token matches the currently resolved tenant.
    /// This prevents users from using a token from Tenant A to access Tenant B resources.
    /// Returns false if validation fails and sets appropriate response, true if validation passes.
    /// </summary>
    private bool ValidateTokenTenant(
        HttpContext context,
        IMultiTenantContextAccessor tenantContextAccessor)
    {
        try
        {
            var currentTenant = tenantContextAccessor.MultiTenantContext?.TenantInfo;
            if (currentTenant == null)
            {
                return true; // No tenant context resolved, allow the request
            }

            // Get the tenant claim type from configuration
            string tenantClaimType = "__tenant__";

            // Extract tenant claim from token
            var tokenTenantClaim = context.User.FindFirst(tenantClaimType)?.Value;

            // If no tenant claim is present in the token, reject the request for security
            if (string.IsNullOrEmpty(tokenTenantClaim))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return false;
            }

            // Validate that the token's tenant matches the current request's tenant
            if (!tokenTenantClaim.Equals(currentTenant.Id, StringComparison.Ordinal))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return false;
            }

            return true; // Validation passed
        }
        catch
        {
            return false; // On error, reject the request
        }
    }
}
