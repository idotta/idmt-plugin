using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Services;

public sealed class IdmtLinkGenerator(
    LinkGenerator linkGenerator,
    IMultiTenantContextAccessor multiTenantContextAccessor,
    IHttpContextAccessor httpContextAccessor,
    ILogger<IdmtLinkGenerator> logger)
{
    public string GeneratePasswordResetLink(string email, string token)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }

        // Generate password setup URL
        var routeValues = new RouteValueDictionary()
        {
            ["tenantId"] = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty,
            ["email"] = email,
            ["token"] = token,
        };

        var passwordSetupUrl = linkGenerator.GetUriByName(
            httpContextAccessor.HttpContext,
            ApplicationOptions.PasswordResetEndpointName,
            routeValues)
            ?? throw new NotSupportedException($"Could not find endpoint named '{ApplicationOptions.PasswordResetEndpointName}'.");

        logger.LogInformation("Password reset link generated for {Email}. Tenant: {TenantId}.", email, multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty);

        return passwordSetupUrl;
    }

    public string GenerateConfirmEmailLink(string email, string token)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }

        var routeValues = new RouteValueDictionary()
        {
            ["tenantId"] = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty,
            ["email"] = email,
            ["token"] = token,
        };

        var confirmEmailUrl = linkGenerator.GetUriByName(httpContextAccessor.HttpContext, ApplicationOptions.ConfirmEmailEndpointName, routeValues)
            ?? throw new NotSupportedException($"Could not find endpoint named '{ApplicationOptions.ConfirmEmailEndpointName}'.");

        return confirmEmailUrl;
    }
}