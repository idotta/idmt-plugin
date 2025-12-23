using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Services;

public interface IIdmtLinkGenerator
{
    string GenerateConfirmEmailApiLink(string email, string token);
    string GenerateConfirmEmailFormLink(string email, string token);
    string GeneratePasswordResetApiLink(string email, string token);
    string GeneratePasswordResetFormLink(string email, string token);
}

public sealed class IdmtLinkGenerator(
    LinkGenerator linkGenerator,
    IMultiTenantContextAccessor multiTenantContextAccessor,
    IHttpContextAccessor httpContextAccessor,
    IOptions<IdmtOptions> options,
    ILogger<IdmtLinkGenerator> logger) : IIdmtLinkGenerator
{
    public string GenerateConfirmEmailApiLink(string email, string token)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }

        var routeValues = new RouteValueDictionary()
        {
            ["tenantIdentifier"] = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Identifier ?? string.Empty,
            ["email"] = email,
            ["token"] = token,
        };

        var confirmEmailUrl = linkGenerator.GetUriByName(httpContextAccessor.HttpContext, ApplicationOptions.ConfirmEmailEndpointName, routeValues)
            ?? throw new NotSupportedException($"Could not find endpoint named '{ApplicationOptions.ConfirmEmailEndpointName}'.");

        logger.LogInformation("Confirm email link generated for {Email}. Tenant: {TenantId}.", email, multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty);

        return confirmEmailUrl;
    }

    public string GenerateConfirmEmailFormLink(string email, string token)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }

        var clientUrl = options.Value.Application.ClientUrl;
        var confirmEmailFormPath = options.Value.Application.ConfirmEmailFormPath;

        if (string.IsNullOrEmpty(clientUrl))
        {
            throw new InvalidOperationException("Client URL is not configured.");
        }

        var queryParams = new Dictionary<string, string?>
        {
            ["tenantIdentifier"] = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Identifier ?? string.Empty,
            ["email"] = email,
            ["token"] = token,
        };

        var uri = Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(
            $"{clientUrl.TrimEnd('/')}/{confirmEmailFormPath.TrimStart('/')}",
            queryParams);

        logger.LogInformation("Confirm email link generated for {Email}. Tenant: {TenantId}.", email, multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty);

        return uri;
    }

    public string GeneratePasswordResetApiLink(string email, string token)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }

        // Generate password setup URL
        var routeValues = new RouteValueDictionary()
        {
            ["tenantIdentifier"] = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Identifier ?? string.Empty,
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

    public string GeneratePasswordResetFormLink(string email, string token)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }

        var clientUrl = options.Value.Application.ClientUrl;
        var resetPasswordFormPath = options.Value.Application.ResetPasswordFormPath;

        if (string.IsNullOrEmpty(clientUrl))
        {
            throw new InvalidOperationException("Client URL is not configured.");
        }

        var queryParams = new Dictionary<string, string?>
        {
            ["tenantIdentifier"] = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Identifier ?? string.Empty,
            ["email"] = email,
            ["token"] = token,
        };

        var uri = Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(
            $"{clientUrl.TrimEnd('/')}/{resetPasswordFormPath.TrimStart('/')}",
            queryParams);

        logger.LogInformation("Password reset link generated for {Email}. Tenant: {TenantId}.", email, multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty);

        return uri;
    }
}