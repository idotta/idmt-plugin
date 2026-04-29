using System.Text;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Services;

public interface IIdmtLinkGenerator
{
    string GenerateConfirmEmailLink(string email, string token);
    string GeneratePasswordResetLink(string email, string token);

    /// <summary>
    /// Generates a confirm-email-change link to be sent to the staged new email address.
    /// Links to the client form at <see cref="ApplicationOptions.ConfirmEmailChangeFormPath"/> with
    /// query parameters: email (current), newEmail (staged), and token (Base64URL-encoded).
    /// Per locked decision (Phase 1, Step 7): tenantIdentifier is intentionally NOT embedded.
    /// </summary>
    string GenerateConfirmEmailChangeLink(string currentEmail, string newEmail, string token);
}

public sealed class IdmtLinkGenerator(
    LinkGenerator linkGenerator,
    IMultiTenantContextAccessor multiTenantContextAccessor,
    IHttpContextAccessor httpContextAccessor,
    IOptions<IdmtOptions> options,
    ILogger<IdmtLinkGenerator> logger) : IIdmtLinkGenerator
{
    public string GenerateConfirmEmailLink(string email, string token)
    {
        var httpContext = httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException("No HTTP context was found.");

        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var tenantIdentifier = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Identifier ?? string.Empty;
        var mode = options.Value.Application.EmailConfirmationMode;

        string url;
        if (mode == EmailConfirmationMode.ServerConfirm)
        {
            var routeValues = new RouteValueDictionary
            {
                ["tenantIdentifier"] = tenantIdentifier,
                ["email"] = email,
                ["token"] = encodedToken,
            };

            // Add route strategy parameter if route strategy is active
            AddTenantRouteParameter(routeValues, tenantIdentifier);

            url = linkGenerator.GetUriByName(httpContext, IdmtEndpointNames.ConfirmEmailDirect, routeValues)
                ?? throw new NotSupportedException($"Could not find endpoint named '{IdmtEndpointNames.ConfirmEmailDirect}'.");
        }
        else
        {
            url = BuildClientFormUrl(
                options.Value.Application.ClientUrl,
                options.Value.Application.ConfirmEmailFormPath,
                tenantIdentifier,
                email,
                encodedToken);
        }

        logger.LogInformation("Confirm email link generated for {Email}. Tenant: {TenantId}.",
            PiiMasker.MaskEmail(email),
            multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty);

        return url;
    }

    public string GenerateConfirmEmailChangeLink(string currentEmail, string newEmail, string token)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }

        if (string.IsNullOrEmpty(options.Value.Application.ClientUrl))
        {
            throw new InvalidOperationException("Client URL is not configured.");
        }

        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        // Locked decision (Phase 1, Step 7): no tenantIdentifier in URL.
        var queryParams = new Dictionary<string, string?>
        {
            ["email"] = currentEmail,
            ["newEmail"] = newEmail,
            ["token"] = encodedToken,
        };

        var clientUrl = options.Value.Application.ClientUrl!;
        var formPath = options.Value.Application.ConfirmEmailChangeFormPath;
        var url = QueryHelpers.AddQueryString(
            $"{clientUrl.TrimEnd('/')}/{formPath.TrimStart('/')}",
            queryParams);

        logger.LogInformation(
            "Confirm email change link generated. Current: {CurrentEmail}. New: {NewEmail}. Tenant: {TenantId}.",
            PiiMasker.MaskEmail(currentEmail),
            PiiMasker.MaskEmail(newEmail),
            multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty);

        return url;
    }

    public string GeneratePasswordResetLink(string email, string token)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            throw new InvalidOperationException("No HTTP context was found.");
        }

        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var tenantIdentifier = multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Identifier ?? string.Empty;

        var url = BuildClientFormUrl(
            options.Value.Application.ClientUrl,
            options.Value.Application.ResetPasswordFormPath,
            tenantIdentifier,
            email,
            encodedToken);

        logger.LogInformation("Password reset link generated for {Email}. Tenant: {TenantId}.",
            PiiMasker.MaskEmail(email),
            multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty);

        return url;
    }

    private static string BuildClientFormUrl(string? clientUrl, string formPath, string tenantIdentifier, string email, string encodedToken)
    {
        if (string.IsNullOrEmpty(clientUrl))
        {
            throw new InvalidOperationException("Client URL is not configured.");
        }

        var queryParams = new Dictionary<string, string?>
        {
            ["tenantIdentifier"] = tenantIdentifier,
            ["email"] = email,
            ["token"] = encodedToken,
        };

        return QueryHelpers.AddQueryString(
            $"{clientUrl.TrimEnd('/')}/{formPath.TrimStart('/')}",
            queryParams);
    }

    private void AddTenantRouteParameter(RouteValueDictionary routeValues, string tenantIdentifier)
    {
        var routeParam = options.Value.MultiTenant.StrategyOptions
            .GetValueOrDefault(IdmtMultiTenantStrategy.Route, IdmtMultiTenantStrategy.DefaultRouteParameter);

        // Only add if different from "tenantIdentifier" to avoid duplication
        if (!string.Equals(routeParam, "tenantIdentifier", StringComparison.Ordinal))
        {
            routeValues[routeParam] = tenantIdentifier;
        }
    }
}
