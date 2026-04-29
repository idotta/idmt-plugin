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
            // Locked decision (Phase 1, Step 8): tenantIdentifier intentionally NOT embedded
            // as a query parameter. Tenant routing relies on path/host strategy or claim-based
            // resolution, not URL query params.
            var routeValues = new RouteValueDictionary
            {
                ["email"] = email,
                ["token"] = encodedToken,
            };

            // Add route strategy parameter if route strategy is active (path-based tenant
            // routing, e.g., /{tenant}/confirm-email). This is the route segment, NOT a query.
            AddTenantRouteParameter(routeValues, tenantIdentifier);

            url = linkGenerator.GetUriByName(httpContext, IdmtEndpointNames.ConfirmEmailDirect, routeValues)
                ?? throw new NotSupportedException($"Could not find endpoint named '{IdmtEndpointNames.ConfirmEmailDirect}'.");
        }
        else
        {
            url = BuildClientFormUrl(
                options.Value.Application.ClientUrl,
                options.Value.Application.ConfirmEmailFormPath,
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

        // Locked decision (Phase 1, Step 8): no tenantIdentifier in URL query params.
        var url = BuildClientFormUrl(
            options.Value.Application.ClientUrl,
            options.Value.Application.ResetPasswordFormPath,
            email,
            encodedToken);

        logger.LogInformation("Password reset link generated for {Email}. Tenant: {TenantId}.",
            PiiMasker.MaskEmail(email),
            multiTenantContextAccessor.MultiTenantContext?.TenantInfo?.Id ?? string.Empty);

        return url;
    }

    private static string BuildClientFormUrl(string? clientUrl, string formPath, string email, string encodedToken)
    {
        if (string.IsNullOrEmpty(clientUrl))
        {
            throw new InvalidOperationException("Client URL is not configured.");
        }

        // Locked decision (Phase 1, Step 8): no tenantIdentifier in URL query params.
        var queryParams = new Dictionary<string, string?>
        {
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

        // Locked decision (Phase 1, Step 8): tenantIdentifier must NOT surface as a query param.
        // The configured route-strategy param ("tenantIdentifier" by default) would become a query
        // string when the endpoint has no matching {tenantIdentifier} route token — so skip it.
        // Custom route-strategy names (e.g., "tenant") are populated; if the endpoint declares a
        // matching route token they fill the path segment, otherwise they become a benign
        // non-tenantIdentifier query param.
        if (!string.Equals(routeParam, "tenantIdentifier", StringComparison.Ordinal))
        {
            routeValues[routeParam] = tenantIdentifier;
        }
    }
}
