using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Models;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Identity;

namespace Idmt.Plugin.Features.Auth;

public static class ConfirmEmail
{
    public sealed record ConfirmEmailRequest(string TenantId, string Email, string Token);

    public sealed record ConfirmEmailResponse(bool Success, string? Message = null);

    public interface IConfirmEmailHandler
    {
        Task<ConfirmEmailResponse> HandleAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class ConfirmEmailHandler(
        UserManager<IdmtUser> userManager,
        ITenantResolver<IdmtTenantInfo> tenantResolver,
        IMultiTenantContextAccessor tenantContextAccessor,
        IMultiTenantContextSetter tenantContextSetter) : IConfirmEmailHandler
    {
        public async Task<ConfirmEmailResponse> HandleAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(request.TenantId))
            {
                return new ConfirmEmailResponse(false, "Tenant ID is required");
            }
            var targetTenant = await tenantResolver.ResolveAsync(request.TenantId);
            if (targetTenant is null || !targetTenant.IsResolved)
            {
                return new ConfirmEmailResponse(false, "Invalid tenant ID");
            }
            var currentTenant = tenantContextAccessor.MultiTenantContext;
            // In this case, the current tenant is not the target tenant, so we deny the request
            if (currentTenant is { } ct && ct.IsResolved && ct.TenantInfo?.Id != targetTenant.TenantInfo?.Id)
            {
                return new ConfirmEmailResponse(false, "Invalid tenant context");
            }
            // Set the tenant context to the target tenant
            tenantContextSetter.MultiTenantContext = targetTenant;

            var user = await userManager.FindByEmailAsync(request.Email!);
            if (user == null)
            {
                return new ConfirmEmailResponse(false, "Confirmation failed");
            }

            var result = await userManager.ConfirmEmailAsync(user, request.Token!);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return new ConfirmEmailResponse(false, errors);
            }

            return new ConfirmEmailResponse(true, "Email confirmed successfully");
        }
    }

    public static Dictionary<string, string[]>? Validate(this ConfirmEmailRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrEmpty(request.TenantId))
        {
            errors["TenantId"] = ["Tenant ID is required"];
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
}
