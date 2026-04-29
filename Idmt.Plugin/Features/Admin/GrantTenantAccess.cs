using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Admin;

public static class GrantTenantAccess
{
    public sealed record GrantAccessRequest(DateTimeOffset? ExpiresAt);

    public interface IGrantTenantAccessHandler
    {
        Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, DateTimeOffset? expiresAt = null, CancellationToken cancellationToken = default);
    }

    // Phase 1 (canonical identity): GrantTenantAccess writes ONLY a TenantAccess row in a single
    // SaveChangesAsync transaction. No shadow IdmtUser is created in the target tenant; IdmtUser is
    // a global entity post Phase 1. No ExecuteInTenantScopeAsync hop, no compensation. The Phase 0
    // self-grant guard at the top of HandleAsync remains in place per the architectural rule that
    // self-grants happen only as a CreateTenant side-effect — never as a first-class HTTP op.
    internal sealed class GrantTenantAccessHandler(
        IdmtDbContext dbContext,
        UserManager<IdmtUser> userManager,
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ICurrentUserService currentUserService,
        TimeProvider timeProvider,
        ILogger<GrantTenantAccessHandler> logger
        ) : IGrantTenantAccessHandler
    {
        public async Task<ErrorOr<Success>> HandleAsync(Guid userId, string tenantIdentifier, DateTimeOffset? expiresAt = null, CancellationToken cancellationToken = default)
        {
            if (currentUserService.UserId is null)
            {
                return IdmtErrors.Auth.Unauthorized;
            }

            if (userId == currentUserService.UserId.Value)
            {
                return IdmtErrors.General.SelfTarget;
            }

            if (expiresAt.HasValue && expiresAt.Value <= timeProvider.GetUtcNow())
            {
                return Error.Validation("ExpiresAt", "Expiration date must be in the future");
            }

            try
            {
                // Canonical (global) IdmtUser lookup.
                var user = await userManager.FindByIdAsync(userId.ToString());
                if (user is null)
                {
                    return IdmtErrors.User.NotFound;
                }

                var targetTenant = await tenantStore.GetByIdentifierAsync(tenantIdentifier);
                if (targetTenant is null)
                {
                    return IdmtErrors.Tenant.NotFound;
                }

                if (!targetTenant.IsActive)
                {
                    return IdmtErrors.Tenant.Inactive;
                }

                var tenantAccess = await dbContext.TenantAccess
                    .FirstOrDefaultAsync(ta => ta.UserId == user.Id && ta.TenantId == targetTenant.Id, cancellationToken);
                if (tenantAccess is not null)
                {
                    tenantAccess.IsActive = true;
                    tenantAccess.ExpiresAt = expiresAt;
                }
                else
                {
                    dbContext.TenantAccess.Add(new TenantAccess
                    {
                        UserId = user.Id,
                        TenantId = targetTenant.Id!,
                        IsActive = true,
                        ExpiresAt = expiresAt
                    });
                }

                await dbContext.SaveChangesAsync(cancellationToken);
                return Result.Success;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error granting tenant access to user {UserId} for tenant {TenantIdentifier}", userId, tenantIdentifier);
                return IdmtErrors.Tenant.AccessError;
            }
        }
    }

    public static RouteHandlerBuilder MapGrantTenantAccessEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/users/{userId:guid}/tenants/{tenantIdentifier}", async Task<Results<Ok, BadRequest, NotFound, ForbidHttpResult, UnauthorizedHttpResult, InternalServerError>> (
            Guid userId,
            string tenantIdentifier,
            [FromBody] GrantAccessRequest request,
            IGrantTenantAccessHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(userId, tenantIdentifier, request.ExpiresAt, cancellationToken);
            if (result.IsError)
            {
                return result.FirstError.Type switch
                {
                    ErrorType.Validation => TypedResults.BadRequest(),
                    ErrorType.NotFound => TypedResults.NotFound(),
                    ErrorType.Forbidden => TypedResults.Forbid(),
                    ErrorType.Unauthorized => TypedResults.Unauthorized(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.Ok();
        })
        .RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)
        .WithSummary("Grant user access to a tenant");
    }
}
