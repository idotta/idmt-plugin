using ErrorOr;
using FluentValidation;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Auth;

public static class DiscoverTenants
{
    public sealed record DiscoverTenantsRequest(string Email);

    public sealed record TenantItem(string Identifier, string Name);

    public sealed record DiscoverTenantsResponse(IReadOnlyList<TenantItem> Tenants);

    public interface IDiscoverTenantsHandler
    {
        Task<ErrorOr<DiscoverTenantsResponse>> HandleAsync(
            DiscoverTenantsRequest request,
            CancellationToken cancellationToken = default);
    }

    internal sealed class DiscoverTenantsHandler(
        IdmtDbContext dbContext,
        TimeProvider timeProvider,
        ILogger<DiscoverTenantsHandler> logger) : IDiscoverTenantsHandler
    {
        public async Task<ErrorOr<DiscoverTenantsResponse>> HandleAsync(
            DiscoverTenantsRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var normalizedEmail = request.Email.ToUpperInvariant();
                var now = timeProvider.GetUtcNow();

                // Find all tenant IDs where the user has a direct account.
                // IgnoreQueryFilters bypasses Finbuckle's automatic tenant filter
                // so we can search across all tenants.
                var directTenantIds = await dbContext.Users
                    .IgnoreQueryFilters()
                    .Where(u => u.NormalizedEmail == normalizedEmail && u.IsActive)
                    .Select(u => u.TenantId)
                    .Distinct()
                    .ToListAsync(cancellationToken);

                // Find tenant IDs granted via TenantAccess (cross-tenant grants).
                // First find user IDs matching the email, then look up their access grants.
                var userIds = await dbContext.Users
                    .IgnoreQueryFilters()
                    .Where(u => u.NormalizedEmail == normalizedEmail && u.IsActive)
                    .Select(u => u.Id)
                    .ToListAsync(cancellationToken);

                var accessTenantIds = await dbContext.TenantAccess
                    .Where(ta => userIds.Contains(ta.UserId)
                                 && ta.IsActive
                                 && (ta.ExpiresAt == null || ta.ExpiresAt > now))
                    .Select(ta => ta.TenantId)
                    .Distinct()
                    .ToListAsync(cancellationToken);

                // Union all tenant IDs
                var allTenantIds = directTenantIds.Union(accessTenantIds).ToList();

                if (allTenantIds.Count == 0)
                {
                    return new DiscoverTenantsResponse([]);
                }

                // Resolve tenant info, filtering only active tenants
                var tenants = await dbContext.Set<IdmtTenantInfo>()
                    .Where(ti => allTenantIds.Contains(ti.Id) && ti.IsActive)
                    .OrderBy(ti => ti.Name)
                    .Select(ti => new TenantItem(ti.Identifier, ti.Name ?? ti.Identifier))
                    .ToListAsync(cancellationToken);

                return new DiscoverTenantsResponse(tenants);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred during tenant discovery for {Email}",
                    PiiMasker.MaskEmail(request.Email));
                return IdmtErrors.General.Unexpected;
            }
        }
    }

    public static RouteHandlerBuilder MapDiscoverTenantsEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/discover-tenants", async Task<Results<Ok<DiscoverTenantsResponse>, ValidationProblem, StatusCodeHttpResult>> (
            [FromBody] DiscoverTenantsRequest request,
            [FromServices] IDiscoverTenantsHandler handler,
            [FromServices] IValidator<DiscoverTenantsRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var result = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (result.IsError)
            {
                return TypedResults.StatusCode(StatusCodes.Status500InternalServerError);
            }

            return TypedResults.Ok(result.Value);
        })
        .WithSummary("Discover tenants by email")
        .WithDescription("Resolve tenant(s) associated with an email address for pre-login discovery");
    }
}
