using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Admin;

public static class CreateTenant
{
    public sealed record CreateTenantRequest(
        string Identifier,
        string Name
    );

    public sealed record CreateTenantResponse(
        string Id,
        string Identifier,
        string Name
    );

    public interface ICreateTenantHandler
    {
        Task<ErrorOr<CreateTenantResponse>> HandleAsync(CreateTenantRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class CreateTenantHandler(
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        ITenantOperationService tenantOps,
        ICurrentUserService currentUserService,
        IOptions<IdmtOptions> options,
        ILogger<CreateTenantHandler> logger) : ICreateTenantHandler
    {
        public async Task<ErrorOr<CreateTenantResponse>> HandleAsync(CreateTenantRequest request, CancellationToken cancellationToken = default)
        {
            // V2-CRIT-2 / HS-4: capture invoker UserId in OUTER scope. CurrentUserService is Scoped
            // and inside TenantOperationService.ExecuteInTenantScopeAsync's child DI scope,
            // CurrentUserService.User is null (invariant #11). Reads inside the inner scope return
            // null/Guid.Empty. Pass invokerUserId by value into the inner-scope work.
            var invokerUserId = currentUserService.UserId;
            if (invokerUserId is null)
            {
                return IdmtErrors.Auth.Unauthorized;
            }

            IdmtTenantInfo resultTenant;

            try
            {
                var existingTenant = await tenantStore.GetByIdentifierAsync(request.Identifier);
                if (existingTenant is not null)
                {
                    if (existingTenant.IsActive)
                    {
                        return IdmtErrors.Tenant.AlreadyExists;
                    }

                    existingTenant = existingTenant with { IsActive = true };
                    if (!await tenantStore.UpdateAsync(existingTenant))
                    {
                        return IdmtErrors.Tenant.UpdateFailed;
                    }
                    resultTenant = existingTenant;
                }
                else
                {
                    var tenant = new IdmtTenantInfo(request.Identifier, request.Name);

                    if (!await tenantStore.AddAsync(tenant))
                    {
                        return IdmtErrors.Tenant.CreationFailed;
                    }

                    // V2-CRIT-2 defensive guard: IdmtTenantInfo's ctor assigns Id from
                    // Guid.CreateVersion7() so this is non-null in the canonical path.
                    // If a custom store contract ever reassigns Id post-AddAsync and leaves it
                    // empty, fail hard before BootstrapTenantAsync would insert TenantAccess
                    // with a null TenantId.
                    if (string.IsNullOrEmpty(tenant.Id))
                    {
                        logger.LogError("Tenant store did not populate Id for tenant {Identifier}", request.Identifier);
                        return IdmtErrors.Tenant.CreationFailed;
                    }
                    resultTenant = tenant;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error creating tenant with identifier {Identifier}", request.Identifier);
                return IdmtErrors.General.Unexpected;
            }

            try
            {
                bool ok = await BootstrapTenantAsync(resultTenant, invokerUserId.Value);
                if (!ok)
                {
                    return IdmtErrors.Tenant.RoleSeedFailed;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error bootstrapping tenant {Identifier}", request.Identifier);
                return IdmtErrors.Tenant.RoleSeedFailed;
            }

            return new CreateTenantResponse(
                resultTenant.Id ?? string.Empty,
                resultTenant.Identifier ?? string.Empty,
                resultTenant.Name ?? string.Empty);
        }

        /// <summary>
        /// Seeds default per-tenant roles AND grants the invoker (SysAdmin) <see cref="TenantAccess"/>
        /// in a single inner-scope SaveChanges. Without the auto-TenantAccess the invoker would be
        /// locked out of the tenant they just created (Phase 1 uniform TenantAccess gate).
        /// </summary>
        private async Task<bool> BootstrapTenantAsync(IdmtTenantInfo tenantInfo, Guid invokerUserId)
        {
            var roles = IdmtDefaultRoleTypes.DefaultRoles;
            if (options.Value.Identity.ExtraRoles.Length > 0)
            {
                roles = [.. roles, .. options.Value.Identity.ExtraRoles];
            }

            var result = await tenantOps.ExecuteInTenantScopeAsync(tenantInfo.Identifier!, async provider =>
            {
                var roleManager = provider.GetRequiredService<RoleManager<IdmtRole>>();
                var dbContext = provider.GetRequiredService<IdmtDbContext>();
                var tenantId = tenantInfo.Id!;

                // V2-CRIT-1: wrap role seeding + invoker TenantAccess insertion in a single
                // ambient transaction. RoleManager.CreateAsync persists each role internally via
                // the same DbContext, so the ambient transaction governs every role row plus the
                // TenantAccess row — if any step throws or fails, all changes roll back together.
                // Without this wrap, partial role rows could persist while TenantAccess insert
                // fails, locking the invoker out of the tenant they just bootstrapped.
                await using var transaction = await dbContext.Database.BeginTransactionAsync();
                try
                {
                    foreach (var role in roles)
                    {
                        if (!await roleManager.RoleExistsAsync(role))
                        {
                            var createResult = await roleManager.CreateAsync(new IdmtRole(role));
                            if (!createResult.Succeeded)
                            {
                                await transaction.RollbackAsync();
                                return IdmtErrors.Tenant.RoleSeedFailed;
                            }
                        }
                    }

                    // HS-4 / V2-CRIT-2: invoker auto-TenantAccess in same inner DI scope as role seeding.
                    // Phase 1 uniform gate requires every accessor (incl. SysAdmin) to have a TenantAccess row.
                    var alreadyHasAccess = await dbContext.TenantAccess
                        .AnyAsync(ta => ta.UserId == invokerUserId && ta.TenantId == tenantId);
                    if (!alreadyHasAccess)
                    {
                        dbContext.TenantAccess.Add(new TenantAccess
                        {
                            UserId = invokerUserId,
                            TenantId = tenantId,
                            IsActive = true,
                            ExpiresAt = null
                        });
                        await dbContext.SaveChangesAsync();
                    }

                    await transaction.CommitAsync();
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }

                return Result.Success;
            }, requireActive: false);

            return !result.IsError;
        }
    }

    public static RouteHandlerBuilder MapCreateTenantEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/tenants", async Task<Results<Created<CreateTenantResponse>, ValidationProblem, Conflict, BadRequest, ProblemHttpResult>> (
            [FromBody] CreateTenantRequest request,
            [FromServices] ICreateTenantHandler handler,
            [FromServices] IValidator<CreateTenantRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var response = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (response.IsError)
            {
                return response.FirstError.Type switch
                {
                    ErrorType.Conflict => TypedResults.Conflict(),
                    ErrorType.Validation => TypedResults.BadRequest(),
                    _ => TypedResults.Problem(response.FirstError.Description, statusCode: StatusCodes.Status500InternalServerError),
                };
            }
            var apiPrefix = context.RequestServices.GetRequiredService<IOptions<IdmtOptions>>().Value.Application.ApiPrefix ?? string.Empty;
            return TypedResults.Created($"{apiPrefix}/admin/tenants/{response.Value.Identifier}", response.Value);
        })
        .RequireAuthorization(IdmtAuthOptions.RequireSysAdminPolicy)
        .WithSummary("Create Tenant")
        .WithDescription("Create a new tenant in the system or reactivate an existing inactive tenant");
    }
}
