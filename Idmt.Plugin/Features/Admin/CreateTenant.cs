using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
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
        IOptions<IdmtOptions> options,
        ILogger<CreateTenantHandler> logger) : ICreateTenantHandler
    {
        public async Task<ErrorOr<CreateTenantResponse>> HandleAsync(CreateTenantRequest request, CancellationToken cancellationToken = default)
        {
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
                bool ok = await GuaranteeTenantRolesAsync(resultTenant);
                if (!ok)
                {
                    return IdmtErrors.Tenant.RoleSeedFailed;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error seeding roles for tenant {Identifier}", request.Identifier);
                return IdmtErrors.Tenant.RoleSeedFailed;
            }

            return new CreateTenantResponse(
                resultTenant.Id ?? string.Empty,
                resultTenant.Identifier ?? string.Empty,
                resultTenant.Name ?? string.Empty);
        }

        private async Task<bool> GuaranteeTenantRolesAsync(IdmtTenantInfo tenantInfo)
        {
            var roles = IdmtDefaultRoleTypes.DefaultRoles;
            if (options.Value.Identity.ExtraRoles.Length > 0)
            {
                roles = [.. roles, .. options.Value.Identity.ExtraRoles];
            }

            var result = await tenantOps.ExecuteInTenantScopeAsync(tenantInfo.Identifier!, async provider =>
            {
                var roleManager = provider.GetRequiredService<RoleManager<IdmtRole>>();
                foreach (var role in roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        var createResult = await roleManager.CreateAsync(new IdmtRole(role));
                        if (!createResult.Succeeded)
                        {
                            return IdmtErrors.Tenant.RoleSeedFailed;
                        }
                    }
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
