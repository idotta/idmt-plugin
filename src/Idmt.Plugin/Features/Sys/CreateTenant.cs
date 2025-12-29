using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Sys;

public static class CreateTenant
{
    public sealed record CreateTenantRequest(
        string Identifier,
        string Name,
        string DisplayName
    );

    public sealed record CreateTenantResponse(
        string Id,
        string Identifier,
        string Name,
        string DisplayName
    );

    public interface ICreateTenantHandler
    {
        Task<Result<CreateTenantResponse>> HandleAsync(CreateTenantRequest request, CancellationToken cancellationToken = default);
    }

    internal sealed class CreateTenantHandler(
        IMultiTenantStore<IdmtTenantInfo> tenantStore,
        IMultiTenantContextSetter tenantContextSetter,
        IMultiTenantContextAccessor tenantContextAccessor,
        IServiceProvider serviceProvider,
        IOptions<IdmtOptions> options,
        ILogger<CreateTenantHandler> logger) : ICreateTenantHandler
    {
        public async Task<Result<CreateTenantResponse>> HandleAsync(CreateTenantRequest request, CancellationToken cancellationToken = default)
        {
            IdmtTenantInfo resultTenant;

            try
            {
                var existingTenant = await tenantStore.GetByIdentifierAsync(request.Identifier);
                if (existingTenant is not null)
                {
                    if (!existingTenant.IsActive)
                    {
                        existingTenant = existingTenant with { IsActive = true };
                        if (!await tenantStore.UpdateAsync(existingTenant))
                        {
                            return Result.Failure<CreateTenantResponse>("Failed to update tenant", StatusCodes.Status500InternalServerError);
                        }
                    }
                    resultTenant = existingTenant;
                }
                else
                {
                    var tenant = new IdmtTenantInfo(request.Identifier, request.Name)
                    {
                        DisplayName = request.DisplayName
                    };

                    if (!await tenantStore.AddAsync(tenant))
                    {
                        return Result.Failure<CreateTenantResponse>("Failed to create tenant", StatusCodes.Status400BadRequest);
                    }
                    resultTenant = tenant;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error creating tenant with identifier {Identifier}", request.Identifier);
                return Result.Failure<CreateTenantResponse>($"Error creating tenant: {ex.Message}", StatusCodes.Status500InternalServerError);
            }

            try
            {
                bool ok = await GuaranteeTenantRolesAsync(resultTenant);
                if (!ok)
                {
                    return Result.Failure<CreateTenantResponse>($"Failed to guarantee tenant roles.", StatusCodes.Status500InternalServerError);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error seeding roles for tenant {Identifier}", request.Identifier);
            }

            return Result.Success(new CreateTenantResponse(
                resultTenant.Id ?? string.Empty,
                resultTenant.Identifier ?? string.Empty,
                resultTenant.Name ?? string.Empty,
                resultTenant.DisplayName ?? string.Empty), StatusCodes.Status200OK);
        }

        private async Task<bool> GuaranteeTenantRolesAsync(IdmtTenantInfo tenantInfo)
        {
            var roles = IdmtDefaultRoleTypes.DefaultRoles;
            if (options.Value.Identity.ExtraRoles.Length > 0)
            {
                roles = [.. roles, .. options.Value.Identity.ExtraRoles];
            }

            // Set tenant context before seeding roles to avoid NullReferenceException with multi-tenant filters
            var previousContext = tenantContextAccessor.MultiTenantContext;
            try
            {
                tenantContextSetter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo);

                // Seed default roles
                using var scope = serviceProvider.CreateScope();
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdmtRole>>();
                foreach (var role in roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        var result = await roleManager.CreateAsync(new IdmtRole(role));
                        if (!result.Succeeded)
                        {
                            return false;
                        }
                    }
                }
            }
            finally
            {
                // Restore previous context
                tenantContextSetter.MultiTenantContext = previousContext;
            }

            return true;
        }
    }

    public static Dictionary<string, string[]>? Validate(this CreateTenantRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrEmpty(request.Identifier))
        {
            errors["Identifier"] = ["Identifier is required"];
        }
        if (string.IsNullOrEmpty(request.Name))
        {
            errors["Name"] = ["Name is required"];
        }
        if (string.IsNullOrEmpty(request.DisplayName))
        {
            errors["DisplayName"] = ["Display Name is required"];
        }

        return errors.Count > 0 ? errors : null;
    }

    public static RouteHandlerBuilder MapCreateTenantEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/tenants", static async Task<Results<Ok<CreateTenantResponse>, Created<CreateTenantResponse>, ValidationProblem, BadRequest>> (
            [FromBody] CreateTenantRequest request,
            [FromServices] ICreateTenantHandler handler,
            HttpContext context) =>
        {
            if (request.Validate() is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }
            var response = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            if (!response.IsSuccess)
            {
                return TypedResults.BadRequest();
            }
            return TypedResults.Ok(response.Value);
        })
        .RequireAuthorization(AuthOptions.RequireSysAdminPolicy)
        .WithSummary("Create Tenant")
        .WithDescription("Create a new tenant in the system or reactivate an existing inactive tenant");
    }
}