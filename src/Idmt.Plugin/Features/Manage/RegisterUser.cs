using ErrorOr;
using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Idmt.Plugin.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Idmt.Plugin.Features.Manage;

public static class RegisterUser
{
    public sealed record RegisterUserRequest
    {
        public required string Email { get; init; }
        public string? Username { get; init; }
        public required string Role { get; init; }
    }

    public sealed record RegisterUserResponse
    {
        public string? UserId { get; init; }
        public string? PasswordSetupToken { get; init; }
        public string? PasswordSetupUrl { get; init; }
    }

    public interface IRegisterUserHandler
    {
        Task<ErrorOr<RegisterUserResponse>> HandleAsync(
            bool useApiLinks,
            RegisterUserRequest request,
            CancellationToken cancellationToken = default);
    }

    internal sealed class RegisterHandler(
        ILogger<RegisterHandler> logger,
        UserManager<IdmtUser> userManager,
        RoleManager<IdmtRole> roleManager,
        ICurrentUserService currentUserService,
        ITenantAccessService tenantAccessService,
        IdmtDbContext dbContext,
        IIdmtLinkGenerator linkGenerator,
        IEmailSender<IdmtUser> emailSender) : IRegisterUserHandler
    {
        public async Task<ErrorOr<RegisterUserResponse>> HandleAsync(
            bool useApiLinks,
            RegisterUserRequest request,
            CancellationToken cancellationToken = default)
        {
            // Security check: Validate role assignment permissions based on current user's role
            if (!tenantAccessService.CanAssignRole(request.Role))
            {
                return IdmtErrors.User.InsufficientPermissions;
            }

            // Get the tenant ID from the current user service (from tenant context)
            var tenantId = currentUserService.TenantId
                ?? throw new InvalidOperationException("Tenant context is not available. Cannot register user without tenant context.");

            var user = new IdmtUser
            {
                UserName = request.Username ?? request.Email,
                Email = request.Email,
                EmailConfirmed = false,
                IsActive = true,
                TenantId = tenantId,
                LastLoginAt = null,
            };

            await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
            try
            {
                bool roleExists = await roleManager.RoleExistsAsync(request.Role);
                if (!roleExists)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return IdmtErrors.User.RoleNotFound;
                }

                var result = await userManager.CreateAsync(user);

                if (!result.Succeeded)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    logger.LogError("Failed to create user: {ErrorMessage}", result.Errors);
                    return IdmtErrors.User.CreationFailed;
                }

                var roleResult = await userManager.AddToRoleAsync(user, request.Role);
                if (!roleResult.Succeeded)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    logger.LogError("Failed to assign role to user: {ErrorMessage}", roleResult.Errors);
                    return IdmtErrors.User.CreationFailed;
                }

                await transaction.CommitAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync(cancellationToken);
                logger.LogError(ex, "Exception occurred during user registration. Transaction rolled back.");
                return IdmtErrors.General.Unexpected;
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);

            var passwordSetupUrl = useApiLinks
                ? linkGenerator.GeneratePasswordResetApiLink(user.Email ?? request.Email, token)
                : linkGenerator.GeneratePasswordResetFormLink(user.Email ?? request.Email, token);

            logger.LogInformation("User created: {Email}. Request by {RequestingUserId}. Tenant: {TenantId}.", user.Email, currentUserService.UserId, tenantId);

            await emailSender.SendPasswordResetLinkAsync(user, user.Email ?? request.Email, passwordSetupUrl);

            return new RegisterUserResponse
            {
                UserId = user.GetId(),
                PasswordSetupToken = token,
                PasswordSetupUrl = passwordSetupUrl
            };
        }
    }

    public static RouteHandlerBuilder MapRegisterUserEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/users", async Task<Results<Ok<RegisterUserResponse>, ValidationProblem, ForbidHttpResult, BadRequest, InternalServerError>> (
            [FromQuery] bool useApiLinks,
            [FromBody] RegisterUserRequest request,
            [FromServices] IRegisterUserHandler handler,
            [FromServices] IValidator<RegisterUserRequest> validator,
            HttpContext context) =>
        {
            if (ValidationHelper.Validate(request, validator) is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var response = await handler.HandleAsync(useApiLinks, request, cancellationToken: context.RequestAborted);
            if (response.IsError)
            {
                return response.FirstError.Type switch
                {
                    ErrorType.Forbidden => TypedResults.Forbid(),
                    ErrorType.Validation => TypedResults.BadRequest(),
                    _ => TypedResults.InternalServerError(),
                };
            }
            return TypedResults.Ok(response.Value);
        })
        .RequireAuthorization(IdmtAuthOptions.RequireTenantManagerPolicy)
        .WithSummary("Register user")
        .WithDescription("Register a new user for a tenant (Admin/System only)");
    }
}
