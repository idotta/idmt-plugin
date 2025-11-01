using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Register;

/// <summary>
/// Handler implementation for user registration following the vertical slice architecture pattern.
/// Handles the complete registration workflow: validates input, checks role existence, creates user account,
/// assigns role, and generates password setup token.
/// </summary>
/// <remarks>
/// This handler creates users without passwords. Users must set their password using the generated token.
/// The user's email is not confirmed until they set their password (email confirmation is handled elsewhere).
/// Users are created as active by default, and soft-deleted by setting IsActive to false.
/// </remarks>
internal sealed class RegisterHandler(
    ILogger<RegisterHandler> logger,
    UserManager<IdmtUser> userManager,
    RoleManager<IdmtRole> roleManager,
    IUserStore<IdmtUser> userStore,
    IUserEmailStore<IdmtUser> emailStore,
    ICurrentUserService currentUserService,
    IdmtDbContext dbContext,
    IOptions<IdmtOptions> options) : IRegisterHandler
{
    /// <summary>
    /// Handles the user registration request. Executes the complete registration workflow:
    /// 1. Validates the request data
    /// 2. Creates the user entity with basic information
    /// 3. Begins a database transaction
    /// 4. Verifies the role exists (within transaction to prevent race conditions)
    /// 5. Creates the user account with tenant context (within transaction)
    /// 6. Assigns the specified role (within transaction)
    /// 7. Commits the transaction if all operations succeed
    /// 8. Generates password setup token
    /// 9. Constructs password setup URL if configured
    /// </summary>
    /// <param name="request">The registration request containing email, optional username, and role</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation</param>
    /// <returns>Registration response with success status, user ID, password setup token, and any errors</returns>
    /// <exception cref="NotSupportedException">Thrown when the user store does not support email functionality</exception>
    public async Task<RegisterUserResponse> HandleAsync(
        RegisterUserRequest request,
        CancellationToken cancellationToken = default)
    {
        // Validate request data (email format, username length, role presence)
        var validationErrors = request.Validate();
        if (validationErrors != null)
        {
            return new RegisterUserResponse
            {
                Success = false,
                StatusCode = StatusCodes.Status400BadRequest,
                ValidationErrors = validationErrors
            };
        }

        // Create user entity with basic information, no password set
        // User is active by default, but email is not confirmed until password is set
        // When the user is unregistered, we set IsActive to false (soft delete)
        var user = new IdmtUser
        {
            UserName = request.Username ?? request.Email,
            Email = request.Email,
            EmailConfirmed = false, // Will be confirmed when password is set
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = currentUserService.UserId!.Value,
            UpdatedBy = currentUserService.UserId!.Value,
            TenantId = currentUserService.TenantId!,
            LastLoginAt = null
        };

        // Set username and email using store-specific methods (ensures proper normalization)
        await userStore.SetUserNameAsync(user, request.Username ?? request.Email, cancellationToken);
        await emailStore.SetEmailAsync(user, request.Email, cancellationToken);
        
        // Use a database transaction to ensure atomicity: all operations (role check, user creation, role assignment) 
        // happen atomically. If any step fails, everything is rolled back.
        await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            // Verify that the specified role exists in the system within the transaction
            // This prevents race conditions where the role could be deleted between check and assignment
            // Note: This check is not tenant-aware - roles are global across all tenants
            bool roleExists = await roleManager.RoleExistsAsync(request.Role);
            if (!roleExists)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new RegisterUserResponse
                {
                    Success = false,
                    StatusCode = StatusCodes.Status400BadRequest,
                    ErrorMessage = "Role not found",
                };
            }

            // Create the user account (this will validate uniqueness constraints per tenant)
            var result = await userManager.CreateAsync(user);

            if (!result.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);
                logger.LogError("Failed to create user: {ErrorMessage}", result.Errors);
                return new RegisterUserResponse
                {
                    Success = false,
                    StatusCode = StatusCodes.Status400BadRequest,
                    ErrorMessage = "Failed to create user",
                    ValidationErrors = result.Errors.ToDictionary(e => e.Code, e => e.Description)
                };
            }

            // Assign the specified role to the user
            // If this fails, the transaction will rollback and the user will not be created
            var roleResult = await userManager.AddToRoleAsync(user, request.Role);
            if (!roleResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);
                logger.LogError("Failed to assign role to user: {ErrorMessage}", roleResult.Errors);
                return new RegisterUserResponse
                {
                    Success = false,
                    StatusCode = StatusCodes.Status400BadRequest,
                    ErrorMessage = "Failed to assign role to user",
                    ValidationErrors = roleResult.Errors.ToDictionary(e => e.Code, e => e.Description)
                };
            }

            // Commit the transaction only if role check, user creation, and role assignment all succeeded
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(cancellationToken);
            logger.LogError(ex, "Exception occurred during user registration. Transaction rolled back.");
            throw;
        }

        // Generate password setup token using ASP.NET Core Identity's password reset token mechanism
        // This token is secure, time-limited, and can be used to set the user's initial password
        var token = await userManager.GeneratePasswordResetTokenAsync(user);

        // Create password setup URL if base URL is configured
        // The URL includes the email and token as query parameters for convenience
        var baseUrl = options.Value.Application.BaseUrl;
        string? passwordSetupUrl = null;
        if (!string.IsNullOrEmpty(baseUrl))
        {
            passwordSetupUrl = $"{baseUrl}{options.Value.Application.PasswordSetupPath}?{options.Value.Application.PasswordSetEmailParameter}={Uri.EscapeDataString(user.Email)}&{options.Value.Application.PasswordSetTokenParameter}={Uri.EscapeDataString(token)}";
        }

        logger.LogInformation("User created: {Email}. Request by {RequestingUserId}. Tenant: {TenantId}.", user.Email, currentUserService.UserId, currentUserService.TenantId);
        
        return new RegisterUserResponse
        {
            Success = true,
            StatusCode = StatusCodes.Status201Created,
            UserId = user.Id.ToString(),
            PasswordSetupToken = token,
            PasswordSetupUrl = passwordSetupUrl,
        };
    }
}