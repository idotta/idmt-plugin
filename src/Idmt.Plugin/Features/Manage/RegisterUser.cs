using System.Text.RegularExpressions;
using Idmt.Plugin.Configuration;
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
    /// <summary>
    /// Request model for user registration. Represents the data required to create a new user account.
    /// The user will be created without a password and will need to set it via the password setup token.
    /// </summary>
    public sealed record RegisterUserRequest
    {
        /// <summary>
        /// Email address for the user. Required and must be a valid email format.
        /// </summary>
        public required string Email { get; init; }

        /// <summary>
        /// Optional username. If not provided, the email address will be used as the username.
        /// </summary>
        public string? Username { get; init; }

        /// <summary>
        /// Role name to assign to the user upon registration. Required and must be an existing role.
        /// </summary>
        public required string Role { get; init; }
    }

    /// <summary>
    /// Response model for user registration operations. Contains the result of the registration attempt,
    /// including success status, user identifier, password setup token, and any validation or error messages.
    /// </summary>
    public sealed record RegisterUserResponse
    {
        /// <summary>
        /// Indicates whether the registration operation succeeded.
        /// </summary>
        public bool Success { get; init; }

        /// <summary>
        /// The unique identifier of the created user (as string). Only populated when Success is true.
        /// </summary>
        public string? UserId { get; init; }

        /// <summary>
        /// Password reset token that can be used to set the user's initial password.
        /// This token is generated using ASP.NET Core Identity's password reset token mechanism.
        /// Only populated when Success is true.
        /// </summary>
        public string? PasswordSetupToken { get; init; }

        /// <summary>
        /// Fully constructed URL for password setup.
        /// Contains the email and token as query parameters. Only populated when Success is true.
        /// </summary>
        public string? PasswordSetupUrl { get; init; }

        /// <summary>
        /// HTTP status code for the response. Defaults to 201 Created for successful registrations,
        /// 400 Bad Request for validation errors or failures.
        /// </summary>
        public int StatusCode { get; init; } = StatusCodes.Status201Created;

        /// <summary>
        /// General error message when registration fails. Used for non-validation errors.
        /// </summary>
        public string? ErrorMessage { get; init; }
    }

    /// <summary>
    /// Handler interface for user registration operations following the vertical slice architecture pattern.
    /// Implementations handle the complete registration workflow including validation, user creation,
    /// role assignment, and password setup token generation.
    /// </summary>
    public interface IRegisterUserHandler
    {
        /// <summary>
        /// Handles a user registration request. Creates a new user account without a password,
        /// assigns the specified role, and generates a password setup token.
        /// </summary>
        /// <param name="request">The registration request containing email, optional username, and role</param>
        /// <param name="cancellationToken">Cancellation token to cancel the operation</param>
        /// <returns>Registration response containing success status, user ID, password setup token, and any errors</returns>
        Task<RegisterUserResponse> HandleAsync(
            bool useApiLinks,
            RegisterUserRequest request,
            CancellationToken cancellationToken = default);
    }


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
        ICurrentUserService currentUserService,
        ITenantAccessService tenantAccessService,
        IdmtDbContext dbContext,
        IIdmtLinkGenerator linkGenerator,
        IEmailSender<IdmtUser> emailSender) : IRegisterUserHandler
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
            bool useApiLinks,
            RegisterUserRequest request,
            CancellationToken cancellationToken = default)
        {
            // Security check: Validate role assignment permissions based on current user's role
            if (!tenantAccessService.CanAssignRole(request.Role))
            {
                return new RegisterUserResponse
                {
                    Success = false,
                    StatusCode = StatusCodes.Status403Forbidden,
                    ErrorMessage = "Insufficient permissions to assign this role."
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
                TenantId = currentUserService.TenantId!,
                LastLoginAt = null,
            };

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
                        ErrorMessage = "Failed to create user"
                    };
                }

                // Set username and email using store-specific methods (ensures proper normalization)
                await userStore.SetUserNameAsync(user, request.Username ?? request.Email, cancellationToken);
                IUserEmailStore<IdmtUser> emailStore = userStore as IUserEmailStore<IdmtUser>
                    ?? throw new NotSupportedException("The user store does not support email functionality.");
                await emailStore.SetEmailAsync(user, request.Email, cancellationToken);

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
                        ErrorMessage = "Failed to assign role to user"
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

            // Generate password setup URL
            var passwordSetupUrl = useApiLinks
                ? linkGenerator.GeneratePasswordResetApiLink(user.Email, token)
                : linkGenerator.GeneratePasswordResetFormLink(user.Email, token);

            logger.LogInformation("User created: {Email}. Request by {RequestingUserId}. Tenant: {TenantId}.", user.Email, currentUserService.UserId, currentUserService.TenantId);

            await emailSender.SendPasswordResetLinkAsync(user, user.Email, passwordSetupUrl);

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

    /// <summary>
    /// Validates the registration request and returns a dictionary of validation errors if any exist.
    /// Returns null if validation passes.
    /// </summary>
    /// <param name="request">The registration request to validate</param>
    /// <returns>Dictionary of field names to error messages if validation fails, null if validation succeeds</returns>
    public static Dictionary<string, string[]>? Validate(this RegisterUserRequest request, string? allowedUsernameCharacters = null)
    {
        var errors = new Dictionary<string, string[]>();

        // Validate email format using standard email validation
        if (!Validators.IsValidEmail(request.Email))
        {
            errors["Email"] = ["Invalid email address."];
        }

        // Validate username length if provided (minimum 3 characters)
        if (request.Username is not null)
        {
            if (!string.IsNullOrEmpty(allowedUsernameCharacters) && !Regex.IsMatch(request.Username, $"^[{allowedUsernameCharacters}]+$"))
            {
                errors["Username"] = [$"Username must contain only the following characters: {allowedUsernameCharacters}"];
            }
        }

        // Validate that role is provided and not empty
        if (string.IsNullOrEmpty(request.Role))
        {
            errors["Role"] = ["Role is required."];
        }

        return errors.Count == 0 ? null : errors;
    }

    public static RouteHandlerBuilder MapRegisterUserEndpoint(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapPost("/users", async Task<Results<Ok<RegisterUserResponse>, ProblemHttpResult, ValidationProblem>> (
            [FromQuery] bool useApiLinks,
            [FromBody] RegisterUserRequest request,
            [FromServices] IRegisterUserHandler handler,
            HttpContext context) =>
        {
            // Validate request data (email format, username length, role presence)
            if (request.Validate() is { } validationErrors)
            {
                return TypedResults.ValidationProblem(validationErrors);
            }

            var response = await handler.HandleAsync(useApiLinks, request, cancellationToken: context.RequestAborted);
            if (!response.Success)
            {
                return TypedResults.Problem(response.ErrorMessage, statusCode: response.StatusCode);
            }
            return TypedResults.Ok(response);
        })
        .RequireAuthorization(AuthOptions.RequireTenantManagerPolicy)
        .WithSummary("Register user")
        .WithDescription("Register a new user for a tenant (Admin/System only)");
    }
}