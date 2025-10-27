using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Finbuckle.MultiTenant;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;

namespace Idmt.Plugin.Features.Register;

/// <summary>
/// Handler for user registration operations
/// </summary>
internal sealed class RegisterHandler : IRegisterHandler
{
    private readonly UserManager<IdmtUser> _userManager;
    private readonly IMultiTenantContextAccessor _tenantAccessor;
    private readonly IOptions<IdmtOptions> _options;

    public RegisterHandler(
        UserManager<IdmtUser> userManager,
        IMultiTenantContextAccessor tenantAccessor,
        IOptions<IdmtOptions> options)
    {
        _userManager = userManager;
        _tenantAccessor = tenantAccessor;
        _options = options;
    }

    /// <summary>
    /// Handles user registration
    /// </summary>
    /// <param name="request">Registration request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Registration response</returns>
    public async Task<RegisterResponse> HandleAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            // Get current tenant context
            var currentTenant = _tenantAccessor.MultiTenantContext?.TenantInfo;
            var tenantId = currentTenant?.Id ?? request.TenantId ?? _options.Value.MultiTenant.DefaultTenantId;

            // Check if user already exists
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                // If user exists in same tenant, return error
                if (existingUser.TenantId == tenantId)
                {
                    return new RegisterResponse
                    {
                        Success = false,
                        ErrorMessage = "A user with this email address already exists"
                    };
                }
            }

            // Create new user
            var user = new IdmtUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                PhoneNumber = request.PhoneNumber,
                TenantId = tenantId,
                EmailConfirmed = !_options.Value.Identity.SignIn.RequireConfirmedEmail,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            // Attempt to create user
            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                return new RegisterResponse
                {
                    Success = false,
                    ErrorMessage = "Failed to create user account",
                    Errors = result.Errors.Select(e => e.Description).ToList()
                };
            }

            var response = new RegisterResponse
            {
                Success = true,
                UserId = user.Id,
                Message = "User account created successfully"
            };

            // Handle email confirmation if required
            if (_options.Value.Identity.SignIn.RequireConfirmedEmail)
            {
                var confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                response.RequiresEmailConfirmation = true;
                response.EmailConfirmationToken = confirmationToken;
                response.Message = "User account created successfully. Please check your email to confirm your account.";
            }

            return response;
        }
        catch (Exception ex)
        {
            return new RegisterResponse
            {
                Success = false,
                ErrorMessage = "An error occurred during registration",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    /// <summary>
    /// Confirms user email address
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="token">Confirmation token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if confirmation was successful</returns>
    public async Task<bool> ConfirmEmailAsync(string userId, string token, CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return false;

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return result.Succeeded;
        }
        catch
        {
            return false;
        }
    }
}