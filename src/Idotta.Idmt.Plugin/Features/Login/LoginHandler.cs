using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Finbuckle.MultiTenant;
using Idotta.Idmt.Plugin.Configuration;
using Idotta.Idmt.Plugin.Models;

namespace Idotta.Idmt.Plugin.Features.Login;

/// <summary>
/// Handler for login operations
/// </summary>
public class LoginHandler
{
    private readonly UserManager<IdmtUser> _userManager;
    private readonly SignInManager<IdmtUser> _signInManager;
    private readonly IMultiTenantContextAccessor _tenantAccessor;
    private readonly IOptions<IdmtOptions> _options;

    public LoginHandler(
        UserManager<IdmtUser> userManager,
        SignInManager<IdmtUser> signInManager,
        IMultiTenantContextAccessor tenantAccessor,
        IOptions<IdmtOptions> options)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tenantAccessor = tenantAccessor;
        _options = options;
    }

    /// <summary>
    /// Handles user login
    /// </summary>
    /// <param name="request">Login request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Login response</returns>
    public async Task<LoginResponse> HandleAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            // Validate tenant context
            var currentTenant = _tenantAccessor.MultiTenantContext?.TenantInfo;
            if (currentTenant == null && !string.IsNullOrEmpty(request.TenantId))
            {
                return new LoginResponse
                {
                    Success = false,
                    ErrorMessage = "Invalid tenant context"
                };
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new LoginResponse
                {
                    Success = false,
                    ErrorMessage = "Invalid email or password"
                };
            }

            // Verify tenant membership
            if (currentTenant != null && user.TenantId != currentTenant.Id)
            {
                return new LoginResponse
                {
                    Success = false,
                    ErrorMessage = "User not found in current tenant"
                };
            }

            // Check if user is active
            if (!user.IsActive)
            {
                return new LoginResponse
                {
                    Success = false,
                    ErrorMessage = "User account is inactive"
                };
            }

            // Attempt sign in
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
            {
                return new LoginResponse
                {
                    Success = false,
                    ErrorMessage = "Invalid email or password"
                };
            }

            // Generate tokens
            var accessToken = await GenerateAccessTokenAsync(user);
            var refreshToken = GenerateRefreshToken();

            // Get user roles
            var roles = await _userManager.GetRolesAsync(user);

            return new LoginResponse
            {
                Success = true,
                AccessToken = accessToken.Token,
                RefreshToken = refreshToken,
                ExpiresAt = accessToken.ExpiresAt,
                User = new UserInfo
                {
                    Id = user.Id,
                    Email = user.Email!,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    TenantId = user.TenantId,
                    Roles = roles.ToList()
                }
            };
        }
        catch (Exception ex)
        {
            return new LoginResponse
            {
                Success = false,
                ErrorMessage = "An error occurred during login",
                Errors = new List<string> { ex.Message }
            };
        }
    }

    private async Task<(string Token, DateTime ExpiresAt)> GenerateAccessTokenAsync(IdmtUser user)
    {
        var jwtOptions = _options.Value.Jwt;
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SecretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, user.UserName!),
            new(ClaimTypes.Email, user.Email!),
            new("tenant_id", user.TenantId ?? string.Empty)
        };

        // Add user roles to claims
        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var expiresAt = DateTime.UtcNow.AddMinutes(jwtOptions.ExpirationMinutes);

        var token = new JwtSecurityToken(
            issuer: jwtOptions.Issuer,
            audience: jwtOptions.Audience,
            claims: claims,
            expires: expiresAt,
            signingCredentials: credentials
        );

        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAt);
    }

    private string GenerateRefreshToken()
    {
        return Guid.NewGuid().ToString();
    }
}