using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Finbuckle.MultiTenant;
using Idotta.Idmt.Plugin.Models;
using System.Security.Claims;

namespace Idotta.Idmt.Sample.Controllers;

/// <summary>
/// User management controller demonstrating multi-tenant and authenticated operations
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
[Produces("application/json")]
public class UsersController : ControllerBase
{
    private readonly UserManager<IdmtUser> _userManager;
    private readonly IMultiTenantContextAccessor _tenantAccessor;

    public UsersController(
        UserManager<IdmtUser> userManager,
        IMultiTenantContextAccessor tenantAccessor)
    {
        _userManager = userManager;
        _tenantAccessor = tenantAccessor;
    }

    /// <summary>
    /// Gets the current user's profile
    /// </summary>
    /// <returns>Current user information</returns>
    [HttpGet("me")]
    [ProducesResponseType(typeof(UserProfileDto), 200)]
    [ProducesResponseType(401)]
    public async Task<ActionResult<UserProfileDto>> GetCurrentUser()
    {
        var userId = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        var roles = await _userManager.GetRolesAsync(user);
        var currentTenant = _tenantAccessor.MultiTenantContext?.TenantInfo;

        return Ok(new UserProfileDto
        {
            Id = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            TenantId = user.TenantId,
            TenantName = currentTenant?.Name ?? "Unknown",
            Roles = roles.ToList(),
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        });
    }

    /// <summary>
    /// Gets all users in the current tenant (requires admin role)
    /// </summary>
    /// <returns>List of users in current tenant</returns>
    [HttpGet]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(typeof(IEnumerable<UserListDto>), 200)]
    [ProducesResponseType(401)]
    [ProducesResponseType(403)]
    public async Task<ActionResult<IEnumerable<UserListDto>>> GetUsers()
    {
        var currentTenant = _tenantAccessor.MultiTenantContext?.TenantInfo;
        if (currentTenant == null)
        {
            return BadRequest("Tenant context not found");
        }

        // Get all users for the current tenant
        var allUsers = _userManager.Users.Where(u => u.TenantId == currentTenant.Id).ToList();
        
        var userDtos = new List<UserListDto>();
        
        foreach (var user in allUsers)
        {
            var roles = await _userManager.GetRolesAsync(user);
            userDtos.Add(new UserListDto
            {
                Id = user.Id,
                Email = user.Email!,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Roles = roles.ToList(),
                IsActive = user.IsActive,
                CreatedAt = user.CreatedAt
            });
        }

        return Ok(userDtos);
    }

    /// <summary>
    /// Updates the current user's profile
    /// </summary>
    /// <param name="request">Profile update request</param>
    /// <returns>Updated user profile</returns>
    [HttpPut("me")]
    [ProducesResponseType(typeof(UserProfileDto), 200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<ActionResult<UserProfileDto>> UpdateCurrentUser([FromBody] UpdateProfileRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var userId = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        // Update profile fields
        user.FirstName = request.FirstName;
        user.LastName = request.LastName;
        user.PhoneNumber = request.PhoneNumber;
        user.UpdatedAt = DateTime.UtcNow;

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        var roles = await _userManager.GetRolesAsync(user);
        var currentTenant = _tenantAccessor.MultiTenantContext?.TenantInfo;

        return Ok(new UserProfileDto
        {
            Id = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            TenantId = user.TenantId,
            TenantName = currentTenant?.Name ?? "Unknown",
            Roles = roles.ToList(),
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        });
    }

    /// <summary>
    /// Gets tenant information
    /// </summary>
    /// <returns>Current tenant information</returns>
    [HttpGet("tenant")]
    [ProducesResponseType(typeof(TenantInfoDto), 200)]
    [ProducesResponseType(400)]
    public ActionResult<TenantInfoDto> GetTenantInfo()
    {
        var currentTenant = _tenantAccessor.MultiTenantContext?.TenantInfo;
        if (currentTenant == null)
        {
            return BadRequest("Tenant context not found");
        }

        return Ok(new TenantInfoDto
        {
            Id = currentTenant.Id!,
            Name = currentTenant.Name!,
            Identifier = currentTenant.Identifier!
        });
    }
}

/// <summary>
/// User profile data transfer object
/// </summary>
public class UserProfileDto
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? TenantId { get; set; }
    public string? TenantName { get; set; }
    public List<string> Roles { get; set; } = new();
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// User list item data transfer object
/// </summary>
public class UserListDto
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public List<string> Roles { get; set; } = new();
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Profile update request
/// </summary>
public class UpdateProfileRequest
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? PhoneNumber { get; set; }
}

/// <summary>
/// Tenant information data transfer object
/// </summary>
public class TenantInfoDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Identifier { get; set; } = string.Empty;
}