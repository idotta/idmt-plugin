using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Finbuckle.MultiTenant;
using Idmt.Plugin.Models;
using System.Security.Claims;

namespace Idmt.Sample.Endpoints;

/// <summary>
/// User management endpoints using minimal APIs
/// </summary>
public static class UserEndpoints
{
    /// <summary>
    /// Maps user management endpoints
    /// </summary>
    /// <param name="app">The web application</param>
    /// <returns>The route group builder</returns>
    public static RouteGroupBuilder MapUserEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/users")
            .WithTags("Users")
            
            .RequireAuthorization();

        // Get current user profile
        group.MapGet("/me", GetCurrentUserAsync)
            .WithName("GetCurrentUser")
            .WithSummary("Gets the current user's profile")
            .Produces<UserProfileDto>(200)
            .Produces(401);

        // Update current user profile
        group.MapPut("/me", UpdateCurrentUserAsync)
            .WithName("UpdateCurrentUser")
            .WithSummary("Updates the current user's profile")
            .Produces<UserProfileDto>(200)
            .Produces(400)
            .Produces(401);

        // Get all users (admin only)
        group.MapGet("/", GetUsersAsync)
            .WithName("GetUsers")
            .WithSummary("Gets all users in the current tenant")
            .Produces<IEnumerable<UserListDto>>(200)
            .Produces(401)
            .Produces(403)
            .RequireAuthorization(policy => policy.RequireRole("Admin"));

        // Get tenant information
        group.MapGet("/tenant", GetTenantInfoAsync)
            .WithName("GetTenantInfo")
            .WithSummary("Gets current tenant information")
            .Produces<TenantInfoDto>(200)
            .Produces(400);

        return group;
    }

    /// <summary>
    /// Gets the current user's profile
    /// </summary>
    /// <param name="httpContext">HTTP context</param>
    /// <param name="userManager">User manager from DI</param>
    /// <param name="tenantAccessor">Tenant accessor from DI</param>
    /// <returns>Current user information</returns>
    private static async Task<IResult> GetCurrentUserAsync(
        HttpContext httpContext,
        [FromServices] UserManager<IdmtUser> userManager,
        [FromServices] IMultiTenantContextAccessor tenantAccessor)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Results.Unauthorized();
        }

        var user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return Results.NotFound();
        }

        var roles = await userManager.GetRolesAsync(user);
        var currentTenant = tenantAccessor.MultiTenantContext?.TenantInfo;

        var userProfile = new UserProfileDto
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
        };

        return Results.Ok(userProfile);
    }

    /// <summary>
    /// Updates the current user's profile
    /// </summary>
    /// <param name="request">Profile update request</param>
    /// <param name="httpContext">HTTP context</param>
    /// <param name="userManager">User manager from DI</param>
    /// <param name="tenantAccessor">Tenant accessor from DI</param>
    /// <returns>Updated user profile</returns>
    private static async Task<IResult> UpdateCurrentUserAsync(
        [FromBody] UpdateProfileRequest request,
        HttpContext httpContext,
        [FromServices] UserManager<IdmtUser> userManager,
        [FromServices] IMultiTenantContextAccessor tenantAccessor)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return Results.Unauthorized();
        }

        var user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return Results.NotFound();
        }

        // Update profile fields
        user.FirstName = request.FirstName;
        user.LastName = request.LastName;
        user.PhoneNumber = request.PhoneNumber;
        user.UpdatedAt = DateTime.UtcNow;

        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return Results.BadRequest(result.Errors);
        }

        var roles = await userManager.GetRolesAsync(user);
        var currentTenant = tenantAccessor.MultiTenantContext?.TenantInfo;

        var userProfile = new UserProfileDto
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
        };

        return Results.Ok(userProfile);
    }

    /// <summary>
    /// Gets all users in the current tenant
    /// </summary>
    /// <param name="userManager">User manager from DI</param>
    /// <param name="tenantAccessor">Tenant accessor from DI</param>
    /// <returns>List of users in current tenant</returns>
    private static async Task<IResult> GetUsersAsync(
        [FromServices] UserManager<IdmtUser> userManager,
        [FromServices] IMultiTenantContextAccessor tenantAccessor)
    {
        var currentTenant = tenantAccessor.MultiTenantContext?.TenantInfo;
        if (currentTenant == null)
        {
            return Results.BadRequest(new { error = "Tenant context not found" });
        }

        // Get all users for the current tenant
        var allUsers = userManager.Users.Where(u => u.TenantId == currentTenant.Id).ToList();
        
        var userDtos = new List<UserListDto>();
        
        foreach (var user in allUsers)
        {
            var roles = await userManager.GetRolesAsync(user);
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

        return Results.Ok(userDtos);
    }

    /// <summary>
    /// Gets tenant information
    /// </summary>
    /// <param name="tenantAccessor">Tenant accessor from DI</param>
    /// <returns>Current tenant information</returns>
    private static IResult GetTenantInfoAsync(
        [FromServices] IMultiTenantContextAccessor tenantAccessor)
    {
        var currentTenant = tenantAccessor.MultiTenantContext?.TenantInfo;
        if (currentTenant == null)
        {
            return Results.BadRequest(new { error = "Tenant context not found" });
        }

        var tenantInfo = new TenantInfoDto
        {
            Id = currentTenant.Id!,
            Name = currentTenant.Name!,
            Identifier = currentTenant.Identifier!
        };

        return Results.Ok(tenantInfo);
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