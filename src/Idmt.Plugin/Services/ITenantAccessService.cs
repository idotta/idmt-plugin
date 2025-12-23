namespace Idmt.Plugin.Services;

/// <summary>
/// Service to manage tenant access permissions for users.
/// </summary>
public interface ITenantAccessService
{
    /// <summary>
    /// Checks if the specified user currently has access to the given tenant.
    /// </summary>
    /// <param name="userId">The ID of the user.</param>
    /// <param name="tenantIdentifier">The identifier of the tenant.</param>
    /// <returns>True if the user can access the tenant, false otherwise.</returns>
    Task<bool> CanAccessTenantAsync(Guid userId, string tenantIdentifier);

    /// <summary>
    /// Checks if the current user can assign the specified role.
    /// </summary>
    /// <param name="role">The role to check.</param>
    /// <returns>True if the current user can assign the role, false otherwise.</returns>
    bool CanAssignRole(string role);

    /// <summary>
    /// Checks if the current user can manage a user with the specified roles.
    /// </summary>
    /// <param name="targetUserRoles">The roles of the target user.</param>
    /// <returns>True if the current user can manage the user, false otherwise.</returns>
    bool CanManageUser(IEnumerable<string> targetUserRoles);
}