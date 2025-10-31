using Idmt.Plugin.Models;

namespace Idmt.Plugin.Services;

/// <summary>
/// Service to manage tenant access permissions for users.
/// </summary>
public interface ITenantAccessService
{
    /// <summary>
    /// Gets the tenant IDs that the specified user can access.
    /// </summary>
    /// <param name="userId">The ID of the user.</param>
    /// <returns>A list of tenant IDs that the user can access.</returns>
    Task<string[]> GetUserAccessibleTenantsAsync(Guid userId);

    /// <summary>
    /// Checks if the specified user currently has access to the given tenant.
    /// </summary>
    /// <param name="userId">The ID of the user.</param>
    /// <param name="tenantId">The ID of the tenant.</param>
    /// <returns>True if the user can access the tenant, false otherwise.</returns>
    Task<bool> CanAccessTenantAsync(Guid userId, string tenantId);

    /// <summary>
    /// Grants a user access to a tenant.
    /// If access already exists, it is reactivated and updated.
    /// Also adds the user record to the target tenant if needed.
    /// </summary>
    /// <param name="userId">The ID of the user to grant access to.</param>
    /// <param name="tenantId">The ID of the tenant.</param>
    /// <param name="expiresAt">An optional expiration date for access.</param>
    /// <returns>True if access was granted, false otherwise.</returns>
    Task<bool> GrantTenantAccessAsync(Guid userId, string tenantId, DateTime? expiresAt = null);

    /// <summary>
    /// Revokes a user's access to a tenant.
    /// Sets the user's access as inactive and disables their user record in the tenant.
    /// </summary>
    /// <param name="userId">The ID of the user to revoke access from.</param>
    /// <param name="tenantId">The ID of the tenant.</param>
    /// <returns>True if access was revoked, false otherwise.</returns>
    Task<bool> RevokeTenantAccessAsync(Guid userId, string tenantId);
}