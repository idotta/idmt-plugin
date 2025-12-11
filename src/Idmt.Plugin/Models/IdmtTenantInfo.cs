using Finbuckle.MultiTenant.Abstractions;

namespace Idmt.Plugin.Models;

/// <summary>
/// Represents the information for a tenant in the multi-tenant application.
/// Implements ITenantInfo interface from Finbuckle.MultiTenant.
/// Identifier must be at least 3 characters long.
/// </summary>
public class IdmtTenantInfo : ITenantInfo, IAuditable
{
    /// <summary>
    /// Unique ID for the tenant (string representation of a GUID).
    /// </summary>
    public string? Id { get; set; } = Guid.CreateVersion7().ToString();

    /// <summary>
    /// Canonical identifier (slug) for use in URL routing and tenant lookup.
    /// </summary>
    public string? Identifier { get; set; }

    /// <summary>
    /// Internal name of the tenant (can be used for display/lookup).
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Human-readable display name for the tenant.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// The tenant's subscription or feature plan, if applicable.
    /// </summary>
    public string? Plan { get; set; }

    /// <summary>
    /// The connection string to the tenant's database, supporting per-tenant data isolation.
    /// </summary>
    public string? ConnectionString { get; set; }

    /// <summary>
    /// Soft delete flag. If false, this tenant is considered inactive.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Path to the tenant's specific login page; defaults to "/login".
    /// </summary>
    public string? LoginPath { get; set; } = "/login";

    /// <summary>
    /// Path to the tenant's specific logout page; defaults to "/logout".
    /// </summary>
    public string? LogoutPath { get; set; } = "/logout";

    /// <summary>
    /// Path to the access denied page for this tenant; defaults to "/access-denied".
    /// </summary>
    public string? AccessDeniedPath { get; set; } = "/access-denied";

    public string GetId() => Id ?? string.Empty;

    public string GetName() => nameof(IdmtTenantInfo);

    public string? GetTenantId() => Id;
}