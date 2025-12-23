using Finbuckle.MultiTenant.Abstractions;

namespace Idmt.Plugin.Models;

/// <summary>
/// Represents the information for a tenant in the multi-tenant application.
/// Implements ITenantInfo interface from Finbuckle.MultiTenant.
/// Identifier must be at least 3 characters long.
/// </summary>
public record IdmtTenantInfo : TenantInfo, IAuditable
{
    public IdmtTenantInfo(string id, string identifier, string name) : base(id, identifier, name)
    {
    }

    public IdmtTenantInfo(string identifier, string name) : base(Guid.CreateVersion7().ToString(), identifier, name)
    {
    }

    /// <summary>
    /// Human-readable display name for the tenant.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// The tenant's subscription or feature plan, if applicable.
    /// </summary>
    public string? Plan { get; init; }

    /// <summary>
    /// The connection string to the tenant's database, supporting per-tenant data isolation.
    /// </summary>
    public string? ConnectionString { get; init; }

    /// <summary>
    /// Soft delete flag. If false, this tenant is considered inactive.
    /// </summary>
    public bool IsActive { get; init; } = true;

    /// <summary>
    /// Path to the tenant's specific login page; defaults to "/login".
    /// </summary>
    public string? LoginPath { get; init; } = "/login";

    /// <summary>
    /// Path to the tenant's specific logout page; defaults to "/logout".
    /// </summary>
    public string? LogoutPath { get; init; } = "/logout";

    /// <summary>
    /// Path to the access denied page for this tenant; defaults to "/access-denied".
    /// </summary>
    public string? AccessDeniedPath { get; init; } = "/access-denied";

    public string GetId() => Id ?? string.Empty;

    public string GetName() => nameof(IdmtTenantInfo);

    public string? GetTenantId() => Id;
}