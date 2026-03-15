namespace Idmt.Plugin.Models;

/// <summary>
/// Interface for entities that can be audited.
/// Implementing this interface allows entities to be tracked 
/// and logged when they are created, modified, or deleted.
/// </summary>
public interface IAuditable
{
    /// <summary>
    /// Get the ID of the entity.
    /// </summary>
    string GetId();

    /// <summary>
    /// Get the name of the entity.
    /// </summary>
    string GetName();

    /// <summary>
    /// Get the tenant ID of the entity.
    /// </summary>
    string? GetTenantId();
}
