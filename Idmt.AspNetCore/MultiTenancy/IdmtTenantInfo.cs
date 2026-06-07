using Finbuckle.MultiTenant.Abstractions;

namespace Idmt.AspNetCore.MultiTenancy;

/// <summary>
/// The Finbuckle tenant descriptor persisted by <c>IdmtTenantStoreDbContext</c>
/// and resolved against per request. Minimal proven shape carried from the spike;
/// 05-multitenancy-audience.md may extend it when it wires tenant resolution.
/// </summary>
public record IdmtTenantInfo : ITenantInfo
{
    public IdmtTenantInfo() { }

    public IdmtTenantInfo(string identifier, string name)
    {
        Id = Guid.CreateVersion7().ToString();
        Identifier = identifier;
        Name = name;
    }

    public string Id { get; set; } = null!;
    public string Identifier { get; set; } = null!;
    public string? Name { get; set; }
    public bool IsActive { get; set; } = true;
}
