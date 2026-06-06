using Microsoft.AspNetCore.Identity;

namespace Idmt.Core.Identity;

/// <summary>
/// Per-tenant role: a role name scoped to a tenant by <see cref="TenantId"/>.
/// System authority does not live here. Post-canonicalization, SysAdmin and
/// SysSupport are sourced from <see cref="IdmtUser.SysRole"/> plus the uniform
/// TenantAccess gate, not from per-tenant role rows.
/// </summary>
public class IdmtRole : IdentityRole<Guid>
{
    public IdmtRole() { }

    public IdmtRole(string name) : base(name) { }

    public override Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>The Finbuckle tenant identifier this role scopes to.</summary>
    public required string TenantId { get; set; }
}
