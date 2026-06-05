using Finbuckle.MultiTenant.Abstractions;
using Microsoft.AspNetCore.Identity;

namespace Idmt.Spike.Host.Domain;

/// <summary>Global system-role flag, mirrors v1 SysRoleKind.</summary>
public enum SysRoleKind
{
    None = 0,
    SysAdmin = 1,
    SysSupport = 2,
}

/// <summary>Global canonical identity (one row per human). Mirrors v1 IdmtUser.</summary>
public class IdmtUser : IdentityUser<Guid>
{
    public override Guid Id { get; set; } = Guid.CreateVersion7();
    public override string? SecurityStamp { get; set; } = Guid.NewGuid().ToString();
    public SysRoleKind SysRole { get; set; } = SysRoleKind.None;
    public bool IsActive { get; set; } = true;
}

/// <summary>Per-tenant role. Mirrors v1 IdmtRole.</summary>
public class IdmtRole : IdentityRole<Guid>
{
    public IdmtRole() { }
    public IdmtRole(string name) : base(name) { }

    public override Guid Id { get; set; } = Guid.CreateVersion7();
    public string TenantId { get; set; } = null!;
}

/// <summary>
/// User-to-tenant edge. NOT multi-tenant: the issuance gate queries it by
/// (userId, tenantId) at the token endpoint where no ambient tenant exists.
/// </summary>
public sealed class TenantAccess
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid UserId { get; set; }
    public string TenantId { get; set; } = null!;
    public bool IsActive { get; set; } = true;
    public DateTimeOffset? ExpiresAt { get; set; }
}

/// <summary>
/// Trivial multi-tenant entity used only to prove gate 4: Finbuckle stamps
/// TenantId on save under an ambient tenant, in the same database/connection
/// that hosts the (tenant-agnostic) OpenIddict stores.
/// </summary>
[MultiTenant]
public sealed class TenantWidget
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public string Label { get; set; } = null!;
    public string TenantId { get; set; } = null!;
}

/// <summary>
/// Support-impersonation audit row. Lives in the tenant-agnostic OpenIddict
/// DbContext so its write shares OpenIddict's store transaction (gate 2).
/// </summary>
public sealed class SupportAudit
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid ActorUserId { get; set; }
    public string TenantId { get; set; } = null!;
    public string Reason { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Tenant descriptor. Mirrors the v1 IdmtTenantInfo shape.</summary>
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
