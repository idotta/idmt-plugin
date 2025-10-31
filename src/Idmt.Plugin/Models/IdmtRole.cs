using Microsoft.AspNetCore.Identity;

namespace Idmt.Plugin.Models;

/// <summary>
/// Multi-tenant application role that extends IdentityRole
/// </summary>
public class IdmtRole : IdentityRole<Guid>
{
    public IdmtRole() : base() { }

    public IdmtRole(string name) : base(name) { }

    public override Guid Id { get; set; } = Guid.CreateVersion7();
    public override string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
}