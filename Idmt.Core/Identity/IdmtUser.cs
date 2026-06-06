using Microsoft.AspNetCore.Identity;

namespace Idmt.Core.Identity;

/// <summary>
/// The canonical, global identity for a human. One row per human across all
/// tenants; <see cref="IdentityUser{Guid}.NormalizedEmail"/> is globally unique.
/// </summary>
/// <remarks>
/// This is a scaffold stub. The full domain (SysRole, PendingEmail, and the
/// rest of the canonical model) is filled in by 02-core-domain.md.
/// </remarks>
public class IdmtUser : IdentityUser<Guid>
{
}
