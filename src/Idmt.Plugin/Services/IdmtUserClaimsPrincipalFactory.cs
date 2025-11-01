using System.Security.Claims;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Services;

internal sealed class IdmtUserClaimsPrincipalFactory(
    UserManager<IdmtUser> userManager,
    RoleManager<IdmtRole> roleManager,
    IOptions<IdentityOptions> optionsAccessor)
    : UserClaimsPrincipalFactory<IdmtUser, IdmtRole>(userManager, roleManager, optionsAccessor)
{
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(IdmtUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        // Add custom claims
        identity.AddClaim(new Claim("is_active", user.IsActive.ToString()));

        return identity;
    }
}
