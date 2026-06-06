using Idmt.Core.Authorization;
using Idmt.Core.Identity;

namespace Idmt.Core.Tests;

public class SupportCapabilityTests
{
    [Theory]
    [InlineData(SysRoleKind.SysAdmin)]
    [InlineData(SysRoleKind.SysSupport)]
    public void Active_sys_role_with_passing_gate_can_mint(SysRoleKind sysRole)
    {
        Assert.True(SupportCapability.CanMint(sysRole, tenantAccessGranted: true));
    }

    [Theory]
    [InlineData(SysRoleKind.SysAdmin)]
    [InlineData(SysRoleKind.SysSupport)]
    public void Active_sys_role_with_failing_gate_cannot_mint(SysRoleKind sysRole)
    {
        // The capability is necessary but not sufficient: the gate still applies.
        Assert.False(SupportCapability.CanMint(sysRole, tenantAccessGranted: false));
    }

    [Fact]
    public void No_sys_role_cannot_mint_even_with_passing_gate()
    {
        Assert.False(SupportCapability.CanMint(SysRoleKind.None, tenantAccessGranted: true));
    }
}
