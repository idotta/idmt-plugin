using Idmt.Plugin.Models;

namespace Idmt.UnitTests.Models;

public class SysRoleKindTests
{
    [Fact]
    public void Enum_SysAdmin_StringValue_EqualsSysAdmin()
    {
        Assert.Equal("SysAdmin", SysRoleKind.SysAdmin.ToString());
    }

    [Fact]
    public void Enum_SysSupport_StringValue_EqualsSysSupport()
    {
        Assert.Equal("SysSupport", SysRoleKind.SysSupport.ToString());
    }

    [Fact]
    public void Enum_None_StringValue_EqualsNone()
    {
        Assert.Equal("None", SysRoleKind.None.ToString());
    }

    [Fact]
    public void Enum_None_IsZero()
    {
        Assert.Equal(0, (int)SysRoleKind.None);
    }

    [Fact]
    public void Enum_StringValue_MatchesIdmtDefaultRoleTypes()
    {
        Assert.Equal(IdmtDefaultRoleTypes.SysAdmin, SysRoleKind.SysAdmin.ToString());
        Assert.Equal(IdmtDefaultRoleTypes.SysSupport, SysRoleKind.SysSupport.ToString());
    }
}
