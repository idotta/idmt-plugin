using Idmt.Plugin.Models;

namespace Idmt.UnitTests.Models;

public class IdmtUserTests
{
    [Fact]
    public void New_DefaultsSysRoleToNone()
    {
        var user = new IdmtUser();
        Assert.Equal(SysRoleKind.None, user.SysRole);
    }

    [Fact]
    public void New_DefaultsPendingEmailToNull()
    {
        var user = new IdmtUser();
        Assert.Null(user.PendingEmail);
    }
}
