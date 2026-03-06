using ErrorOr;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Manage;

public class UpdateUserHandlerTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<ITenantAccessService> _tenantAccessServiceMock;
    private readonly UpdateUser.UpdateUserHandler _handler;

    public UpdateUserHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _tenantAccessServiceMock = new Mock<ITenantAccessService>();

        _handler = new UpdateUser.UpdateUserHandler(
            _userManagerMock.Object,
            _tenantAccessServiceMock.Object,
            NullLogger<UpdateUser.UpdateUserHandler>.Instance);
    }

    [Fact]
    public async Task ReturnsNotFound_WhenUserDoesNotExist()
    {
        // Arrange
        SetupUsersQueryable([]);
        var request = new UpdateUser.UpdateUserRequest(IsActive: true);

        // Act
        var result = await _handler.HandleAsync(Guid.NewGuid(), request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.NotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.NotFound, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsForbidden_WhenCannotManageUser()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var user = new IdmtUser
        {
            Id = userId,
            UserName = "target@test.com",
            Email = "target@test.com",
            TenantId = "tenant-1"
        };
        SetupUsersQueryable([user]);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["SysAdmin"]);
        _tenantAccessServiceMock.Setup(x => x.CanManageUser(It.IsAny<IEnumerable<string>>())).Returns(false);

        var request = new UpdateUser.UpdateUserRequest(IsActive: false);

        // Act
        var result = await _handler.HandleAsync(userId, request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.InsufficientPermissions", result.FirstError.Code);
        Assert.Equal(ErrorType.Forbidden, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsUpdateFailed_WhenIdentityUpdateFails()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var user = new IdmtUser
        {
            Id = userId,
            UserName = "target@test.com",
            Email = "target@test.com",
            TenantId = "tenant-1",
            IsActive = true
        };
        SetupUsersQueryable([user]);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["TenantAdmin"]);
        _tenantAccessServiceMock.Setup(x => x.CanManageUser(It.IsAny<IEnumerable<string>>())).Returns(true);
        _userManagerMock.Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Update failed" }));

        var request = new UpdateUser.UpdateUserRequest(IsActive: false);

        // Act
        var result = await _handler.HandleAsync(userId, request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.UpdateFailed", result.FirstError.Code);
    }

    private void SetupUsersQueryable(List<IdmtUser> users)
    {
        var queryable = users.AsQueryable();
        var mockDbSet = new Mock<IQueryable<IdmtUser>>();
        mockDbSet.As<IAsyncEnumerable<IdmtUser>>()
            .Setup(m => m.GetAsyncEnumerator(It.IsAny<CancellationToken>()))
            .Returns(new TestAsyncEnumerator<IdmtUser>(queryable.GetEnumerator()));
        mockDbSet.As<IQueryable<IdmtUser>>().Setup(m => m.Provider)
            .Returns(new TestAsyncQueryProvider<IdmtUser>(queryable.Provider));
        mockDbSet.As<IQueryable<IdmtUser>>().Setup(m => m.Expression).Returns(queryable.Expression);
        mockDbSet.As<IQueryable<IdmtUser>>().Setup(m => m.ElementType).Returns(queryable.ElementType);
        mockDbSet.As<IQueryable<IdmtUser>>().Setup(m => m.GetEnumerator()).Returns(queryable.GetEnumerator());

        _userManagerMock.SetupGet(x => x.Users).Returns(mockDbSet.Object);
    }
}
