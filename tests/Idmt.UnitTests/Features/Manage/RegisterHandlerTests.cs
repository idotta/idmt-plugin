using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Manage;

public class RegisterHandlerTests : IDisposable
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<RoleManager<IdmtRole>> _roleManagerMock;
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly Mock<ITenantAccessService> _tenantAccessServiceMock;
    private readonly Mock<IIdmtLinkGenerator> _linkGeneratorMock;
    private readonly Mock<IEmailSender<IdmtUser>> _emailSenderMock;
    private readonly IdmtDbContext _dbContext;
    private readonly RegisterUser.RegisterHandler _handler;

    public RegisterHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        var roleStoreMock = new Mock<IRoleStore<IdmtRole>>();
        _roleManagerMock = new Mock<RoleManager<IdmtRole>>(
            roleStoreMock.Object, null!, null!, null!, null!);

        _currentUserServiceMock = new Mock<ICurrentUserService>();
        _tenantAccessServiceMock = new Mock<ITenantAccessService>();
        _linkGeneratorMock = new Mock<IIdmtLinkGenerator>();
        _emailSenderMock = new Mock<IEmailSender<IdmtUser>>();

        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var dummyTenant = new IdmtTenantInfo("system-test-tenant", "system-test", "System Test Tenant");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var options = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;

        _dbContext = new IdmtDbContext(
            tenantAccessorMock.Object,
            options,
            _currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        _handler = new RegisterUser.RegisterHandler(
            NullLogger<RegisterUser.RegisterHandler>.Instance,
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _currentUserServiceMock.Object,
            _tenantAccessServiceMock.Object,
            _dbContext,
            _linkGeneratorMock.Object,
            _emailSenderMock.Object);
    }

    [Fact]
    public async Task ReturnsRoleNotFound_WhenRoleDoesNotExist()
    {
        // Arrange
        _tenantAccessServiceMock.Setup(x => x.CanAssignRole(It.IsAny<string>())).Returns(true);
        _currentUserServiceMock.SetupGet(x => x.TenantId).Returns("tenant-1");
        _roleManagerMock.Setup(x => x.RoleExistsAsync("NonExistentRole")).ReturnsAsync(false);

        var request = new RegisterUser.RegisterUserRequest
        {
            Email = "user@test.com",
            Role = "NonExistentRole"
        };

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.RoleNotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsForbidden_WhenCallerCannotAssignRole()
    {
        // Arrange
        _tenantAccessServiceMock.Setup(x => x.CanAssignRole("SysAdmin")).Returns(false);

        var request = new RegisterUser.RegisterUserRequest
        {
            Email = "user@test.com",
            Role = "SysAdmin"
        };

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.InsufficientPermissions", result.FirstError.Code);
        Assert.Equal(ErrorType.Forbidden, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsTenantNotResolved_WhenTenantIdIsNull()
    {
        // Arrange
        _tenantAccessServiceMock.Setup(x => x.CanAssignRole(It.IsAny<string>())).Returns(true);
        _currentUserServiceMock.SetupGet(x => x.TenantId).Returns((string?)null);

        var request = new RegisterUser.RegisterUserRequest
        {
            Email = "user@test.com",
            Role = "TenantAdmin"
        };

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.NotResolved", result.FirstError.Code);
    }

    [Fact]
    public async Task UsesEmailAsUsername_WhenUsernameNotProvided()
    {
        // Arrange
        var email = "user@test.com";
        _tenantAccessServiceMock.Setup(x => x.CanAssignRole(It.IsAny<string>())).Returns(true);
        _currentUserServiceMock.SetupGet(x => x.TenantId).Returns("tenant-1");
        _roleManagerMock.Setup(x => x.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(true);
        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock
            .Setup(x => x.AddToRoleAsync(It.IsAny<IdmtUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock
            .Setup(x => x.GeneratePasswordResetTokenAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync("reset-token");
        _linkGeneratorMock
            .Setup(x => x.GeneratePasswordResetLink(It.IsAny<string>(), It.IsAny<string>()))
            .Returns("https://example.com/reset");

        var request = new RegisterUser.RegisterUserRequest
        {
            Email = email,
            Username = null,
            Role = "TenantAdmin"
        };

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        _userManagerMock.Verify(x => x.CreateAsync(
            It.Is<IdmtUser>(u => u.UserName == email)), Times.Once);
    }

    [Fact]
    public async Task ReturnsCreationFailed_WhenCreateAsyncFails()
    {
        // Arrange
        _tenantAccessServiceMock.Setup(x => x.CanAssignRole(It.IsAny<string>())).Returns(true);
        _currentUserServiceMock.SetupGet(x => x.TenantId).Returns("tenant-1");
        _roleManagerMock.Setup(x => x.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(true);
        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Duplicate email" }));

        var request = new RegisterUser.RegisterUserRequest
        {
            Email = "user@test.com",
            Role = "TenantAdmin"
        };

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.CreationFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsCreationFailed_WhenRoleAssignmentFails()
    {
        // Arrange
        _tenantAccessServiceMock.Setup(x => x.CanAssignRole(It.IsAny<string>())).Returns(true);
        _currentUserServiceMock.SetupGet(x => x.TenantId).Returns("tenant-1");
        _roleManagerMock.Setup(x => x.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(true);
        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(IdentityResult.Success);
        _userManagerMock
            .Setup(x => x.AddToRoleAsync(It.IsAny<IdmtUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Role assignment failed" }));

        var request = new RegisterUser.RegisterUserRequest
        {
            Email = "user@test.com",
            Role = "TenantAdmin"
        };

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.CreationFailed", result.FirstError.Code);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }
}
