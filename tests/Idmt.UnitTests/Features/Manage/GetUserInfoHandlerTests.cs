using System.Security.Claims;
using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Moq;

namespace Idmt.UnitTests.Features.Manage;

public class GetUserInfoHandlerTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly GetUserInfo.GetUserInfoHandler _handler;

    public GetUserInfoHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();

        _handler = new GetUserInfo.GetUserInfoHandler(
            _userManagerMock.Object,
            _tenantStoreMock.Object);
    }

    [Fact]
    public async Task ReturnsClaimsNotFound_WhenEmailClaimMissing()
    {
        // Arrange - principal with no email claim
        var principal = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.Name, "testuser")
        ], "Bearer"));

        // Act
        var result = await _handler.HandleAsync(principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.ClaimsNotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsNotFound_WhenUserDoesNotExistInDb()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("nonexistent@test.com");
        _userManagerMock.Setup(x => x.FindByEmailAsync("nonexistent@test.com"))
            .ReturnsAsync((IdmtUser?)null);

        // Act
        var result = await _handler.HandleAsync(principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.NotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.NotFound, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsNotFound_WhenUserIsInactive()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("inactive@test.com");
        var user = new IdmtUser
        {
            UserName = "inactive",
            Email = "inactive@test.com",
            TenantId = "tenant-1",
            IsActive = false
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("inactive@test.com")).ReturnsAsync(user);

        // Act
        var result = await _handler.HandleAsync(principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.NotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsNoRolesAssigned_WhenUserHasNoRoles()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("noroles@test.com");
        var user = new IdmtUser
        {
            UserName = "noroles",
            Email = "noroles@test.com",
            TenantId = "tenant-1",
            IsActive = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("noroles@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync([]);

        // Act
        var result = await _handler.HandleAsync(principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.NoRolesAssigned", result.FirstError.Code);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsTenantNotFound_WhenTenantDoesNotExist()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "user@test.com",
            TenantId = "missing-tenant",
            IsActive = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["TenantAdmin"]);
        _tenantStoreMock.Setup(x => x.GetAsync("missing-tenant")).ReturnsAsync((IdmtTenantInfo?)null);

        // Act
        var result = await _handler.HandleAsync(principal);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.NotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.NotFound, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsAllRoles_WhenUserHasSingleRole()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "user@test.com",
            TenantId = "tenant-1",
            IsActive = true
        };
        var tenant = new IdmtTenantInfo("tenant-1", "Tenant One");

        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["Member"]);
        _tenantStoreMock.Setup(x => x.GetAsync("tenant-1")).ReturnsAsync(tenant);

        // Act
        var result = await _handler.HandleAsync(principal);

        // Assert
        Assert.False(result.IsError);
        Assert.Single(result.Value.Roles);
        Assert.Equal("Member", result.Value.Roles[0]);
    }

    [Fact]
    public async Task ReturnsAllRoles_SortedAlphabetically_WhenUserHasMultipleRoles()
    {
        // Arrange
        var principal = CreatePrincipalWithEmail("multi@test.com");
        var user = new IdmtUser
        {
            UserName = "multiuser",
            Email = "multi@test.com",
            TenantId = "tenant-1",
            IsActive = true
        };
        var tenant = new IdmtTenantInfo("tenant-1", "Tenant One");

        _userManagerMock.Setup(x => x.FindByEmailAsync("multi@test.com")).ReturnsAsync(user);
        // Roles are intentionally supplied in non-alphabetical order to verify sorting.
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["TenantAdmin", "Member", "Auditor"]);
        _tenantStoreMock.Setup(x => x.GetAsync("tenant-1")).ReturnsAsync(tenant);

        // Act
        var result = await _handler.HandleAsync(principal);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal(3, result.Value.Roles.Count);
        Assert.Equal(new[] { "Auditor", "Member", "TenantAdmin" }, result.Value.Roles);
    }

    private static ClaimsPrincipal CreatePrincipalWithEmail(string email)
    {
        return new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Name, "testuser")
        ], "Bearer"));
    }
}
