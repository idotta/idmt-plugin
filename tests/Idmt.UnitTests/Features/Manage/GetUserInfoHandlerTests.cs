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
    private readonly Mock<IMultiTenantContextAccessor<IdmtTenantInfo>> _tenantAccessorMock;
    private readonly GetUserInfo.GetUserInfoHandler _handler;

    public GetUserInfoHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _tenantAccessorMock = new Mock<IMultiTenantContextAccessor<IdmtTenantInfo>>();

        _handler = new GetUserInfo.GetUserInfoHandler(
            _userManagerMock.Object,
            _tenantAccessorMock.Object);
    }

    private void SetTenantContext(IdmtTenantInfo? tenant)
    {
        if (tenant is null)
        {
            _tenantAccessorMock.SetupGet(x => x.MultiTenantContext)
                .Returns((IMultiTenantContext<IdmtTenantInfo>)null!);
        }
        else
        {
            _tenantAccessorMock.SetupGet(x => x.MultiTenantContext)
                .Returns(new MultiTenantContext<IdmtTenantInfo>(tenant));
        }
    }

    [Fact]
    public async Task ReturnsClaimsNotFound_WhenEmailClaimMissing()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.Name, "testuser")
        ], "Bearer"));

        var result = await _handler.HandleAsync(principal);

        Assert.True(result.IsError);
        Assert.Equal("User.ClaimsNotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsNotFound_WhenUserDoesNotExistInDb()
    {
        var principal = CreatePrincipalWithEmail("nonexistent@test.com");
        _userManagerMock.Setup(x => x.FindByEmailAsync("nonexistent@test.com"))
            .ReturnsAsync((IdmtUser?)null);

        var result = await _handler.HandleAsync(principal);

        Assert.True(result.IsError);
        Assert.Equal("User.NotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.NotFound, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsNotFound_WhenUserIsInactive()
    {
        var principal = CreatePrincipalWithEmail("inactive@test.com");
        var user = new IdmtUser
        {
            UserName = "inactive",
            Email = "inactive@test.com",
            IsActive = false
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("inactive@test.com")).ReturnsAsync(user);

        var result = await _handler.HandleAsync(principal);

        Assert.True(result.IsError);
        Assert.Equal("User.NotFound", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsNoRolesAssigned_WhenUserHasNoRoles()
    {
        var principal = CreatePrincipalWithEmail("noroles@test.com");
        var user = new IdmtUser
        {
            UserName = "noroles",
            Email = "noroles@test.com",
            IsActive = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("noroles@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync([]);

        var result = await _handler.HandleAsync(principal);

        Assert.True(result.IsError);
        Assert.Equal("User.NoRolesAssigned", result.FirstError.Code);
        Assert.Equal(ErrorType.Validation, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsTenantNotFound_WhenAmbientTenantContextMissing()
    {
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "user@test.com",
            IsActive = true
        };
        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["TenantAdmin"]);
        SetTenantContext(null);

        var result = await _handler.HandleAsync(principal);

        Assert.True(result.IsError);
        Assert.Equal("Tenant.NotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.NotFound, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsAllRoles_WhenUserHasSingleRole()
    {
        var principal = CreatePrincipalWithEmail("user@test.com");
        var user = new IdmtUser
        {
            UserName = "testuser",
            Email = "user@test.com",
            IsActive = true
        };
        var tenant = new IdmtTenantInfo("tenant-1", "tenant-1", "Tenant One");

        _userManagerMock.Setup(x => x.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["Member"]);
        SetTenantContext(tenant);

        var result = await _handler.HandleAsync(principal);

        Assert.False(result.IsError);
        Assert.Single(result.Value.Roles);
        Assert.Equal("Member", result.Value.Roles[0]);
    }

    [Fact]
    public async Task ReturnsAllRoles_SortedAlphabetically_WhenUserHasMultipleRoles()
    {
        var principal = CreatePrincipalWithEmail("multi@test.com");
        var user = new IdmtUser
        {
            UserName = "multiuser",
            Email = "multi@test.com",
            IsActive = true
        };
        var tenant = new IdmtTenantInfo("tenant-1", "tenant-1", "Tenant One");

        _userManagerMock.Setup(x => x.FindByEmailAsync("multi@test.com")).ReturnsAsync(user);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["TenantAdmin", "Member", "Auditor"]);
        SetTenantContext(tenant);

        var result = await _handler.HandleAsync(principal);

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
