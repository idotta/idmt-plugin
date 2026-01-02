using System.Security.Claims;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Services;

/// <summary>
/// Unit tests for IdmtUserClaimsPrincipalFactory.
/// Tests that custom claims (is_active and tenant) are correctly added to the user's claims identity.
/// </summary>
public class IdmtUserClaimsPrincipalFactoryTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<RoleManager<IdmtRole>> _roleManagerMock;
    private readonly Mock<IOptions<IdentityOptions>> _identityOptionsMock;
    private readonly Mock<IOptions<IdmtOptions>> _idmtOptionsMock;
    private readonly IdmtUserClaimsPrincipalFactory _factory;

    public IdmtUserClaimsPrincipalFactoryTests()
    {
        var userStoreMock = Mock.Of<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock,
            null!, null!, null!, null!, null!, null!, null!, null!);

        // Mock UserManager methods that the base class might call
        _userManagerMock.Setup(x => x.GetRolesAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(Array.Empty<string>());
        _userManagerMock.Setup(x => x.GetClaimsAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(Array.Empty<Claim>());

        var roleStoreMock = Mock.Of<IRoleStore<IdmtRole>>();
        _roleManagerMock = new Mock<RoleManager<IdmtRole>>(
            roleStoreMock,
            null!, null!, null!, null!);

        _identityOptionsMock = new Mock<IOptions<IdentityOptions>>();
        var identityOptions = new IdentityOptions
        {
            ClaimsIdentity = new ClaimsIdentityOptions
            {
                // Configure claim types to avoid null value issues
                EmailClaimType = ClaimTypes.Email,
                RoleClaimType = ClaimTypes.Role,
                SecurityStampClaimType = "AspNet.Identity.SecurityStamp",
                UserIdClaimType = ClaimTypes.NameIdentifier,
                UserNameClaimType = ClaimTypes.Name
            }
        };
        _identityOptionsMock.Setup(x => x.Value).Returns(identityOptions);

        _idmtOptionsMock = new Mock<IOptions<IdmtOptions>>();
        _idmtOptionsMock.Setup(x => x.Value).Returns(IdmtOptions.Default);

        _factory = new IdmtUserClaimsPrincipalFactory(
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _identityOptionsMock.Object,
            _idmtOptionsMock.Object);
    }

    [Fact]
    public async Task CreateAsync_AddsIsActiveClaim_WithCorrectValue()
    {
        var user = new IdmtUser
        {
            Id = Guid.NewGuid(),
            UserName = "testuser",
            Email = "test@example.com",
            EmailConfirmed = false,
            PhoneNumber = null,
            PhoneNumberConfirmed = false,
            TwoFactorEnabled = false,
            LockoutEnabled = false,
            AccessFailedCount = 0,
            TenantId = "tenant-123",
            IsActive = true,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        var principal = await _factory.CreateAsync(user);

        var isActiveClaim = principal.FindFirst("is_active");
        Assert.NotNull(isActiveClaim);
        Assert.Equal("True", isActiveClaim.Value);
    }

    [Fact]
    public async Task CreateAsync_AddsIsActiveClaim_WhenUserIsInactive()
    {
        var user = new IdmtUser
        {
            Id = Guid.NewGuid(),
            UserName = "testuser",
            Email = "test@example.com",
            TenantId = "tenant-123",
            IsActive = false,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        var principal = await _factory.CreateAsync(user);

        var isActiveClaim = principal.FindFirst("is_active");
        Assert.NotNull(isActiveClaim);
        Assert.Equal("False", isActiveClaim.Value);
    }

    [Fact]
    public async Task CreateAsync_AddsTenantClaim_WithDefaultClaimType()
    {
        const string tenantId = "tenant-456";
        var user = new IdmtUser
        {
            Id = Guid.NewGuid(),
            UserName = "testuser",
            Email = "test@example.com",
            TenantId = tenantId,
            IsActive = true,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        var principal = await _factory.CreateAsync(user);

        var tenantClaim = principal.FindFirst(IdmtMultiTenantStrategy.DefaultClaimType);
        Assert.NotNull(tenantClaim);
        Assert.Equal(tenantId, tenantClaim.Value);
    }

    [Fact]
    public async Task CreateAsync_AddsTenantClaim_WithCustomClaimType()
    {
        const string customClaimType = "custom_tenant_claim";
        const string tenantId = "tenant-789";

        var customOptions = new IdmtOptions
        {
            MultiTenant = new MultiTenantOptions
            {
                StrategyOptions = new Dictionary<string, string>
                {
                    { IdmtMultiTenantStrategy.ClaimOption, customClaimType }
                }
            }
        };

        var customOptionsMock = new Mock<IOptions<IdmtOptions>>();
        customOptionsMock.Setup(x => x.Value).Returns(customOptions);

        var customFactory = new IdmtUserClaimsPrincipalFactory(
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _identityOptionsMock.Object,
            customOptionsMock.Object);

        var user = new IdmtUser
        {
            Id = Guid.NewGuid(),
            UserName = "testuser",
            Email = "test@example.com",
            TenantId = tenantId,
            IsActive = true,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        var principal = await customFactory.CreateAsync(user);

        var tenantClaim = principal.FindFirst(customClaimType);
        Assert.NotNull(tenantClaim);
        Assert.Equal(tenantId, tenantClaim.Value);

        // Verify default claim type is not present
        var defaultTenantClaim = principal.FindFirst(IdmtMultiTenantStrategy.DefaultClaimType);
        Assert.Null(defaultTenantClaim);
    }

    [Fact]
    public async Task CreateAsync_IncludesBaseClaims()
    {
        var userId = Guid.NewGuid();
        var user = new IdmtUser
        {
            Id = userId,
            UserName = "testuser",
            Email = "test@example.com",
            TenantId = "tenant-123",
            IsActive = true,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        var principal = await _factory.CreateAsync(user);

        // Verify base claims are present (from base.GenerateClaimsAsync)
        var nameIdentifierClaim = principal.FindFirst(ClaimTypes.NameIdentifier);
        Assert.NotNull(nameIdentifierClaim);
        Assert.Equal(userId.ToString(), nameIdentifierClaim.Value);

        var nameClaim = principal.FindFirst(ClaimTypes.Name);
        Assert.NotNull(nameClaim);
        Assert.Equal(user.UserName, nameClaim.Value);
    }

    [Fact]
    public async Task CreateAsync_AddsAllCustomClaims()
    {
        const string tenantId = "tenant-999";
        var user = new IdmtUser
        {
            Id = Guid.NewGuid(),
            UserName = "testuser",
            Email = "test@example.com",
            TenantId = tenantId,
            IsActive = true,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        var principal = await _factory.CreateAsync(user);

        // Verify both custom claims are present
        var isActiveClaim = principal.FindFirst("is_active");
        Assert.NotNull(isActiveClaim);
        Assert.Equal("True", isActiveClaim.Value);

        var tenantClaim = principal.FindFirst(IdmtMultiTenantStrategy.DefaultClaimType);
        Assert.NotNull(tenantClaim);
        Assert.Equal(tenantId, tenantClaim.Value);
    }
}

