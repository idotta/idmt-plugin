using System.Security.Claims;
using Finbuckle.MultiTenant.Abstractions;
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
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
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
        _userManagerMock.Setup(x => x.GetSecurityStampAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync(() => Guid.NewGuid().ToString());
        _userManagerMock.Setup(x => x.GetUserIdAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync((IdmtUser u) => u.Id.ToString());
        _userManagerMock.Setup(x => x.GetUserNameAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync((IdmtUser u) => u.UserName ?? string.Empty);
        _userManagerMock.Setup(x => x.GetEmailAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync((IdmtUser u) => u.Email ?? string.Empty);
        _userManagerMock.Setup(x => x.GetPhoneNumberAsync(It.IsAny<IdmtUser>()))
            .ReturnsAsync((IdmtUser u) => u.PhoneNumber ?? string.Empty);

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

        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();

        _idmtOptionsMock = new Mock<IOptions<IdmtOptions>>();
        _idmtOptionsMock.Setup(x => x.Value).Returns(IdmtOptions.Default);

        _factory = new IdmtUserClaimsPrincipalFactory(
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _identityOptionsMock.Object,
            _tenantStoreMock.Object,
            _idmtOptionsMock.Object);
    }

    private async Task<ClaimsIdentity> CallGenerateClaimsAsync(IdmtUser user)
    {
        var method = typeof(IdmtUserClaimsPrincipalFactory)
            .GetMethod("GenerateClaimsAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        if (method == null)
        {
            throw new InvalidOperationException("GenerateClaimsAsync method not found.");
        }
        return (ClaimsIdentity)await (dynamic)method.Invoke(_factory, new object[] { user })!;
    }

    [Fact]
    public async Task CreateAsync_AddsIsActiveClaim_WithCorrectValue()
    {
        const string tenantId = "tenant-id-123";
        const string tenantIdentifier = "tenant-123";
        var tenantInfo = new IdmtTenantInfo(tenantId, tenantIdentifier, "Test Tenant");

        var user = new IdmtUser
        {
            Id = Guid.NewGuid(),
            UserName = "testuser",
            NormalizedUserName = "TESTUSER",
            Email = "test@example.com",
            NormalizedEmail = "TEST@EXAMPLE.COM",
            EmailConfirmed = true,
            PhoneNumber = "1234567890",
            PhoneNumberConfirmed = true,
            TwoFactorEnabled = false,
            LockoutEnabled = false,
            AccessFailedCount = 0,
            TenantId = tenantId,
            IsActive = true,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        _tenantStoreMock.Setup(x => x.GetAsync(tenantId))
            .ReturnsAsync(tenantInfo);

        var identity = await CallGenerateClaimsAsync(user);

        var isActiveClaim = identity.FindFirst("is_active");
        Assert.NotNull(isActiveClaim);
        Assert.Equal("True", isActiveClaim.Value);
    }

    [Fact]
    public async Task CreateAsync_AddsIsActiveClaim_WhenUserIsInactive()
    {
        const string tenantId = "tenant-id-123";
        const string tenantIdentifier = "tenant-123";
        var tenantInfo = new IdmtTenantInfo(tenantId, tenantIdentifier, "Test Tenant");

        var user = new IdmtUser
        {
            Id = Guid.NewGuid(),
            UserName = "testuser",
            Email = "test@example.com",
            TenantId = tenantId,
            IsActive = false,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        _tenantStoreMock.Setup(x => x.GetAsync(tenantId))
            .ReturnsAsync(tenantInfo);

        var identity = await CallGenerateClaimsAsync(user);

        var isActiveClaim = identity.FindFirst("is_active");
        Assert.NotNull(isActiveClaim);
        Assert.Equal("False", isActiveClaim.Value);
    }

    [Fact]
    public async Task CreateAsync_AddsTenantClaim_WithDefaultClaimType()
    {
        const string tenantId = "tenant-id-456";
        const string tenantIdentifier = "tenant-456";
        var tenantInfo = new IdmtTenantInfo(tenantId, tenantIdentifier, "Test Tenant");

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

        _tenantStoreMock.Setup(x => x.GetAsync(tenantId))
            .ReturnsAsync(tenantInfo);

        var identity = await CallGenerateClaimsAsync(user);

        var tenantClaim = identity.FindFirst(IdmtMultiTenantStrategy.DefaultClaim);
        Assert.NotNull(tenantClaim);
        // The factory adds tenantInfo.Identifier, not tenantId
        Assert.Equal(tenantIdentifier, tenantClaim.Value);
    }

    [Fact]
    public async Task CreateAsync_AddsTenantClaim_WithCustomClaimType()
    {
        const string customClaimType = "custom_tenant_claim";
        const string tenantId = "tenant-id-789";
        const string tenantIdentifier = "tenant-789";
        var tenantInfo = new IdmtTenantInfo(tenantId, tenantIdentifier, "Test Tenant");

        var customOptions = new IdmtOptions
        {
            MultiTenant = new MultiTenantOptions
            {
                StrategyOptions = new Dictionary<string, string>
                {
                    { IdmtMultiTenantStrategy.Claim, customClaimType }
                }
            }
        };

        var customOptionsMock = new Mock<IOptions<IdmtOptions>>();
        customOptionsMock.Setup(x => x.Value).Returns(customOptions);

        var customTenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();
        customTenantStoreMock.Setup(x => x.GetAsync(tenantId))
            .ReturnsAsync(tenantInfo);

        var customFactory = new IdmtUserClaimsPrincipalFactory(
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _identityOptionsMock.Object,
            customTenantStoreMock.Object,
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

        var customMethod = typeof(IdmtUserClaimsPrincipalFactory)
            .GetMethod("GenerateClaimsAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var identity = (ClaimsIdentity)await (dynamic)customMethod!.Invoke(customFactory, new object[] { user })!;

        var tenantClaim = identity.FindFirst(customClaimType);
        Assert.NotNull(tenantClaim);
        // The factory adds tenantInfo.Identifier, not tenantId
        Assert.Equal(tenantIdentifier, tenantClaim.Value);

        // Verify default claim type is not present
        var defaultTenantClaim = identity.FindFirst(IdmtMultiTenantStrategy.DefaultClaim);
        Assert.Null(defaultTenantClaim);
    }

    [Fact]
    public async Task CreateAsync_IncludesBaseClaims()
    {
        const string tenantId = "tenant-id-123";
        const string tenantIdentifier = "tenant-123";
        var tenantInfo = new IdmtTenantInfo(tenantId, tenantIdentifier, "Test Tenant");

        var userId = Guid.NewGuid();
        var user = new IdmtUser
        {
            Id = userId,
            UserName = "testuser",
            Email = "test@example.com",
            TenantId = tenantId,
            IsActive = true,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };

        _tenantStoreMock.Setup(x => x.GetAsync(tenantId))
            .ReturnsAsync(tenantInfo);

        var identity = await CallGenerateClaimsAsync(user);

        // Verify base claims are present (from base.GenerateClaimsAsync)
        var nameIdentifierClaim = identity.FindFirst(ClaimTypes.NameIdentifier);
        Assert.NotNull(nameIdentifierClaim);
        Assert.Equal(userId.ToString(), nameIdentifierClaim.Value);

        var nameClaim = identity.FindFirst(ClaimTypes.Name);
        Assert.NotNull(nameClaim);
        Assert.Equal(user.UserName, nameClaim.Value);
    }

    [Fact]
    public async Task CreateAsync_AddsAllCustomClaims()
    {
        const string tenantId = "tenant-id-999";
        const string tenantIdentifier = "tenant-999";
        var tenantInfo = new IdmtTenantInfo(tenantId, tenantIdentifier, "Test Tenant");

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

        _tenantStoreMock.Setup(x => x.GetAsync(tenantId))
            .ReturnsAsync(tenantInfo);

        var identity = await CallGenerateClaimsAsync(user);

        // Verify both custom claims are present
        var isActiveClaim = identity.FindFirst("is_active");
        Assert.NotNull(isActiveClaim);
        Assert.Equal("True", isActiveClaim.Value);

        var tenantClaim = identity.FindFirst(IdmtMultiTenantStrategy.DefaultClaim);
        Assert.NotNull(tenantClaim);
        // The factory adds tenantInfo.Identifier, not tenantId
        Assert.Equal(tenantIdentifier, tenantClaim.Value);
    }
}

