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
/// Unit tests for <see cref="IdmtUserClaimsPrincipalFactory"/>.
///
/// Phase 1 (canonical identity) behaviour pinned here:
/// - Tenant claim is sourced from the ambient <see cref="IMultiTenantContextAccessor"/>;
///   <see cref="IdmtUser"/> no longer carries a TenantId column.
/// - Principal generation throws <see cref="InvalidOperationException"/> when the ambient
///   tenant context is null (CD-4 fail-closed).
/// - <see cref="SysRoleKind"/> is emitted as <c>Claim(ClaimTypes.Role, "SysAdmin"|"SysSupport")</c>
///   when the user has a non-<c>None</c> SysRole.
/// </summary>
public class IdmtUserClaimsPrincipalFactoryTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<RoleManager<IdmtRole>> _roleManagerMock;
    private readonly Mock<IOptions<IdentityOptions>> _identityOptionsMock;
    private readonly Mock<IMultiTenantContextAccessor> _multiTenantContextAccessorMock;
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
                EmailClaimType = ClaimTypes.Email,
                RoleClaimType = ClaimTypes.Role,
                SecurityStampClaimType = "AspNet.Identity.SecurityStamp",
                UserIdClaimType = ClaimTypes.NameIdentifier,
                UserNameClaimType = ClaimTypes.Name
            }
        };
        _identityOptionsMock.Setup(x => x.Value).Returns(identityOptions);

        _multiTenantContextAccessorMock = new Mock<IMultiTenantContextAccessor>();

        _idmtOptionsMock = new Mock<IOptions<IdmtOptions>>();
        _idmtOptionsMock.Setup(x => x.Value).Returns(IdmtOptions.Default);

        _factory = new IdmtUserClaimsPrincipalFactory(
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _identityOptionsMock.Object,
            _multiTenantContextAccessorMock.Object,
            _idmtOptionsMock.Object,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<IdmtUserClaimsPrincipalFactory>.Instance);
    }

    private void SetAmbientTenant(string tenantId, string tenantIdentifier, string name = "Test Tenant")
    {
        var tenant = new IdmtTenantInfo(tenantId, tenantIdentifier, name);
        var context = new MultiTenantContext<IdmtTenantInfo>(tenant);
        _multiTenantContextAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(context);
    }

    private void SetAmbientTenantNull()
    {
        _multiTenantContextAccessorMock.SetupGet(x => x.MultiTenantContext)
            .Returns((IMultiTenantContext)null!);
    }

    private async Task<ClaimsIdentity> CallGenerateClaimsAsync(IdmtUser user)
    {
        var method = typeof(IdmtUserClaimsPrincipalFactory)
            .GetMethod("GenerateClaimsAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("GenerateClaimsAsync method not found.");
        try
        {
            return (ClaimsIdentity)await (dynamic)method.Invoke(_factory, new object[] { user })!;
        }
        catch (System.Reflection.TargetInvocationException tie) when (tie.InnerException is not null)
        {
            // Re-throw inner so xUnit can match against the original exception type.
            throw tie.InnerException;
        }
    }

    private static IdmtUser BuildUser(SysRoleKind sysRole = SysRoleKind.None) => new()
    {
        Id = Guid.NewGuid(),
        UserName = "testuser",
        NormalizedUserName = "TESTUSER",
        Email = "test@example.com",
        NormalizedEmail = "TEST@EXAMPLE.COM",
        EmailConfirmed = true,
        IsActive = true,
        SysRole = sysRole,
        SecurityStamp = Guid.NewGuid().ToString(),
        ConcurrencyStamp = Guid.NewGuid().ToString()
    };

    [Fact]
    public async Task GenerateClaims_WithAmbientTenant_EmitsTenantClaimFromAmbient()
    {
        SetAmbientTenant("tenant-id-123", "tenant-123");
        var user = BuildUser();

        var identity = await CallGenerateClaimsAsync(user);

        var tenantClaim = identity.FindFirst(IdmtMultiTenantStrategy.DefaultClaim);
        Assert.NotNull(tenantClaim);
        Assert.Equal("tenant-123", tenantClaim.Value);
    }

    [Fact]
    public async Task GenerateClaims_EmitsIsActiveClaim_WithCorrectValue()
    {
        SetAmbientTenant("tenant-id-123", "tenant-123");
        var user = BuildUser();

        var identity = await CallGenerateClaimsAsync(user);

        var isActiveClaim = identity.FindFirst("is_active");
        Assert.NotNull(isActiveClaim);
        Assert.Equal("True", isActiveClaim.Value);
    }

    [Fact]
    public async Task GenerateClaims_EmitsIsActiveClaim_WhenUserIsInactive()
    {
        SetAmbientTenant("tenant-id-123", "tenant-123");
        var user = BuildUser();
        user.IsActive = false;

        var identity = await CallGenerateClaimsAsync(user);

        var isActiveClaim = identity.FindFirst("is_active");
        Assert.NotNull(isActiveClaim);
        Assert.Equal("False", isActiveClaim.Value);
    }

    [Fact]
    public async Task GenerateClaims_WithCustomClaimType_EmitsTenantClaimUnderCustomKey()
    {
        const string customClaimType = "custom_tenant_claim";
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

        var customAccessor = new Mock<IMultiTenantContextAccessor>();
        var tenant = new IdmtTenantInfo("tenant-id-789", "tenant-789", "Custom Tenant");
        customAccessor.SetupGet(x => x.MultiTenantContext)
            .Returns(new MultiTenantContext<IdmtTenantInfo>(tenant));

        var customFactory = new IdmtUserClaimsPrincipalFactory(
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _identityOptionsMock.Object,
            customAccessor.Object,
            customOptionsMock.Object,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<IdmtUserClaimsPrincipalFactory>.Instance);

        var user = BuildUser();
        var method = typeof(IdmtUserClaimsPrincipalFactory)
            .GetMethod("GenerateClaimsAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var identity = (ClaimsIdentity)await (dynamic)method!.Invoke(customFactory, new object[] { user })!;

        var tenantClaim = identity.FindFirst(customClaimType);
        Assert.NotNull(tenantClaim);
        Assert.Equal("tenant-789", tenantClaim.Value);

        // Default claim type must NOT be emitted when custom is configured.
        var defaultTenantClaim = identity.FindFirst(IdmtMultiTenantStrategy.DefaultClaim);
        Assert.Null(defaultTenantClaim);
    }

    [Fact]
    public async Task GenerateClaims_IncludesBaseClaims()
    {
        SetAmbientTenant("tenant-id-123", "tenant-123");
        var user = BuildUser();

        var identity = await CallGenerateClaimsAsync(user);

        var nameIdentifierClaim = identity.FindFirst(ClaimTypes.NameIdentifier);
        Assert.NotNull(nameIdentifierClaim);
        Assert.Equal(user.Id.ToString(), nameIdentifierClaim.Value);

        var nameClaim = identity.FindFirst(ClaimTypes.Name);
        Assert.NotNull(nameClaim);
        Assert.Equal(user.UserName, nameClaim.Value);
    }

    [Fact]
    public async Task GenerateClaims_WithSysRoleSysAdmin_EmitsRoleClaim()
    {
        SetAmbientTenant("tenant-id-123", "tenant-123");
        var user = BuildUser(SysRoleKind.SysAdmin);

        var identity = await CallGenerateClaimsAsync(user);

        var roleClaims = identity.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        Assert.Contains("SysAdmin", roleClaims);
    }

    [Fact]
    public async Task GenerateClaims_WithSysRoleSysSupport_EmitsRoleClaim()
    {
        SetAmbientTenant("tenant-id-123", "tenant-123");
        var user = BuildUser(SysRoleKind.SysSupport);

        var identity = await CallGenerateClaimsAsync(user);

        var roleClaims = identity.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        Assert.Contains("SysSupport", roleClaims);
    }

    [Fact]
    public async Task GenerateClaims_WithSysRoleNone_DoesNotEmitSysRoleClaim()
    {
        SetAmbientTenant("tenant-id-123", "tenant-123");
        var user = BuildUser();

        var identity = await CallGenerateClaimsAsync(user);

        var roleClaims = identity.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        Assert.DoesNotContain("SysAdmin", roleClaims);
        Assert.DoesNotContain("SysSupport", roleClaims);
        Assert.DoesNotContain("None", roleClaims);
    }

    [Fact]
    public async Task GenerateClaims_WithNullAmbientTenant_ThrowsInvalidOperationException()
    {
        SetAmbientTenantNull();
        var user = BuildUser();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CallGenerateClaimsAsync(user));
        Assert.Contains("ambient tenant context", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
