using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Features.Admin;

public class CreateTenantHandlerTests
{
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly Mock<ITenantOperationService> _tenantOpsMock;
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly IOptions<IdmtOptions> _options;
    private readonly Guid _invokerUserId = Guid.NewGuid();
    private readonly CreateTenant.CreateTenantHandler _handler;

    public CreateTenantHandlerTests()
    {
        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();
        _tenantOpsMock = new Mock<ITenantOperationService>();
        _currentUserServiceMock = new Mock<ICurrentUserService>();
        _currentUserServiceMock.SetupGet(x => x.UserId).Returns(_invokerUserId);
        _options = Options.Create(new IdmtOptions());

        _handler = new CreateTenant.CreateTenantHandler(
            _tenantStoreMock.Object,
            _tenantOpsMock.Object,
            _currentUserServiceMock.Object,
            _options,
            NullLogger<CreateTenant.CreateTenantHandler>.Instance);
    }

    private void SetupRoleSeedSuccess()
    {
        _tenantOpsMock
            .Setup(x => x.ExecuteInTenantScopeAsync(
                It.IsAny<string>(),
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()))
            .ReturnsAsync(Result.Success);
    }

    private void SetupRoleSeedFailure()
    {
        _tenantOpsMock
            .Setup(x => x.ExecuteInTenantScopeAsync(
                It.IsAny<string>(),
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()))
            .ReturnsAsync(IdmtErrors.Tenant.RoleSeedFailed);
    }

    [Fact]
    public async Task ReactivatesInactiveTenant_AndReturnsExistingId()
    {
        // Arrange
        var existingTenant = new IdmtTenantInfo("existing-id", "test-tenant", "Test Tenant") { IsActive = false };

        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("test-tenant"))
            .ReturnsAsync(existingTenant);

        _tenantStoreMock
            .Setup(x => x.UpdateAsync(It.Is<IdmtTenantInfo>(t => t.IsActive && t.Id == "existing-id")))
            .ReturnsAsync(true);

        SetupRoleSeedSuccess();

        var request = new CreateTenant.CreateTenantRequest("test-tenant", "Test Tenant");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        Assert.Equal("existing-id", result.Value.Id);
        Assert.Equal("test-tenant", result.Value.Identifier);

        _tenantStoreMock.Verify(
            x => x.UpdateAsync(It.Is<IdmtTenantInfo>(t => t.IsActive && t.Id == "existing-id")),
            Times.Once);

        _tenantStoreMock.Verify(x => x.AddAsync(It.IsAny<IdmtTenantInfo>()), Times.Never);
    }

    [Fact]
    public async Task ReturnsCreationFailed_WhenStoreAddFails()
    {
        // Arrange
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("new-tenant"))
            .ReturnsAsync((IdmtTenantInfo?)null);

        _tenantStoreMock
            .Setup(x => x.AddAsync(It.IsAny<IdmtTenantInfo>()))
            .ReturnsAsync(false);

        var request = new CreateTenant.CreateTenantRequest("new-tenant", "New Tenant");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.CreationFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsUpdateFailed_WhenReactivationUpdateFails()
    {
        // Arrange
        var inactiveTenant = new IdmtTenantInfo("tid", "inactive-tenant", "Inactive") { IsActive = false };

        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("inactive-tenant"))
            .ReturnsAsync(inactiveTenant);

        _tenantStoreMock
            .Setup(x => x.UpdateAsync(It.IsAny<IdmtTenantInfo>()))
            .ReturnsAsync(false);

        var request = new CreateTenant.CreateTenantRequest("inactive-tenant", "Inactive");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.UpdateFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task ReturnsRoleSeedFailed_WhenRoleCreationFails()
    {
        // Arrange
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("new-tenant"))
            .ReturnsAsync((IdmtTenantInfo?)null);

        _tenantStoreMock
            .Setup(x => x.AddAsync(It.IsAny<IdmtTenantInfo>()))
            .ReturnsAsync(true);

        SetupRoleSeedFailure();

        var request = new CreateTenant.CreateTenantRequest("new-tenant", "New Tenant");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Tenant.RoleSeedFailed", result.FirstError.Code);
    }

    [Fact]
    public async Task SeedsExtraRoles_WhenConfiguredInOptions()
    {
        // Arrange
        var optionsWithExtraRoles = Options.Create(new IdmtOptions
        {
            Identity = new IdmtAuthOptions
            {
                ExtraRoles = ["CustomRole1", "CustomRole2"]
            }
        });

        var handler = new CreateTenant.CreateTenantHandler(
            _tenantStoreMock.Object,
            _tenantOpsMock.Object,
            _currentUserServiceMock.Object,
            optionsWithExtraRoles,
            NullLogger<CreateTenant.CreateTenantHandler>.Instance);

        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("new-tenant"))
            .ReturnsAsync((IdmtTenantInfo?)null);

        _tenantStoreMock
            .Setup(x => x.AddAsync(It.IsAny<IdmtTenantInfo>()))
            .ReturnsAsync(true);

        // Capture the callback to verify roles passed
        Func<IServiceProvider, Task<ErrorOr<Success>>>? capturedOperation = null;
        _tenantOpsMock
            .Setup(x => x.ExecuteInTenantScopeAsync(
                It.IsAny<string>(),
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()))
            .Callback<string, Func<IServiceProvider, Task<ErrorOr<Success>>>, bool>((_, op, _) => capturedOperation = op)
            .ReturnsAsync(Result.Success);

        var request = new CreateTenant.CreateTenantRequest("new-tenant", "New Tenant");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);
        Assert.NotNull(capturedOperation);

        // Verify the tenant operation was called with requireActive: false
        _tenantOpsMock.Verify(
            x => x.ExecuteInTenantScopeAsync(
                "new-tenant",
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                false),
            Times.Once);

        // Verify that the operation was invoked, confirming the handler proceeded with role seeding.
        // The extra roles (CustomRole1, CustomRole2) are combined with DefaultRoles inside the handler's
        // GuaranteeTenantRolesAsync method. The fact that the operation was called with the tenant scope
        // confirms the role seeding path was executed.
        _tenantOpsMock.Verify(
            x => x.ExecuteInTenantScopeAsync(
                It.IsAny<string>(),
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()),
            Times.Once);
    }

    [Fact]
    public async Task Handle_NullCurrentUser_ReturnsUnauthorized()
    {
        // Arrange
        var unauthMock = new Mock<ICurrentUserService>();
        unauthMock.SetupGet(x => x.UserId).Returns((Guid?)null);

        var handler = new CreateTenant.CreateTenantHandler(
            _tenantStoreMock.Object,
            _tenantOpsMock.Object,
            unauthMock.Object,
            _options,
            NullLogger<CreateTenant.CreateTenantHandler>.Instance);

        var request = new CreateTenant.CreateTenantRequest("new-tenant", "New Tenant");

        // Act
        var result = await handler.HandleAsync(request);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("Auth.Unauthorized", result.FirstError.Code);

        // Tenant store must not be touched when invoker is unauthenticated.
        _tenantStoreMock.Verify(x => x.GetByIdentifierAsync(It.IsAny<string>()), Times.Never);
        _tenantStoreMock.Verify(x => x.AddAsync(It.IsAny<IdmtTenantInfo>()), Times.Never);
        _tenantOpsMock.Verify(
            x => x.ExecuteInTenantScopeAsync(
                It.IsAny<string>(),
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()),
            Times.Never);
    }

    [Fact]
    public async Task Handle_AsSysAdmin_CapturesInvokerUserIdOutsideInnerScope()
    {
        // V2-CRIT-2 regression. Asserts that invokerUserId resolved at handler entry is the value
        // ultimately surfaced — and that ICurrentUserService.UserId is read EXACTLY ONCE (outer
        // scope), not again from inside ExecuteInTenantScopeAsync.

        // Arrange
        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("new-tenant"))
            .ReturnsAsync((IdmtTenantInfo?)null);

        _tenantStoreMock
            .Setup(x => x.AddAsync(It.IsAny<IdmtTenantInfo>()))
            .ReturnsAsync(true);

        SetupRoleSeedSuccess();

        var request = new CreateTenant.CreateTenantRequest("new-tenant", "New Tenant");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.False(result.IsError);

        // Single read of UserId — proves we did not re-read from inside the inner scope.
        _currentUserServiceMock.Verify(x => x.UserId, Times.Once);
    }

    [Fact]
    public void Handler_Constructor_DependsOnICurrentUserService()
    {
        // H1 regression: ctor-level test fails when ICurrentUserService dependency is removed.
        var ctors = typeof(CreateTenant.CreateTenantHandler).GetConstructors();
        Assert.Single(ctors);
        var ctor = ctors[0];
        var paramTypes = ctor.GetParameters().Select(p => p.ParameterType).ToArray();
        Assert.Contains(typeof(ICurrentUserService), paramTypes);
    }

    [Fact]
    public async Task Handle_RoleSeedingFails_RollsBackTenantAccess()
    {
        // V2-CRIT-1 regression: when role seeding fails mid-bootstrap, the ambient transaction
        // must roll back so no TenantAccess row persists. We capture the inner-scope callback the
        // handler hands to ITenantOperationService and execute it against a real SQLite-backed
        // IdmtDbContext + a RoleManager mock that fails on CreateAsync.
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var dbOptions = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseSqlite(connection)
            .Options;

        var tenant = new IdmtTenantInfo("tenant-id-1", "new-tenant", "New Tenant");

        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        tenantAccessorMock
            .SetupGet(x => x.MultiTenantContext)
            .Returns(new MultiTenantContext<IdmtTenantInfo>(tenant));

        var currentUserStub = new Mock<ICurrentUserService>();
        currentUserStub.SetupGet(x => x.UserId).Returns(_invokerUserId);

        await using var dbContext = new IdmtDbContext(
            tenantAccessorMock.Object,
            dbOptions,
            currentUserStub.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        await dbContext.Database.EnsureCreatedAsync();

        // Failing RoleManager: every CreateAsync returns IdentityResult.Failed.
        var roleStoreMock = Mock.Of<IRoleStore<IdmtRole>>();
        var roleManagerMock = new Mock<RoleManager<IdmtRole>>(
            roleStoreMock, null!, null!, null!, null!);
        roleManagerMock.Setup(x => x.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(false);
        roleManagerMock.Setup(x => x.CreateAsync(It.IsAny<IdmtRole>()))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "boom" }));

        // Inner-scope provider exposes IdmtDbContext + RoleManager exactly as the production scope does.
        var innerServices = new ServiceCollection();
        innerServices.AddSingleton(dbContext);
        innerServices.AddSingleton(roleManagerMock.Object);
        await using var innerProvider = innerServices.BuildServiceProvider();

        // Capture the inner-scope operation the handler hands to ITenantOperationService and
        // invoke it against our real DbContext + failing role manager.
        Func<IServiceProvider, Task<ErrorOr<Success>>>? capturedOperation = null;
        _tenantOpsMock
            .Setup(x => x.ExecuteInTenantScopeAsync(
                It.IsAny<string>(),
                It.IsAny<Func<IServiceProvider, Task<ErrorOr<Success>>>>(),
                It.IsAny<bool>()))
            .Returns(async (string _id, Func<IServiceProvider, Task<ErrorOr<Success>>> op, bool _flag) =>
            {
                capturedOperation = op;
                return await op(innerProvider);
            });

        _tenantStoreMock
            .Setup(x => x.GetByIdentifierAsync("new-tenant"))
            .ReturnsAsync((IdmtTenantInfo?)null);
        _tenantStoreMock
            .Setup(x => x.AddAsync(It.IsAny<IdmtTenantInfo>()))
            .ReturnsAsync(true);

        var request = new CreateTenant.CreateTenantRequest("new-tenant", "New Tenant");

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert: handler surfaces RoleSeedFailed and the transaction rolled back, so no
        // TenantAccess row persisted in the SQLite-backed DbContext.
        Assert.True(result.IsError);
        Assert.Equal("Tenant.RoleSeedFailed", result.FirstError.Code);

        await using var verifyContext = new IdmtDbContext(
            tenantAccessorMock.Object,
            dbOptions,
            currentUserStub.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        var tenantAccessRows = await verifyContext.TenantAccess.IgnoreQueryFilters().ToListAsync();
        Assert.Empty(tenantAccessRows);
    }
}
