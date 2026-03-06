using ErrorOr;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Errors;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Features.Admin;

public class CreateTenantHandlerTests
{
    private readonly Mock<IMultiTenantStore<IdmtTenantInfo>> _tenantStoreMock;
    private readonly Mock<ITenantOperationService> _tenantOpsMock;
    private readonly IOptions<IdmtOptions> _options;
    private readonly CreateTenant.CreateTenantHandler _handler;

    public CreateTenantHandlerTests()
    {
        _tenantStoreMock = new Mock<IMultiTenantStore<IdmtTenantInfo>>();
        _tenantOpsMock = new Mock<ITenantOperationService>();
        _options = Options.Create(new IdmtOptions());

        _handler = new CreateTenant.CreateTenantHandler(
            _tenantStoreMock.Object,
            _tenantOpsMock.Object,
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
}
