using Idmt.Plugin.Models;

namespace Idmt.UnitTests.Models;

public class IdmtTenantInfoTests
{
    [Fact]
    public void ThrowsArgumentException_WhenIdentifierIsTooShort()
    {
        // Arrange & Act & Assert
        var ex = Assert.Throws<ArgumentException>(
            () => new IdmtTenantInfo("some-id", "ab", "Test Tenant"));

        Assert.Equal("identifier", ex.ParamName);
        Assert.Contains("at least 3 characters", ex.Message);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("xy")]
    public void ThrowsArgumentException_WhenIdentifierLengthIsLessThanThree(string shortIdentifier)
    {
        Assert.Throws<ArgumentException>(
            () => new IdmtTenantInfo("some-id", shortIdentifier, "Test Tenant"));
    }

    [Theory]
    [InlineData(null, "valid-id", "Valid Name")]   // null id
    [InlineData("", "valid-id", "Valid Name")]     // empty id
    [InlineData("some-id", null, "Valid Name")]    // null identifier
    [InlineData("some-id", "", "Valid Name")]      // empty identifier
    [InlineData("some-id", "valid-id", null)]      // null name
    [InlineData("some-id", "valid-id", "")]        // empty name
    public void ThrowsArgumentException_ForNullOrEmptyRequiredFields(
        string? id, string? identifier, string? name)
    {
        Assert.ThrowsAny<ArgumentException>(
            () => new IdmtTenantInfo(id!, identifier!, name!));
    }

    [Fact]
    public void CreatesSuccessfully_WithValidParameters()
    {
        // Arrange & Act
        var tenant = new IdmtTenantInfo("tenant-id-1", "my-tenant", "My Tenant");

        // Assert
        Assert.Equal("tenant-id-1", tenant.Id);
        Assert.Equal("my-tenant", tenant.Identifier);
        Assert.Equal("My Tenant", tenant.Name);
        Assert.True(tenant.IsActive);
        Assert.Equal("/login", tenant.LoginPath);
        Assert.Equal("/logout", tenant.LogoutPath);
        Assert.Equal("/access-denied", tenant.AccessDeniedPath);
    }

    [Fact]
    public void CreatesSuccessfully_WithTwoParameterConstructor()
    {
        // Arrange & Act
        var tenant = new IdmtTenantInfo("my-tenant", "My Tenant");

        // Assert
        Assert.NotNull(tenant.Id);
        Assert.NotEmpty(tenant.Id);
        Assert.Equal("my-tenant", tenant.Identifier);
        Assert.Equal("My Tenant", tenant.Name);
    }

    [Fact]
    public void GetId_ReturnsId()
    {
        var tenant = new IdmtTenantInfo("tenant-id", "identifier", "name");
        Assert.Equal("tenant-id", tenant.GetId());
    }

    [Fact]
    public void GetName_ReturnsName()
    {
        var tenant = new IdmtTenantInfo("tenant-id", "identifier", "My Name");
        Assert.Equal("My Name", tenant.GetName());
    }

    [Fact]
    public void GetTenantId_ReturnsId()
    {
        var tenant = new IdmtTenantInfo("tenant-id", "identifier", "name");
        Assert.Equal("tenant-id", tenant.GetTenantId());
    }
}
