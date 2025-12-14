using System.Collections.Generic;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Validation;
using Xunit;

namespace Idmt.UnitTests.Validation;

public class ValidatorsTests
{
    [Theory]
    [InlineData("test@example.com", true)]
    [InlineData("user.name+tag@example.co.uk", true)]
    [InlineData("invalid-email", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("test@example", true)] // EmailAddressAttribute might be lenient
    public void IsValidEmail_ValidatesCorrectly(string? email, bool expected)
    {
        var result = Validators.IsValidEmail(email);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void IsValidNewPassword_ReturnsFalse_WhenPasswordIsEmpty()
    {
        var options = new PasswordOptions();
        var result = Validators.IsValidNewPassword("", options, out var errors);

        Assert.False(result);
        Assert.NotNull(errors);
        Assert.Contains("Password is required", errors);
    }

    [Fact]
    public void IsValidNewPassword_ValidatesLength()
    {
        var options = new PasswordOptions { RequiredLength = 8 };
        var result = Validators.IsValidNewPassword("short", options, out var errors);

        Assert.False(result);
        Assert.NotNull(errors);
        Assert.Contains("Password must be at least 8 characters long.", errors);
    }

    [Fact]
    public void IsValidNewPassword_ValidatesDigit()
    {
        var options = new PasswordOptions { RequireDigit = true };
        var result = Validators.IsValidNewPassword("NoDigit", options, out var errors);

        Assert.False(result);
        Assert.NotNull(errors);
        Assert.Contains("Password must contain at least one digit.", errors);
    }

    [Fact]
    public void IsValidNewPassword_ValidatesLowercase()
    {
        var options = new PasswordOptions { RequireLowercase = true };
        var result = Validators.IsValidNewPassword("NOLOWERCASE1", options, out var errors);

        Assert.False(result);
        Assert.NotNull(errors);
        Assert.Contains("Password must contain at least one lowercase letter.", errors);
    }

    [Fact]
    public void IsValidNewPassword_ValidatesUppercase()
    {
        var options = new PasswordOptions { RequireUppercase = true };
        var result = Validators.IsValidNewPassword("nouppercase1", options, out var errors);

        Assert.False(result);
        Assert.NotNull(errors);
        Assert.Contains("Password must contain at least one uppercase letter.", errors);
    }

    [Fact]
    public void IsValidNewPassword_ValidatesNonAlphanumeric()
    {
        var options = new PasswordOptions { RequireNonAlphanumeric = true };
        var result = Validators.IsValidNewPassword("NoSpecialChar1", options, out var errors);

        Assert.False(result);
        Assert.NotNull(errors);
        Assert.Contains("Password must contain at least one non-alphanumeric character.", errors);
    }

    [Fact]
    public void IsValidNewPassword_ValidatesUniqueChars()
    {
        var options = new PasswordOptions { RequiredUniqueChars = 4 };
        var result = Validators.IsValidNewPassword("aaaa1", options, out var errors);

        Assert.False(result);
        Assert.NotNull(errors);
        Assert.Contains("Password must contain at least 4 unique characters.", errors);
    }

    [Fact]
    public void IsValidNewPassword_ReturnsTrue_WhenAllRequirementsMet()
    {
        var options = new PasswordOptions
        {
            RequiredLength = 6,
            RequireDigit = true,
            RequireLowercase = true,
            RequireUppercase = true,
            RequireNonAlphanumeric = true,
            RequiredUniqueChars = 1
        };

        var result = Validators.IsValidNewPassword("Pass1!", options, out var errors);

        Assert.True(result);
        Assert.Null(errors);
    }

    [Theory]
    [InlineData("d81e3678-00a8-444f-a715-171804791e84", true)]
    [InlineData("invalid-guid", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsValidGuid_ValidatesCorrectly(string? guid, bool expected)
    {
        var result = Validators.IsValidGuid(guid);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("tenant1", true)]
    [InlineData("te", false)] // Length < 3
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsValidTenantId_ValidatesCorrectly(string? tenantId, bool expected)
    {
        var result = Validators.IsValidTenantId(tenantId);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("user1", true)]
    [InlineData("us", false)] // Length < 3
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsValidEmailOrUsername_ValidatesCorrectly(string? input, bool expected)
    {
        var result = Validators.IsValidEmailOrUsername(input);
        Assert.Equal(expected, result);
    }
}
