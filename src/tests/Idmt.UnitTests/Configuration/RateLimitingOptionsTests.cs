using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features;

namespace Idmt.UnitTests.Configuration;

public class RateLimitingOptionsTests
{
    // ------------------------------------------------------------------
    // Default values
    // ------------------------------------------------------------------

    [Fact]
    public void Enabled_DefaultsToTrue()
    {
        var options = new RateLimitingOptions();
        Assert.True(options.Enabled);
    }

    [Fact]
    public void PermitLimit_DefaultsToTen()
    {
        var options = new RateLimitingOptions();
        Assert.Equal(10, options.PermitLimit);
    }

    [Fact]
    public void WindowInSeconds_DefaultsToSixty()
    {
        var options = new RateLimitingOptions();
        Assert.Equal(60, options.WindowInSeconds);
    }

    // ------------------------------------------------------------------
    // IdmtOptions integration
    // ------------------------------------------------------------------

    [Fact]
    public void IdmtOptions_ExposesRateLimitingProperty_WithDefaults()
    {
        var idmtOptions = new IdmtOptions();

        Assert.NotNull(idmtOptions.RateLimiting);
        Assert.True(idmtOptions.RateLimiting.Enabled);
        Assert.Equal(10, idmtOptions.RateLimiting.PermitLimit);
        Assert.Equal(60, idmtOptions.RateLimiting.WindowInSeconds);
    }

    [Fact]
    public void IdmtOptions_Default_HasRateLimitingEnabled()
    {
        var defaults = IdmtOptions.Default;

        Assert.NotNull(defaults.RateLimiting);
        Assert.True(defaults.RateLimiting.Enabled);
    }

    // ------------------------------------------------------------------
    // Custom values round-trip
    // ------------------------------------------------------------------

    [Fact]
    public void RateLimitingOptions_CanBeDisabled()
    {
        var options = new RateLimitingOptions { Enabled = false };
        Assert.False(options.Enabled);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(100)]
    public void RateLimitingOptions_AcceptsCustomPermitLimit(int permitLimit)
    {
        var options = new RateLimitingOptions { PermitLimit = permitLimit };
        Assert.Equal(permitLimit, options.PermitLimit);
    }

    [Theory]
    [InlineData(10)]
    [InlineData(30)]
    [InlineData(300)]
    public void RateLimitingOptions_AcceptsCustomWindowInSeconds(int window)
    {
        var options = new RateLimitingOptions { WindowInSeconds = window };
        Assert.Equal(window, options.WindowInSeconds);
    }

    // ------------------------------------------------------------------
    // AuthEndpoints policy name constant
    // ------------------------------------------------------------------

    [Fact]
    public void AuthEndpoints_AuthRateLimiterPolicy_IsIdmtAuth()
    {
        // The policy name must match the name registered in AddRateLimiter so that
        // RequireRateLimiting wires up to the correct limiter at runtime.
        Assert.Equal("idmt-auth", AuthEndpoints.AuthRateLimiterPolicy);
    }
}
