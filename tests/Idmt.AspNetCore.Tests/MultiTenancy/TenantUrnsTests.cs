using Idmt.AspNetCore.MultiTenancy;

namespace Idmt.AspNetCore.Tests.MultiTenancy;

public sealed class TenantUrnsTests
{
    [Fact]
    public void For_PrependsPrefix()
    {
        Assert.Equal("urn:idmt:tenant:acme", TenantUrns.For("acme"));
    }

    [Fact]
    public void IdentifierFrom_RoundTrips()
    {
        Assert.Equal("acme", TenantUrns.IdentifierFrom(TenantUrns.For("acme")));
    }

    [Theory]
    [InlineData("acme")]
    [InlineData("urn:other:acme")]
    [InlineData("")]
    public void IdentifierFrom_ReturnsNull_ForNonPrefixedValue(string value)
    {
        // A malformed or unrelated audience must never silently parse as a tenant.
        Assert.Null(TenantUrns.IdentifierFrom(value));
    }
}
