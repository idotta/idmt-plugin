using Idmt.Spike.Host.Wiring;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;

namespace Idmt.Spike.Tests;

/// <summary>
/// Gate 5: the two-layer §2.9 seam. Layer 1 — a last-wins post-configuration —
/// re-clamps a locked option a consumer subtracted before it. Layer 2 — a startup
/// self-check — fails host start when a consumer subtracts a locked option after
/// the lock (the position a raw consumer PostConfigure lands).
/// </summary>
public sealed class Gate5_SelfCheckTests(WebApplicationFactory<Program> factory)
    : BaseSpikeIntegrationTest(factory)
{
    [Fact]
    public void Layer1_LastWinsLock_ReclampsEarlierSubtraction()
    {
        // A hostile subtraction registered BEFORE AddIdmtSpike: the lock runs later
        // and wins, so the final snapshot still has reference tokens enabled.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddDataProtection();
        services.PostConfigure<OpenIddictServerOptions>(o => o.UseReferenceAccessTokens = false);

        services.AddIdmtSpike();

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;

        Assert.True(options.UseReferenceAccessTokens,
            "Layer-1 lock should re-clamp UseReferenceAccessTokens after an earlier subtraction.");
    }

    [Fact]
    public void HealthyHost_Boots()
    {
        // The unmodified host starts and serves (control for the hostile case below).
        using var client = Factory.CreateClient();
        Assert.NotNull(client);
    }

    [Fact]
    public void Layer2_SelfCheck_FailsHostStart_OnLaterSubtraction()
    {
        // A hostile subtraction registered AFTER AddIdmtSpike (the position a raw
        // consumer PostConfigure lands) is past the lock's reach, so the startup
        // self-check must fail host start.
        using var hostile = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.PostConfigure<OpenIddictServerOptions>(o => o.UseReferenceAccessTokens = false)));

        var ex = Assert.ThrowsAny<Exception>(() => hostile.CreateClient());

        var invariant = Unwrap(ex).OfType<IdmtSecurityInvariantException>().FirstOrDefault();
        Assert.NotNull(invariant);
        Assert.Contains("UseReferenceAccessTokens", invariant!.Message, StringComparison.Ordinal);
    }

    private static IEnumerable<Exception> Unwrap(Exception ex)
    {
        for (var current = ex; current is not null; current = current.InnerException)
        {
            yield return current;
        }
    }
}
