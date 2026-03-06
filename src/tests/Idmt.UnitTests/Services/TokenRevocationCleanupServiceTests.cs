using Idmt.Plugin.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Services;

public class TokenRevocationCleanupServiceTests
{
    // A very short interval lets the tests run without real wall-clock waiting.
    private static readonly TimeSpan TestInterval = TimeSpan.FromMilliseconds(50);

    // ---------------------------------------------------------------------------
    // Helper: build the service under test wired to the given scope factory.
    // ---------------------------------------------------------------------------
    private static TokenRevocationCleanupService BuildSut(IServiceScopeFactory scopeFactory) =>
        new(scopeFactory, NullLogger<TokenRevocationCleanupService>.Instance, TestInterval);

    // ---------------------------------------------------------------------------
    // Helper: create a scope factory whose scopes resolve the given revocation mock.
    // ---------------------------------------------------------------------------
    private static IServiceScopeFactory BuildScopeFactory(ITokenRevocationService revocationService)
    {
        var serviceProvider = new Mock<IServiceProvider>();
        serviceProvider
            .Setup(sp => sp.GetService(typeof(ITokenRevocationService)))
            .Returns(revocationService);

        var scope = new Mock<IServiceScope>();
        scope.SetupGet(s => s.ServiceProvider).Returns(serviceProvider.Object);

        var scopeFactory = new Mock<IServiceScopeFactory>();
        scopeFactory.Setup(f => f.CreateScope()).Returns(scope.Object);

        return scopeFactory.Object;
    }

    // ---------------------------------------------------------------------------
    // Test 1: CleanupExpiredAsync is called after the interval elapses.
    // ---------------------------------------------------------------------------
    [Fact]
    public async Task ExecuteAsync_CallsCleanupExpiredAsync_AfterInterval()
    {
        // Arrange
        var revocationMock = new Mock<ITokenRevocationService>();

        // Block after the first cleanup so the loop does not spin again during
        // the assertion window — the second delay will wait on the token.
        var firstCallCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        revocationMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<CancellationToken>()))
            .Callback(() => firstCallCompleted.TrySetResult())
            .Returns(Task.CompletedTask);

        using var cts = new CancellationTokenSource();
        var sut = BuildSut(BuildScopeFactory(revocationMock.Object));

        // Act: start the background service and wait for the first cleanup to fire.
        var backgroundTask = sut.StartAsync(cts.Token);

        var completedInTime = await Task.WhenAny(
            firstCallCompleted.Task,
            Task.Delay(TimeSpan.FromSeconds(5)));

        // Cancel so the service shuts down cleanly.
        await cts.CancelAsync();
        await sut.StopAsync(CancellationToken.None);
        await backgroundTask;

        // Assert
        Assert.True(completedInTime == firstCallCompleted.Task,
            "CleanupExpiredAsync was not called within the timeout.");

        revocationMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
    }

    // ---------------------------------------------------------------------------
    // Test 2: An exception thrown by CleanupExpiredAsync does not crash the loop;
    //         the service continues and calls cleanup again on the next iteration.
    // ---------------------------------------------------------------------------
    [Fact]
    public async Task ExecuteAsync_ContinuesRunning_AfterCleanupThrows()
    {
        // Arrange
        var revocationMock = new Mock<ITokenRevocationService>();
        var secondCallCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var callCount = 0;
        revocationMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                callCount++;
                if (callCount == 1)
                {
                    // First call: simulate a transient database error.
                    throw new InvalidOperationException("Simulated DB failure");
                }

                // Second call: succeed and signal the test.
                secondCallCompleted.TrySetResult();
                return Task.CompletedTask;
            });

        using var cts = new CancellationTokenSource();
        var sut = BuildSut(BuildScopeFactory(revocationMock.Object));

        // Act
        var backgroundTask = sut.StartAsync(cts.Token);

        var completedInTime = await Task.WhenAny(
            secondCallCompleted.Task,
            Task.Delay(TimeSpan.FromSeconds(5)));

        await cts.CancelAsync();
        await sut.StopAsync(CancellationToken.None);
        await backgroundTask;

        // Assert: the service recovered from the exception and ran a second cleanup.
        Assert.True(completedInTime == secondCallCompleted.Task,
            "Service did not recover and call CleanupExpiredAsync a second time after an exception.");

        revocationMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<CancellationToken>()),
            Times.AtLeast(2));
    }

    // ---------------------------------------------------------------------------
    // Test 3: Cancellation during Task.Delay causes a clean shutdown without
    //         calling CleanupExpiredAsync at all.
    // ---------------------------------------------------------------------------
    [Fact]
    public async Task ExecuteAsync_StopsCleanly_WhenCancelledDuringDelay()
    {
        // Arrange: use a very long interval so cancellation fires while waiting.
        var revocationMock = new Mock<ITokenRevocationService>();

        var scopeFactory = BuildScopeFactory(revocationMock.Object);
        var sut = new TokenRevocationCleanupService(
            scopeFactory,
            NullLogger<TokenRevocationCleanupService>.Instance,
            interval: TimeSpan.FromHours(1)); // long interval — cancellation fires first

        using var cts = new CancellationTokenSource();

        // Act
        var backgroundTask = sut.StartAsync(cts.Token);

        // Cancel almost immediately — the service is inside Task.Delay(1h).
        await cts.CancelAsync();
        await sut.StopAsync(CancellationToken.None);
        await backgroundTask;

        // Assert: cleanup was never reached because cancellation fired during the delay.
        revocationMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<CancellationToken>()),
            Times.Never);
    }
}
