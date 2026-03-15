using System.Net;
using System.Security.Claims;
using Idmt.Plugin.Middleware;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Http;
using Moq;

namespace Idmt.UnitTests.Middleware;

public class CurrentUserMiddlewareTests
{
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly CurrentUserMiddleware _middleware;

    public CurrentUserMiddlewareTests()
    {
        _currentUserServiceMock = new Mock<ICurrentUserService>();
        _middleware = new CurrentUserMiddleware(_currentUserServiceMock.Object);
    }

    [Fact]
    public async Task SetsCurrentUser_FromAuthenticatedRequest()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "testuser"), new Claim(ClaimTypes.Email, "test@example.com")],
            "TestScheme");
        context.User = new ClaimsPrincipal(identity);
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
        context.Request.Headers["User-Agent"] = "TestAgent/1.0";

        // Act
        await _middleware.InvokeAsync(context, _ => Task.CompletedTask);

        // Assert
        _currentUserServiceMock.Verify(
            s => s.SetCurrentUser(
                It.Is<ClaimsPrincipal>(u => u.Identity != null && u.Identity.Name == "testuser"),
                "192.168.1.100",
                "TestAgent/1.0"),
            Times.Once);
    }

    [Fact]
    public async Task AlwaysCallsNext_WhenAuthenticated()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "testuser")],
            "TestScheme");
        context.User = new ClaimsPrincipal(identity);
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        var nextCalled = false;

        // Act
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        // Assert
        Assert.True(nextCalled);
    }

    [Fact]
    public async Task AlwaysCallsNext_WhenUnauthenticated()
    {
        // Arrange
        var context = new DefaultHttpContext(); // No user set, defaults to unauthenticated
        var nextCalled = false;

        // Act
        await _middleware.InvokeAsync(context, _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        // Assert
        Assert.True(nextCalled);
        _currentUserServiceMock.Verify(
            s => s.SetCurrentUser(It.IsAny<ClaimsPrincipal>(), It.IsAny<string?>(), It.IsAny<string?>()),
            Times.Once);
    }

    [Fact]
    public async Task PassesNullIp_WhenRemoteIpAddressIsNull()
    {
        // Arrange
        var context = new DefaultHttpContext();
        // RemoteIpAddress is null by default on DefaultHttpContext
        Assert.Null(context.Connection.RemoteIpAddress);
        context.Request.Headers["User-Agent"] = "SomeAgent";

        // Act
        await _middleware.InvokeAsync(context, _ => Task.CompletedTask);

        // Assert - should not throw and should pass null for IP
        _currentUserServiceMock.Verify(
            s => s.SetCurrentUser(
                It.IsAny<ClaimsPrincipal>(),
                null,
                "SomeAgent"),
            Times.Once);
    }
}
