using ErrorOr;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Models;
using Idmt.Plugin.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace Idmt.UnitTests.Features.Manage;

public class UnregisterHandlerTests
{
    private readonly Mock<UserManager<IdmtUser>> _userManagerMock;
    private readonly Mock<ICurrentUserService> _currentUserServiceMock;
    private readonly Mock<ITenantAccessService> _tenantAccessServiceMock;
    private readonly UnregisterUser.UnregisterUserHandler _handler;

    public UnregisterHandlerTests()
    {
        var userStoreMock = new Mock<IUserStore<IdmtUser>>();
        _userManagerMock = new Mock<UserManager<IdmtUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        _currentUserServiceMock = new Mock<ICurrentUserService>();
        _tenantAccessServiceMock = new Mock<ITenantAccessService>();

        _handler = new UnregisterUser.UnregisterUserHandler(
            _currentUserServiceMock.Object,
            NullLogger<UnregisterUser.UnregisterUserHandler>.Instance,
            _userManagerMock.Object,
            _tenantAccessServiceMock.Object);
    }

    [Fact]
    public async Task ReturnsNotFound_WhenUserDoesNotExist()
    {
        // Arrange
        var userId = Guid.NewGuid();
        SetupUsersQueryable([]);

        // Act
        var result = await _handler.HandleAsync(userId);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.NotFound", result.FirstError.Code);
        Assert.Equal(ErrorType.NotFound, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsForbidden_WhenCallerCannotManageTargetUser()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var user = new IdmtUser
        {
            Id = userId,
            UserName = "target@test.com",
            Email = "target@test.com",
            TenantId = "tenant-1"
        };
        SetupUsersQueryable([user]);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["SysAdmin"]);
        _tenantAccessServiceMock.Setup(x => x.CanManageUser(It.IsAny<IEnumerable<string>>())).Returns(false);

        // Act
        var result = await _handler.HandleAsync(userId);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.InsufficientPermissions", result.FirstError.Code);
        Assert.Equal(ErrorType.Forbidden, result.FirstError.Type);
    }

    [Fact]
    public async Task ReturnsDeletionFailed_WhenDeleteFails()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var user = new IdmtUser
        {
            Id = userId,
            UserName = "target@test.com",
            Email = "target@test.com",
            TenantId = "tenant-1"
        };
        SetupUsersQueryable([user]);
        _userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(["TenantAdmin"]);
        _tenantAccessServiceMock.Setup(x => x.CanManageUser(It.IsAny<IEnumerable<string>>())).Returns(true);
        _userManagerMock.Setup(x => x.DeleteAsync(user))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Delete failed" }));

        // Act
        var result = await _handler.HandleAsync(userId);

        // Assert
        Assert.True(result.IsError);
        Assert.Equal("User.DeletionFailed", result.FirstError.Code);
    }

    private void SetupUsersQueryable(List<IdmtUser> users)
    {
        var queryable = users.AsQueryable();
        var mockDbSet = new Mock<IQueryable<IdmtUser>>();
        mockDbSet.As<IAsyncEnumerable<IdmtUser>>()
            .Setup(m => m.GetAsyncEnumerator(It.IsAny<CancellationToken>()))
            .Returns(new TestAsyncEnumerator<IdmtUser>(queryable.GetEnumerator()));
        mockDbSet.As<IQueryable<IdmtUser>>().Setup(m => m.Provider)
            .Returns(new TestAsyncQueryProvider<IdmtUser>(queryable.Provider));
        mockDbSet.As<IQueryable<IdmtUser>>().Setup(m => m.Expression).Returns(queryable.Expression);
        mockDbSet.As<IQueryable<IdmtUser>>().Setup(m => m.ElementType).Returns(queryable.ElementType);
        mockDbSet.As<IQueryable<IdmtUser>>().Setup(m => m.GetEnumerator()).Returns(queryable.GetEnumerator());

        _userManagerMock.SetupGet(x => x.Users).Returns(mockDbSet.Object);
    }
}

/// <summary>
/// Test async query provider for mocking EF Core async operations.
/// </summary>
internal class TestAsyncQueryProvider<TEntity> : IAsyncQueryProvider
{
    private readonly IQueryProvider _inner;

    internal TestAsyncQueryProvider(IQueryProvider inner) => _inner = inner;

    public IQueryable CreateQuery(System.Linq.Expressions.Expression expression) => new TestAsyncEnumerable<TEntity>(expression);
    public IQueryable<TElement> CreateQuery<TElement>(System.Linq.Expressions.Expression expression) => new TestAsyncEnumerable<TElement>(expression);
    public object? Execute(System.Linq.Expressions.Expression expression) => _inner.Execute(expression);
    public TResult Execute<TResult>(System.Linq.Expressions.Expression expression) => _inner.Execute<TResult>(expression);
    public TResult ExecuteAsync<TResult>(System.Linq.Expressions.Expression expression, CancellationToken cancellationToken = default)
    {
        var expectedResultType = typeof(TResult).GetGenericArguments()[0];
        var executionResult = typeof(IQueryProvider)
            .GetMethod(nameof(IQueryProvider.Execute), 1, [typeof(System.Linq.Expressions.Expression)])!
            .MakeGenericMethod(expectedResultType)
            .Invoke(_inner, [expression]);

        return (TResult)typeof(Task).GetMethod(nameof(Task.FromResult))!
            .MakeGenericMethod(expectedResultType)
            .Invoke(null, [executionResult])!;
    }
}

internal class TestAsyncEnumerable<T> : EnumerableQuery<T>, IAsyncEnumerable<T>, IQueryable<T>
{
    public TestAsyncEnumerable(System.Linq.Expressions.Expression expression) : base(expression) { }

    public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
        => new TestAsyncEnumerator<T>(this.AsEnumerable().GetEnumerator());

    IQueryProvider IQueryable.Provider => new TestAsyncQueryProvider<T>(this);
}

internal class TestAsyncEnumerator<T> : IAsyncEnumerator<T>
{
    private readonly IEnumerator<T> _inner;

    public TestAsyncEnumerator(IEnumerator<T> inner) => _inner = inner;

    public T Current => _inner.Current;

    public ValueTask DisposeAsync()
    {
        _inner.Dispose();
        return ValueTask.CompletedTask;
    }

    public ValueTask<bool> MoveNextAsync() => new(_inner.MoveNext());
}
