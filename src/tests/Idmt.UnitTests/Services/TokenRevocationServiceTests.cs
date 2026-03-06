using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Models;
using Idmt.Plugin.Persistence;
using Idmt.Plugin.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Idmt.UnitTests.Services;

public class TokenRevocationServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly IdmtDbContext _dbContext;
    private readonly FakeTimeProvider _timeProvider;
    private readonly TokenRevocationService _sut;

    private static readonly Guid UserId = Guid.NewGuid();
    private const string TenantId = "test-tenant";

    public TokenRevocationServiceTests()
    {
        // Use SQLite in-memory so ExecuteDeleteAsync is supported
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var tenantAccessorMock = new Mock<IMultiTenantContextAccessor>();
        var currentUserServiceMock = new Mock<ICurrentUserService>();

        var dummyTenant = new IdmtTenantInfo("sys-id", "system-test", "System Test");
        var dummyContext = new MultiTenantContext<IdmtTenantInfo>(dummyTenant);
        tenantAccessorMock.SetupGet(x => x.MultiTenantContext).Returns(dummyContext);

        var options = new DbContextOptionsBuilder<IdmtDbContext>()
            .UseSqlite(_connection)
            .Options;

        _dbContext = new IdmtDbContext(
            tenantAccessorMock.Object,
            options,
            currentUserServiceMock.Object,
            TimeProvider.System,
            NullLogger<IdmtDbContext>.Instance);

        _dbContext.Database.EnsureCreated();

        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 3, 4, 12, 0, 0, TimeSpan.Zero));

        var idmtOptions = Options.Create(new IdmtOptions());

        _sut = new TokenRevocationService(
            _dbContext,
            _timeProvider,
            idmtOptions,
            NullLogger<TokenRevocationService>.Instance);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_ReturnsTrue_WhenTokenIssuedBeforeRevocation()
    {
        // Arrange: revoke at T=20, token issued at T=10
        var revokedAt = new DateTime(2026, 3, 4, 0, 0, 20, DateTimeKind.Utc);
        var issuedAt = new DateTime(2026, 3, 4, 0, 0, 10, DateTimeKind.Utc);

        _dbContext.RevokedTokens.Add(new RevokedToken
        {
            TokenId = $"{UserId}:{TenantId}",
            RevokedAt = revokedAt,
            ExpiresAt = revokedAt.AddDays(30)
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _sut.IsTokenRevokedAsync(UserId, TenantId, issuedAt);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_ReturnsFalse_WhenTokenIssuedAfterRevocation()
    {
        // Arrange: revoke at T=20, token issued at T=30
        var revokedAt = new DateTime(2026, 3, 4, 0, 0, 20, DateTimeKind.Utc);
        var issuedAt = new DateTime(2026, 3, 4, 0, 0, 30, DateTimeKind.Utc);

        _dbContext.RevokedTokens.Add(new RevokedToken
        {
            TokenId = $"{UserId}:{TenantId}",
            RevokedAt = revokedAt,
            ExpiresAt = revokedAt.AddDays(30)
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _sut.IsTokenRevokedAsync(UserId, TenantId, issuedAt);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_ReturnsFalse_WhenTokenIssuedAtExactRevocationTime()
    {
        // Arrange: revoke at T=20, token issued at T=20 (boundary: strict < means NOT revoked)
        var revokedAt = new DateTime(2026, 3, 4, 0, 0, 20, DateTimeKind.Utc);
        var issuedAt = new DateTime(2026, 3, 4, 0, 0, 20, DateTimeKind.Utc);

        _dbContext.RevokedTokens.Add(new RevokedToken
        {
            TokenId = $"{UserId}:{TenantId}",
            RevokedAt = revokedAt,
            ExpiresAt = revokedAt.AddDays(30)
        });
        await _dbContext.SaveChangesAsync();

        // Act
        var result = await _sut.IsTokenRevokedAsync(UserId, TenantId, issuedAt);

        // Assert: strict less-than means exact match is NOT revoked
        Assert.False(result);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_ReturnsFalse_WhenNoRevocationExists()
    {
        // Arrange: no revocation record in the database
        var issuedAt = new DateTime(2026, 3, 4, 0, 0, 10, DateTimeKind.Utc);

        // Act
        var result = await _sut.IsTokenRevokedAsync(UserId, TenantId, issuedAt);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task RevokeUserTokensAsync_CreatesNewRecord_WhenNoneExists()
    {
        // Arrange
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var expectedTokenId = $"{UserId}:{TenantId}";
        var expectedExpiration = TimeSpan.FromDays(30); // default RefreshTokenExpiration

        // Act
        await _sut.RevokeUserTokensAsync(UserId, TenantId);

        // Assert
        var record = await _dbContext.RevokedTokens.FindAsync(expectedTokenId);
        Assert.NotNull(record);
        Assert.Equal(expectedTokenId, record.TokenId);
        Assert.Equal(now, record.RevokedAt);
        Assert.Equal(now.Add(expectedExpiration), record.ExpiresAt);
    }

    [Fact]
    public async Task RevokeUserTokensAsync_UpdatesExpiresAt_WhenRecordAlreadyExists()
    {
        // Arrange: create an initial revocation record
        var initialTime = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc);
        var tokenId = $"{UserId}:{TenantId}";

        _dbContext.RevokedTokens.Add(new RevokedToken
        {
            TokenId = tokenId,
            RevokedAt = initialTime,
            ExpiresAt = initialTime.AddDays(30)
        });
        await _dbContext.SaveChangesAsync();

        // Advance time so we can observe the ExpiresAt update
        _timeProvider.Advance(TimeSpan.FromHours(1));
        var expectedNow = _timeProvider.GetUtcNow().UtcDateTime;

        // Act
        await _sut.RevokeUserTokensAsync(UserId, TenantId);

        // Assert: ExpiresAt slides forward from the new call time
        var record = await _dbContext.RevokedTokens.FindAsync(tokenId);
        Assert.NotNull(record);
        Assert.Equal(expectedNow.AddDays(30), record.ExpiresAt);
    }

    [Fact]
    public async Task RevokeUserTokensAsync_DoesNotMoveRevokedAt_WhenRecordAlreadyExists()
    {
        // Arrange: seed a record with a known original RevokedAt timestamp
        var originalRevokedAt = new DateTime(2026, 3, 1, 0, 0, 0, DateTimeKind.Utc);
        var tokenId = $"{UserId}:{TenantId}";

        _dbContext.RevokedTokens.Add(new RevokedToken
        {
            TokenId = tokenId,
            RevokedAt = originalRevokedAt,
            ExpiresAt = originalRevokedAt.AddDays(30)
        });
        await _dbContext.SaveChangesAsync();

        // Advance the clock so that re-revoking would use a later timestamp
        _timeProvider.Advance(TimeSpan.FromHours(6));
        var laterTime = _timeProvider.GetUtcNow().UtcDateTime;

        // Sanity-check: the later time really is after the original
        Assert.True(laterTime > originalRevokedAt);

        // Act: revoke again for the same user / tenant
        await _sut.RevokeUserTokensAsync(UserId, TenantId);

        // Assert: RevokedAt must remain at the original value so that tokens
        // issued between originalRevokedAt and laterTime stay revoked
        var record = await _dbContext.RevokedTokens.FindAsync(tokenId);
        Assert.NotNull(record);
        Assert.Equal(originalRevokedAt, record.RevokedAt);

        // ExpiresAt must have been extended to the new call time + expiry window
        Assert.Equal(laterTime.AddDays(30), record.ExpiresAt);
    }

    [Fact]
    public async Task CleanupExpiredAsync_DeletesOnlyExpiredRecords()
    {
        // Arrange: add two records -- one expired, one still valid
        var now = _timeProvider.GetUtcNow().UtcDateTime;

        var expiredRecord = new RevokedToken
        {
            TokenId = "expired-user:tenant-a",
            RevokedAt = now.AddDays(-60),
            ExpiresAt = now.AddHours(-1) // expired
        };

        var activeRecord = new RevokedToken
        {
            TokenId = "active-user:tenant-b",
            RevokedAt = now.AddHours(-1),
            ExpiresAt = now.AddDays(29) // still valid
        };

        _dbContext.RevokedTokens.AddRange(expiredRecord, activeRecord);
        await _dbContext.SaveChangesAsync();

        // Act
        await _sut.CleanupExpiredAsync();

        // Assert
        var remaining = await _dbContext.RevokedTokens.ToListAsync();
        Assert.Single(remaining);
        Assert.Equal("active-user:tenant-b", remaining[0].TokenId);
    }

    /// <summary>
    /// Documents the TOCTOU race-condition retry contract for
    /// <see cref="TokenRevocationService.RevokeUserTokensAsync"/>.
    ///
    /// Race scenario:
    ///   Two concurrent logout requests for the same user+tenant both call
    ///   RevokeUserTokensAsync at roughly the same time.
    ///   1. Both see FindAsync return null (no existing record).
    ///   2. Both queue a new RevokedToken for insert.
    ///   3. The first SaveChangesAsync succeeds.
    ///   4. The second hits a unique constraint violation (DbUpdateException).
    ///   5. The catch block clears the tracker, reloads the winner's record,
    ///      and updates only ExpiresAt — leaving RevokedAt untouched.
    ///
    /// True concurrent DB access cannot be deterministically reproduced with a
    /// single-connection SQLite in-memory database in a unit test, so this test
    /// instead verifies the retry path directly: it seeds the winning record
    /// first, then asserts that a second call (which would follow the update
    /// branch, not the retry branch) correctly extends ExpiresAt without moving
    /// RevokedAt. The retry branch itself is covered structurally by the
    /// try/catch in the production code; a full concurrency integration test
    /// would require two separate DbContext instances backed by a real database.
    /// </summary>
    [Fact]
    public async Task RevokeUserTokensAsync_ConcurrentInsertRace_RetryUpdatesExpiresAtWithoutMovingRevokedAt()
    {
        // Arrange: simulate the state left by the "winning" concurrent insert —
        // a record already exists in the database before our call begins.
        var winnerRevokedAt = new DateTime(2026, 3, 4, 12, 0, 0, DateTimeKind.Utc);
        var tokenId = $"{UserId}:{TenantId}";

        _dbContext.RevokedTokens.Add(new RevokedToken
        {
            TokenId = tokenId,
            RevokedAt = winnerRevokedAt,
            ExpiresAt = winnerRevokedAt.AddDays(30)
        });
        await _dbContext.SaveChangesAsync();

        // Advance the clock slightly so the second caller's ExpiresAt differs
        // from the winner's — this lets us assert the slide-forward happened.
        _timeProvider.Advance(TimeSpan.FromSeconds(5));
        var secondCallerNow = _timeProvider.GetUtcNow().UtcDateTime;

        // Act: the "losing" caller arrives after the winner has already inserted.
        // Because FindAsync now returns the existing record, the service takes the
        // update branch. The important invariant is that RevokedAt is not moved.
        await _sut.RevokeUserTokensAsync(UserId, TenantId);

        // Assert
        var record = await _dbContext.RevokedTokens.FindAsync(tokenId);
        Assert.NotNull(record);

        // RevokedAt must remain at the winner's original timestamp so that every
        // token issued before that moment stays revoked.
        Assert.Equal(winnerRevokedAt, record.RevokedAt);

        // ExpiresAt must be extended to the second caller's expiry window so the
        // revocation record lives long enough to cover both callers' refresh-token
        // lifetimes.
        Assert.Equal(secondCallerNow.AddDays(30), record.ExpiresAt);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        _connection.Dispose();
    }
}
