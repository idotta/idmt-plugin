using Finbuckle.MultiTenant.Abstractions;
using Idmt.Spike.Host.Domain;
using Idmt.Spike.Host.Persistence;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace Idmt.Spike.Host.Auth;

/// <summary>Per-tenant audience URN, the RFC 8707 resource value.</summary>
public static class TenantUrns
{
    public const string Prefix = "urn:idmt:tenant:";

    public static string For(string identifier) => Prefix + identifier;

    public static string? IdentifierFrom(string urn) =>
        urn.StartsWith(Prefix, StringComparison.Ordinal) ? urn[Prefix.Length..] : null;
}

/// <summary>
/// The uniform TenantAccess gate. Queried at token issuance for every grant,
/// with no reliance on an ambient tenant (the token endpoint has none).
/// </summary>
public interface ITenantAccessGate
{
    Task<bool> CanAccessAsync(Guid userId, string tenantIdentifier, CancellationToken ct);
}

public sealed class TenantAccessGate(IdmtIdentityDbContext db, TimeProvider clock) : ITenantAccessGate
{
    public async Task<bool> CanAccessAsync(Guid userId, string tenantIdentifier, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        // SQLite cannot translate the DateTimeOffset comparison, so filter the
        // translatable predicate in SQL and evaluate expiry in memory. The
        // candidate set is at most a handful of rows per (user, tenant).
        var candidates = await db.TenantAccess
            .Where(ta => ta.UserId == userId && ta.TenantId == tenantIdentifier && ta.IsActive)
            .Select(ta => ta.ExpiresAt)
            .ToListAsync(ct);

        return candidates.Any(expiresAt => expiresAt == null || expiresAt > now);
    }
}

/// <summary>
/// Gate 3: the IDMT-owned per-request audience handler. Successor to v1's
/// ValidateBearerTokenTenantMiddleware, relocated into the OpenIddict validation
/// pipeline. Rejects any token whose audience does not bind to the
/// Finbuckle-resolved tenant. Runs after the built-in handlers establish the
/// principal (UseMultiTenant must run before UseAuthentication so the accessor
/// is populated).
/// </summary>
public sealed class TenantAudienceValidationHandler(IMultiTenantContextAccessor<IdmtTenantInfo> accessor)
    : IOpenIddictValidationHandler<ProcessAuthenticationContext>
{
    public static OpenIddictValidationHandlerDescriptor Descriptor { get; } =
        OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseScopedHandler<TenantAudienceValidationHandler>()
            // Run after every built-in authentication handler has populated the principal.
            .SetOrder(int.MaxValue - 100_000)
            .SetType(OpenIddictValidationHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        // Only access tokens are tenant-bound; skip other token types.
        if (context.AccessTokenPrincipal is null || context.IsRejected)
        {
            return ValueTask.CompletedTask;
        }

        var resolved = accessor.MultiTenantContext?.TenantInfo?.Identifier;
        if (string.IsNullOrEmpty(resolved))
        {
            // No resolved tenant on a token-bound request: refuse rather than guess.
            context.Reject(Errors.InvalidToken, "No tenant was resolved for this request.");
            return ValueTask.CompletedTask;
        }

        var expected = TenantUrns.For(resolved);
        var audiences = context.AccessTokenPrincipal.GetAudiences();
        if (!audiences.Contains(expected, StringComparer.Ordinal))
        {
            context.Reject(Errors.InvalidToken, "Token audience does not match the resolved tenant.");
        }

        return ValueTask.CompletedTask;
    }
}
