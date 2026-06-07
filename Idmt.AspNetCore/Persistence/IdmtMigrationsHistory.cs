namespace Idmt.AspNetCore.Persistence;

/// <summary>
/// Distinct EF Core migration-history table names, one per context, so the three
/// contexts can share a single database without their histories colliding on the
/// default <c>__EFMigrationsHistory</c> table.
/// </summary>
public static class IdmtMigrationsHistory
{
    public const string App = "__IdmtMigrationsHistory";
    public const string OpenIddict = "__IdmtOpenIddictMigrationsHistory";
    public const string TenantStore = "__IdmtTenantStoreMigrationsHistory";
}
