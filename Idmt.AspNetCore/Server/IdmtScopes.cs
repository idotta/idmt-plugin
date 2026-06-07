namespace Idmt.AspNetCore.Server;

/// <summary>
/// The scope catalog the OpenIddict server can issue. A client may only request a
/// scope the server knows; consumers extend this catalog through the seeder rather
/// than by editing the server registration.
/// </summary>
public static class IdmtScopes
{
    /// <summary>The ordinary resource scope.</summary>
    public const string Api = "api";

    /// <summary>
    /// Marks a support token: a tenant-audienced reference token an IDMT system user
    /// mints server-side to act on a tenant's behalf (see task 08, support-token mint).
    /// </summary>
    public const string Support = "support";
}
