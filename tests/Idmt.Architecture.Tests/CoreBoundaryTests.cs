using Idmt.Core.Identity;

namespace Idmt.Architecture.Tests;

/// <summary>
/// The architecture fitness function: the first CI gate from ADR 0002 section 4.
/// Fails the build if <c>Idmt.Core</c> reaches any engine infrastructure assembly.
/// </summary>
public class CoreBoundaryTests
{
    [Fact]
    public void Core_references_no_infrastructure_assembly()
    {
        // Identity abstractions are allowed: IdmtUser/IdmtRole derive from
        // IdentityUser<Guid>/IdentityRole<Guid>. The EF Core store binding is not.
        string[] forbidden =
        [
            "OpenIddict",
            "Finbuckle",
            "Microsoft.EntityFrameworkCore",
            "Microsoft.AspNetCore.Identity.EntityFrameworkCore",
        ];

        string[] allowed =
        [
            "Microsoft.Extensions.Identity.Stores",
            "Microsoft.AspNetCore.Identity",
        ];

        var referenced = typeof(IdmtUser).Assembly
            .GetReferencedAssemblies()
            .Select(name => name.Name!);

        var leaks = referenced
            .Where(name => forbidden.Any(prefix =>
                name.StartsWith(prefix, StringComparison.Ordinal)))
            .Where(name => !allowed.Any(prefix =>
                string.Equals(name, prefix, StringComparison.Ordinal)))
            .ToArray();

        Assert.True(leaks.Length == 0,
            $"Idmt.Core must not reference infrastructure: {string.Join(", ", leaks)}");
    }
}
