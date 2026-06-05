# Solution and packages

In this first v2 build task you create the greenfield solution skeleton: three
shipped packages and one test project that enforces the architectural boundary
between them. The boundary is the point of this task. `Idmt.Core` holds the pure
domain, and it must never reach an infrastructure type. You don't enforce that
rule with a code-review habit or with extra packages; you enforce it with a
fitness test that fails the build the moment `Idmt.Core` references OpenIddict,
Finbuckle, Entity Framework Core, or ASP.NET Core. Get this skeleton right and
every later task drops into a place that already keeps the domain clean.

## What you build

This task scaffolds four projects: three you ship and one that guards them. None
of them carries real logic yet; you're laying down the shape and the boundary
the rest of v2 fills in.

- `Idmt.Core`: the pure domain layer (a class library with zero infrastructure
  references).
- `Idmt.AspNetCore`: the composition root and the only package most consumers
  add, referencing `Idmt.Core`.
- `Idmt.Mfa`: the opt-in multi-factor package, referencing `Idmt.Core`.
- `Idmt.Architecture.Tests`: the fitness-test project that asserts `Idmt.Core`
  has no infrastructure assembly references.

## Source of truth

The package split and the test that enforces it come straight from the v2
architecture decision record. Read it before you write code so the boundary you
build matches the one that was decided.

The module boundaries live in
[ADR 0002 section 2.2](../../adr/0002-idmt-v2-openiddict-authorization-layer.md),
which fixes the three-package split and names the architecture fitness function
as the enforcement mechanism. The test strategy in
[ADR 0002 section 4](../../adr/0002-idmt-v2-openiddict-authorization-layer.md)
lists the fitness function as the first CI gate: `Idmt.Core` references no
infrastructure assembly, and vendor types appear only in their owning folder.

## Design

The design is a one-way dependency graph with the domain at the bottom. Two
packages depend on `Idmt.Core`, and `Idmt.Core` depends on nothing
infrastructural. This section gives you the responsibility of each package, the
dependency direction, a representative project file, and a folder tree to start
from.

The dependency direction is fixed and one-way:

- `Idmt.AspNetCore` depends on `Idmt.Core`.
- `Idmt.Mfa` depends on `Idmt.Core`.
- `Idmt.Core` depends on nothing infrastructural. No OpenIddict, no
  Finbuckle.MultiTenant, no Entity Framework Core, no ASP.NET Core.

### `Idmt.Core`: the domain

`Idmt.Core` is the part of v2 that's genuinely yours: the multi-tenant
authorization model and the ports the infrastructure plugs into. It holds the
canonical `IdmtUser`, `IdmtRole`, `TenantAccess`, and `SysRole` types, the
authorization policies, the support-capability rule, and the repository and
service ports. The second-factor requirement is a domain invariant and lives
here, not in `Idmt.Mfa`: `Idmt.Mfa` supplies factor implementations, but the
rule that a system user or a multi-tenant user must satisfy a second factor
before a token issues belongs to the core gate.

`Idmt.Core` is a plain class library. It uses `Microsoft.NET.Sdk`, not the web
SDK, because nothing in the domain touches the web stack. A representative
`PropertyGroup`:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <LangVersion>14</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>

</Project>
```

A suggested folder tree:

```text
Idmt.Core/
  Idmt.Core.csproj
  Identity/
    IdmtUser.cs
    IdmtRole.cs
    TenantAccess.cs
    SysRole.cs
  Authorization/
    IdmtPolicies.cs
    SupportCapability.cs
  Ports/
    IUserRepository.cs
    ITenantAccessRepository.cs
    ISupportAuditPort.cs
```

### `Idmt.AspNetCore`: the composition root

`Idmt.AspNetCore` is where every vendor lives. It references `Idmt.Core` and
hosts the OpenIddict, Finbuckle.MultiTenant, Entity Framework Core, endpoint,
and email integrations, each isolated in a dedicated folder so a reader can see
exactly which vendor a file belongs to. The folder names map to the ADR: server
wiring under `Server/`, tenant resolution under `MultiTenancy/`, the two
`DbContext` types and their stores under `Persistence/`, and the
pre-authorized route groups under `Endpoints/`.

`Idmt.AspNetCore` is a library that consumers reference from their web host, not
a web application itself. So it uses `Microsoft.NET.Sdk` (not
`Microsoft.NET.Sdk.Web`) and adds a `FrameworkReference` to
`Microsoft.AspNetCore.App` to pull in the ASP.NET Core shared framework without
becoming a runnable app:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <LangVersion>14</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>

  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\Idmt.Core\Idmt.Core.csproj" />
  </ItemGroup>

</Project>
```

A suggested folder tree, with vendor types isolated by folder:

```text
Idmt.AspNetCore/
  Idmt.AspNetCore.csproj
  IdmtBuilder/
    IIdmtBuilder.cs
    ServiceCollectionExtensions.cs
  Server/            (OpenIddict wiring)
  MultiTenancy/      (Finbuckle.MultiTenant resolution)
  Persistence/       (EF Core contexts and stores)
  Endpoints/         (MapIdmtTenantApi, MapIdmtSysAdminApi)
  Email/             (transport and link generation)
```

### `Idmt.Mfa`: opt-in multi-factor

`Idmt.Mfa` is a separate package on purpose. It supplies factor implementations,
TOTP now and WebAuthn through `fido2-net-lib` later, and shipping it apart keeps
the WebAuthn dependency off the main package for consumers who don't need it.
Like the others, it references `Idmt.Core` and nothing more from the IDMT side.

A suggested folder tree:

```text
Idmt.Mfa/
  Idmt.Mfa.csproj
  Totp/
    TotpFactorProvider.cs
  WebAuthn/          (fido2-net-lib, added later)
```

## The architecture fitness function

`Idmt.Architecture.Tests` is a compile-and-test project that turns the domain
boundary into a build gate. It loads the `Idmt.Core` assembly, reflects over the
assemblies `Idmt.Core` references, and fails if any infrastructure assembly
appears in that list. This is the first CI gate from
[ADR 0002 section 4](../../adr/0002-idmt-v2-openiddict-authorization-layer.md),
and it must pass before any merge.

The test asserts two things. First, `Idmt.Core` references no infrastructure
assembly: not OpenIddict, not Finbuckle.MultiTenant, not Entity Framework Core,
and not ASP.NET Core. Second, the way it checks is reflection over
`Assembly.GetReferencedAssemblies()` on the `Idmt.Core` assembly, matched
against a deny list of infrastructure assembly name prefixes. A representative
shape:

```csharp
[Fact]
public void Core_references_no_infrastructure_assembly()
{
    string[] forbidden =
    [
        "OpenIddict",
        "Finbuckle",
        "Microsoft.EntityFrameworkCore",
        "Microsoft.AspNetCore",
    ];

    var referenced = typeof(IdmtUser).Assembly
        .GetReferencedAssemblies()
        .Select(name => name.Name!);

    var leaks = referenced
        .Where(name => forbidden.Any(prefix =>
            name.StartsWith(prefix, StringComparison.Ordinal)))
        .ToArray();

    Assert.True(leaks.Length == 0,
        $"Idmt.Core must not reference infrastructure: {string.Join(", ", leaks)}");
}
```

A test enforces this rather than more packages because of a deliberate trade-off
recorded in the ADR. The ADR chose three packages over five. A five-package
split would give cleaner vendor-version blast radius, because OpenIddict,
Finbuckle, and Entity Framework Core would each sit behind a separate assembly,
so a major-version bump in one wouldn't touch the others. The ADR rejected that
split as more ceremony than a solo-owned plugin warrants. The architecture test
recovers the domain-isolation benefit a finer split would have enforced
structurally: it keeps infrastructure types out of the domain regardless of how
few packages you ship. What the test can't recover is the vendor-version blast
radius, since OpenIddict, Finbuckle, and Entity Framework Core all live in
`Idmt.AspNetCore` and a major bump in any one touches that one assembly. That
blast radius is the consciously accepted cost of three packages instead of five.

This boundary is also why v1's mistakes don't recur. v1 conflated "feature
folder" with "layer," which is how a feature handler ended up performing
cross-layer surgery on persistence rows. The architecture test makes the
firewall a compile-and-test guarantee, so the domain stays isolated no matter
how the feature folders are arranged.

The spike used a single host project for speed, so there's no single spike file
to copy into this layout. The spike proved the engine composition; the package
boundary is the new work this task delivers.

## Dependencies

This is the first v2 task, so it has no prerequisites. You're starting from an
empty `docs/v2` slot and a greenfield solution. Everything later in the v2 plan
builds on the skeleton you create here.

## Acceptance criteria

You're done when the boundary holds and the build is clean. Both criteria are
mechanical, so CI can check them.

- The architecture fitness test passes: `Idmt.Core` references zero
  infrastructure assemblies (no OpenIddict, Finbuckle.MultiTenant, Entity
  Framework Core, or ASP.NET Core).
- The solution builds with warnings treated as errors. Every project sets
  `TreatWarningsAsErrors` to `true`, and a warning fails the build.

## Next steps

With the skeleton and the boundary in place, the next tasks fill the empty
packages from the bottom up. Start with the domain, then stand up persistence.

Read [02-core-domain.md](02-core-domain.md) next to fill `Idmt.Core` with the
canonical identity types, the authorization policies, the support-capability
rule, and the repository and service ports. After that,
[03-persistence-and-contexts.md](03-persistence-and-contexts.md) stands up the
two Entity Framework Core contexts in `Idmt.AspNetCore`: the multi-tenant
application context and the separate, tenant-agnostic OpenIddict store context.
