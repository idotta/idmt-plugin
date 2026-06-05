# Solution and packages

In this first v2 build task you create the greenfield solution skeleton: two
shipped packages, built from three projects, plus one test project that enforces
the architectural boundary between them. The boundary is the point of this task.
`Idmt.Core` holds the domain, and it must never reach an engine infrastructure
type. It openly depends on the ASP.NET Core Identity abstractions its entities
extend: `IdmtUser : IdentityUser<Guid>` and `IdmtRole : IdentityRole<Guid>` mean
the domain references `Microsoft.Extensions.Identity.Stores` and
`Microsoft.AspNetCore.Identity`. `Idmt.Core` is a separate project but not a
shipped package: there is no consumer of the domain without the host, so its
assembly ships inside the `Idmt.AspNetCore` package. The project boundary exists
for one reason: to keep the engine-isolation guarantee compile-enforced. You don't
enforce it with a code-review habit; you enforce it with a fitness test that fails
the build the moment `Idmt.Core` references OpenIddict, Finbuckle, Entity Framework
Core, or the Identity Entity Framework Core store package. Get this skeleton right
and every later task drops into a place that already keeps the domain clean.

## What you build

This task scaffolds four projects: two you ship as packages, one internal domain
project folded into the `Idmt.AspNetCore` package, and one that guards the
boundary. None of them carries real logic yet; you're laying down the shape and
the boundary the rest of v2 fills in.

- `Idmt.Core`: the domain layer (a non-packable class library whose only
  infrastructure references are the ASP.NET Core Identity abstractions its base
  types require). It is not shipped on its own; its assembly is included in the
  `Idmt.AspNetCore` package.
- `Idmt.AspNetCore`: the composition root and the package most consumers add,
  referencing `Idmt.Core` and including its assembly.
- `Idmt.Mfa`: the opt-in multi-factor package, referencing the `Idmt.AspNetCore`
  package (which carries `Idmt.Core` transitively).
- `Idmt.Architecture.Tests`: the fitness-test project that asserts `Idmt.Core`
  has no denied infrastructure assembly references.

## Source of truth

The package split and the test that enforces it come straight from the v2
architecture decision record. Read it before you write code so the boundary you
build matches the one that was decided.

The module boundaries live in
[ADR 0002 section 2.2](../../adr/0002-idmt-v2-openiddict-authorization-layer.md),
which fixes the module split and names the architecture fitness function
as the enforcement mechanism. (The ADR framed `Idmt.Core` as a shipped package;
v2 keeps it a separate project but folds its assembly into the `Idmt.AspNetCore`
package, since no consumer references the domain alone. The boundary the ADR cares
about is unchanged.) The test strategy in
[ADR 0002 section 4](../../adr/0002-idmt-v2-openiddict-authorization-layer.md)
lists the fitness function as the first CI gate: `Idmt.Core` references no
infrastructure assembly, and vendor types appear only in their owning folder.

## Design

The design is a one-way dependency graph with the domain at the bottom. The two
shipping projects depend on `Idmt.Core`, and `Idmt.Core` depends on no engine
infrastructure. This section gives you the responsibility of each project, the
dependency direction, a representative project file, and a folder tree to start
from.

The dependency direction is fixed and one-way:

- `Idmt.AspNetCore` depends on `Idmt.Core` and embeds its assembly in the package.
- `Idmt.Mfa` depends on the `Idmt.AspNetCore` package (which carries `Idmt.Core`
  transitively), not on `Idmt.Core` directly, so the domain assembly is packaged in
  exactly one place.
- `Idmt.Core` depends on nothing infrastructural except ASP.NET Core Identity
  abstractions. It references `Microsoft.Extensions.Identity.Stores` and
  `Microsoft.AspNetCore.Identity` (because `IdmtUser`/`IdmtRole` derive from the
  Identity base types) but no OpenIddict, no Finbuckle.MultiTenant, no Entity
  Framework Core, and not the Identity Entity Framework Core store package.

### `Idmt.Core`: the domain

`Idmt.Core` is the part of v2 that's genuinely yours: the multi-tenant
authorization model. It holds the canonical `IdmtUser`, `IdmtRole`,
`TenantAccess`, `ClientTenantAccess`, and `SysRole` types, the authorization
policies, the support-capability rule, the gate service ports
(`ITenantAccessGate`, `IClientTenantAccessGate`), and a clock port. It declares no
repository ports: data access is not abstracted, because Entity Framework Core's
`DbContext` and ASP.NET Core Identity's `UserManager` are already the persistence
abstractions, and v2 commits to them with no second backend in view. Those queries
live in `Idmt.AspNetCore`. The second-factor requirement is a domain invariant and
lives here, not in `Idmt.Mfa`: `Idmt.Mfa` supplies factor implementations, but the
rule that a system user or a multi-tenant user must satisfy a second factor before
a token issues belongs to the core gate.

`Idmt.Core` is a plain class library. It uses `Microsoft.NET.Sdk`, not the web
SDK, because nothing in the domain touches the web stack. It is not packed on its
own (`IsPackable` is false); its assembly ships inside the `Idmt.AspNetCore`
package. Its only package reference is the ASP.NET Core Identity abstractions
(`Microsoft.Extensions.Identity.Stores`), which `IdmtUser` and `IdmtRole` need
because they derive from `IdentityUser<Guid>` and `IdentityRole<Guid>`. A
representative project file:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <LangVersion>14</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <IsPackable>false</IsPackable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.Extensions.Identity.Stores" Version="10.0.3" />
  </ItemGroup>

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
    ClientTenantAccess.cs
    SysRole.cs
  Authorization/
    IdmtPolicies.cs
    SupportCapability.cs
  Ports/
    ITenantAccessGate.cs
    IClientTenantAccessGate.cs
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
    <!-- OpenIddict server and store (pinned to the spike's proven versions). -->
    <PackageReference Include="OpenIddict.AspNetCore" Version="7.5.0" />
    <PackageReference Include="OpenIddict.EntityFrameworkCore" Version="7.5.0" />

    <!-- Finbuckle multi-tenancy and its Identity/EF Core bridges. -->
    <PackageReference Include="Finbuckle.MultiTenant.AspNetCore" Version="10.0.3" />
    <PackageReference Include="Finbuckle.MultiTenant.EntityFrameworkCore" Version="10.0.3" />
    <PackageReference Include="Finbuckle.MultiTenant.Identity.EntityFrameworkCore" Version="10.0.3" />

    <!-- ASP.NET Core Identity backed by EF Core (the store binding lives here, not in Core). -->
    <PackageReference Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore" Version="10.0.3" />

    <!-- Persisted, shared Data Protection key ring (see 09-browser-login-bff.md). -->
    <PackageReference Include="Microsoft.AspNetCore.DataProtection.EntityFrameworkCore" Version="10.0.3" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\Idmt.Core\Idmt.Core.csproj" PrivateAssets="all" />
  </ItemGroup>

  <!-- Idmt.Core is non-packable, so bundle its assembly into this package. -->
  <PropertyGroup>
    <TargetsForTfmSpecificBuildOutput>$(TargetsForTfmSpecificBuildOutput);IncludeCoreAssembly</TargetsForTfmSpecificBuildOutput>
  </PropertyGroup>
  <Target Name="IncludeCoreAssembly">
    <ItemGroup>
      <BuildOutputInPackage Include="$(OutputPath)Idmt.Core.dll" />
    </ItemGroup>
  </Target>

</Project>
```

Because `Idmt.Core` is a separate project but not its own package, the
`ProjectReference` carries `PrivateAssets="all"` and a `BuildOutputInPackage`
target folds the `Idmt.Core` assembly into the `Idmt.AspNetCore` package. Without
that target a consumer would resolve `Idmt.AspNetCore` and find the domain types
missing at runtime. The OpenIddict (7.5.0) and Finbuckle plus Identity EF Core
(10.0.3) pins match the spike's `Idmt.Spike.Host.csproj` exactly, so you ship the
same versions the gates proved. The Data Protection EF Core package is new to the product (the
in-process spike never needed a persisted key ring); pin it to the same 10.0.3
line as the rest of the framework packages. A consumer who keys Data Protection in
a key vault instead of the database swaps this package for the matching key-vault
provider; the requirement is a persisted, shared key ring, not this specific
provider (see [09-browser-login-bff.md](09-browser-login-bff.md)).

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
the WebAuthn dependency off the main package for consumers who don't need it. It
references the `Idmt.AspNetCore` package, not `Idmt.Core` directly. Two reasons:
`Idmt.Mfa` is meaningless without the host (it plugs factor providers into the
auth pipeline), and depending on `Idmt.AspNetCore` brings the `Idmt.Core` assembly
transitively (that package already embeds it), so the domain assembly is shipped
in exactly one place and a consumer who installs both packages never sees a
duplicate-assembly conflict.

For first ship it carries a single TOTP source (`Otp.NET`); the WebAuthn package
(`Fido2`, from `fido2-net-lib`) is added only when the WebAuthn factor lands, so
its transitive dependencies stay off the package until then:

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
    <!-- TOTP now. -->
    <PackageReference Include="Otp.NET" Version="1.4.0" />
    <!-- WebAuthn later: <PackageReference Include="Fido2" Version="..." /> -->
  </ItemGroup>

  <ItemGroup>
    <!-- Brings Idmt.Core transitively (embedded in the Idmt.AspNetCore package). -->
    <ProjectReference Include="..\Idmt.AspNetCore\Idmt.AspNetCore.csproj" />
  </ItemGroup>

</Project>
```

The spike never wired an MFA provider, so neither package has a spike pin; pin the
TOTP source at edit time and add the `Fido2` pin when [12-mfa.md](12-mfa.md)
delivers the WebAuthn factor.

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
and not the Identity Entity Framework Core store package. It deliberately allows
the ASP.NET Core Identity abstractions (`Microsoft.Extensions.Identity.Stores`
and `Microsoft.AspNetCore.Identity`), because `IdmtUser` and `IdmtRole` derive
from `IdentityUser<Guid>` and `IdentityRole<Guid>`. The deny list therefore
denies `Microsoft.AspNetCore.Identity.EntityFrameworkCore` (the store binding)
while permitting the two abstraction assemblies, which is why the prefix match
has to be exact enough to tell them apart. Second, the way it checks is reflection
over `Assembly.GetReferencedAssemblies()` on the `Idmt.Core` assembly, matched
against a deny list of infrastructure assembly name prefixes. A representative
shape:

```csharp
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
```

A test enforces this rather than more packages because of a deliberate trade-off
recorded in the ADR. The ADR chose a coarse split over a fine one. A finer split
would give cleaner vendor-version blast radius, because OpenIddict, Finbuckle, and
Entity Framework Core would each sit behind a separate assembly, so a
major-version bump in one wouldn't touch the others. The ADR rejected that as more
ceremony than a solo-owned plugin warrants, and v2 goes one step coarser still:
`Idmt.Core` is not even shipped as its own package, since nothing consumes the
domain without the host. The architecture test recovers the domain-isolation
benefit a finer split would have enforced structurally: it keeps infrastructure
types out of the domain regardless of how few packages you ship. What the test
can't recover is the vendor-version blast radius, since OpenIddict, Finbuckle, and
Entity Framework Core all live in `Idmt.AspNetCore` and a major bump in any one
touches that one assembly. That blast radius is the consciously accepted cost of
two packages instead of five.

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

- The architecture fitness test passes: `Idmt.Core` references no infrastructure
  assembly (no OpenIddict, Finbuckle.MultiTenant, Entity Framework Core, or the
  Identity Entity Framework Core store package), while the allowed ASP.NET Core
  Identity abstractions (`Microsoft.Extensions.Identity.Stores`,
  `Microsoft.AspNetCore.Identity`) are not flagged.
- The solution builds with warnings treated as errors. Every project sets
  `TreatWarningsAsErrors` to `true`, and a warning fails the build.

## Next steps

With the skeleton and the boundary in place, the next tasks fill the empty
packages from the bottom up. Start with the domain, then stand up persistence.

Read [02-core-domain.md](02-core-domain.md) next to fill `Idmt.Core` with the
canonical identity types, the authorization policies, the support-capability
rule, and the gate service ports. After that,
[03-persistence-and-contexts.md](03-persistence-and-contexts.md) stands up the
two Entity Framework Core contexts in `Idmt.AspNetCore`: the multi-tenant
application context and the separate, tenant-agnostic OpenIddict store context.
