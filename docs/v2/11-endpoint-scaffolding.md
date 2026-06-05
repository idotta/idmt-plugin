# Endpoint scaffolding

The scaffolding is the payoff for "opinionated but customizable." IDMT v2
provides two mapping entry points, `MapIdmtTenantApi` and
`MapIdmtSysAdminApi`, that mount the built-in surfaces with the correct
authorization policy and rate limiter already attached. Both return the
resulting route group, so you add your own minimal-API endpoints to that
group and inherit the pre-attached policy without redeclaring auth on
every handler. The consumer never touches a policy name at the call site;
the umbrella already carries it.

This doc is the build guide for those two entry points, the five public
policy-name constants they depend on, and the returned-route-group pattern
you use to extend either surface.

## What you build

The scaffolding lives in `Idmt.AspNetCore`, specifically in
`Endpoints/`, consistent with the vertical-slice layout that the existing
`ApplicationBuilderExtensions.cs` and feature classes already follow. You
build two things:

- `MapIdmtTenantApi`: the tenant-facing entry point. Mounts account
  self-management, the out-of-band email flows, and tenant membership
  management under a fixed prefix with `RequireTenantMember` and the
  tenant rate limiter attached. Returns the route group.
- `MapIdmtSysAdminApi`: the system-admin entry point. Mounts tenant
  lifecycle, `TenantAccess` grant and revoke, system-role assignment, and
  the support-token exchange under a fixed prefix with `RequireSysAdmin`
  attached. Returns the route group.

Both entry points follow the style already established in
`Idmt.Plugin/Extensions/ApplicationBuilderExtensions.cs` and
`Idmt.Plugin/Features/AuthEndpoints.cs`: a static extension method on
`IEndpointRouteBuilder` that calls `MapGroup`, attaches policy and
(optionally) rate-limiter constraints to the group, delegates to
per-area endpoint classes, and returns the group to the caller.

## Source of truth

Read these before you implement, so the names, the surfaces, and the
policy constants match the committed architecture exactly.

- [ADR 0002 §2.10, endpoint scaffolding](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#210-endpoint-scaffolding):
  the decision that fixes both entry points, the returned-group pattern,
  and the five public policy-name constants.
- [ADR 0002 §2.5.1, browser clients use a backend-for-frontend session](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#251-browser-clients-use-a-backend-for-frontend-session):
  the optional session surface that sits alongside `MapIdmtTenantApi`.
- [ADR 0002 §2.8, system support through a server-side token mint](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#28-system-support-through-a-server-side-token-mint):
  the support exchange that `MapIdmtSysAdminApi` mounts.
- `Idmt.Plugin/Extensions/ApplicationBuilderExtensions.cs`: the current
  `MapIdmtEndpoints` implementation, the style this scaffolding follows.
- `Idmt.Plugin/Features/AuthEndpoints.cs`: a representative feature group,
  showing how `MapGroup`, `RequireRateLimiting`, and per-endpoint mapping
  methods compose.

## The tenant API surface

`MapIdmtTenantApi` mounts everything a tenant member needs to manage their
own account and their membership in the resolved tenant. The entry point
is an extension method on `IEndpointRouteBuilder`. It creates a route
group under a fixed prefix (for example, `/api/v2/tenant`), attaches the
`RequireTenantMember` policy to the group, conditionally attaches the
tenant rate limiter when rate limiting is enabled, and delegates to the
per-area feature classes that register the individual routes. It then
returns the group.

The built-in routes mounted under this group cover:

- Account self-management: profile reads and updates, password change,
  and the out-of-band email-change flow (stage, confirm, cancel).
- Email flows: the confirm-email and confirm-email-change endpoints, and
  resend-confirmation. These share the group's tenant policy so only an
  authenticated tenant member can trigger or resolve the flows.
- Tenant membership: read your own membership status and access grants
  within the resolved tenant.

The rate limiter that `MapIdmtTenantApi` attaches is the same
fixed-window policy `AuthEndpoints.cs` already applies to the auth
group. It protects the tenant surface from traffic bursts at the account
and email endpoints. The limiter is applied conditionally: when
`IdmtOptions.RateLimiting.Enabled` is false, the `RequireRateLimiting`
call is skipped so that hosts managing their own rate limiting can opt
out cleanly. The limiter policy name is an internal constant in the
feature file, following the `AuthRateLimiterPolicy = "idmt-auth"` pattern
in `AuthEndpoints.cs`.

`MapIdmtTenantApi` returns the `RouteGroupBuilder`. Every route you add
to that group inherits the `RequireTenantMember` policy automatically. You
do not call `RequireAuthorization` again on your own endpoints.

## The system-admin API surface

`MapIdmtSysAdminApi` mounts the system-administration surface: the
operations that only a holder of the `SysAdmin` system role may perform.
It creates a route group under a fixed prefix (for example,
`/api/v2/sysadmin`), attaches the `RequireSysAdmin` policy to the group,
and delegates to the per-area feature classes. It returns the group.

`MapIdmtSysAdminApi` asserts that `EnableSysAdminSurface()` was called on the
builder before it maps anything. The assertion exists because the surface
carries a locked control (the MFA fail-fast, invariant 8) that `Build()` can
only enforce when it sees the flag at registration time, and `Build()` runs
before this mapping. If the surface is mapped without the flag, the locked
control would not have been wired, so the mapping throws rather than mounting
an un-gated sys-admin surface. The same pattern applies to the BFF session
mapping, which asserts `EnableBffSession()` was called so the CSRF control
(invariant 9) is in place. See
[the locked seam](10-locked-seam.md#surface-opt-in-flags) for the flag side.

The built-in routes mounted under this group cover:

- Tenant lifecycle: create, activate, suspend, and delete tenants.
- `TenantAccess` management: grant and revoke a user's access to a
  specific tenant.
- System-role assignment: elevate or demote a user's `SysRoleKind`.
- Support operations: mint a support token for a target tenant (the
  server-side mint described in
  [the support-token mint doc](08-support-token-mint.md)) and revoke
  an active support token.

`MapIdmtSysAdminApi` does not attach a rate limiter separately. The
sys-admin surface is reached only by callers who already hold a
`RequireSysAdmin` token, which is a narrow audience. You may attach a
rate limiter to the returned group if you need one.

`MapIdmtSysAdminApi` also returns the `RouteGroupBuilder`. Every route
you add to that group inherits `RequireSysAdmin`. A request that does not
carry a token with the `SysAdmin` role claim is rejected by the
authorization middleware before it reaches any handler you mount.

## Email transport, link generation, and the out-of-band email-change flow

The tenant surface mounts the email-confirmation, resend-confirmation, and
out-of-band email-change endpoints, but the transport and link-generation
machinery behind them is currently mounted yet unbuilt. This section assigns it
an owner so it does not fall between the scaffolding and the core domain. The
email cross-cutting concern is owned here, alongside the tenant surface that
exposes its endpoints, and it reuses the v1 shapes rather than inventing new
ones.

- Email transport: the `IIdmtEmailSender` abstraction (the v1 shape) sends
  confirmation, password-reset, and email-change messages. The builder's
  `WithEmailTransport(...)` seam in [the locked seam](10-locked-seam.md#the-iidmtbuilder-fluent-interface)
  registers the concrete sender; the default in development is the no-op or
  logging sender the v1 sample uses.
- Link generation: `IIdmtLinkGenerator` (the v1 interface in
  `Idmt.Plugin/Services/IdmtLinkGenerator.cs`) builds the confirm-email,
  password-reset, and confirm-email-change links. Keep its v1 contract:
  `GenerateConfirmEmailLink`, `GeneratePasswordResetLink`, and
  `GenerateConfirmEmailChangeLink`, with the locked decision that the tenant
  identifier is not embedded as a query parameter (path or claim resolution
  carries it instead).
- The out-of-band email-change flow: `PUT /manage/info` stages the next email
  into `IdmtUser.PendingEmail` and returns 202 Accepted while staged; `Email`
  is committed only when the recipient POSTs the Identity-issued token to the
  confirm-email-change endpoint. This is the v1 flow carried forward unchanged.
- PII masking: structured logs in this surface mask email addresses through
  `PiiMasker` (the v1 shape in `Idmt.Plugin/Services/PiiMasker.cs`), so a
  confirmation or change log line never records a raw address.

## Request and response record shapes for locked-invariant operations

The slice records for most endpoints can be left to the implementer, following
the vertical-slice convention. Two of the sys-admin operations touch locked
invariants, so their request records are pinned here to keep the locked behavior
unambiguous. They use `required` members rather than `= null!;` initializers,
per the C# 14 convention.

The support-mint request carries the audited reason that invariant 7 requires,
so `Reason` is a `required` member with a FluentValidation `NotEmpty` rule. The
TTL is optional because the support-token TTL ceiling (invariant 6) applies a
default and clamps any supplied value down to the ceiling; a consumer can lower
it but never raise it past the ceiling.

```csharp
public sealed record MintSupportTokenRequest
{
    public required Guid TargetUserId { get; init; }
    public required string TenantIdentifier { get; init; }
    public required string Reason { get; init; }
    public TimeSpan? Ttl { get; init; }
}

internal sealed class MintSupportTokenRequestValidator
    : AbstractValidator<MintSupportTokenRequest>
{
    public MintSupportTokenRequestValidator()
    {
        RuleFor(x => x.Reason).NotEmpty();
    }
}
```

The `TenantAccess` grant and revoke records carry the target user and the
Finbuckle tenant identifier the uniform gate (invariant 1) keys on. Grant takes
an optional expiry; revoke needs only the pairing. These mirror the v1 admin
slice shapes in `Idmt.Plugin/Features/Admin/`.

```csharp
public sealed record GrantTenantAccessRequest
{
    public required Guid UserId { get; init; }
    public required string TenantIdentifier { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
}

public sealed record RevokeTenantAccessRequest
{
    public required Guid UserId { get; init; }
    public required string TenantIdentifier { get; init; }
}
```

## Authorization policy constants

Four of the constants in `IdmtPolicies` are gating authorization policies:
`RequireSysAdmin`, `RequireSysUser`, `RequireTenantManager`, and
`RequireTenantMember`. They are public constants in `Idmt.Core`, declared in
the domain rather than in `Idmt.AspNetCore` because they name the authorization
model IDMT owns, and both the scaffolding and consumer code reference them from
one canonical spelling. The
[core domain doc](02-core-domain.md#authorization-policy-constants)
covers their declaration and the `SysRoleKind` enum alignment in detail.
This section explains what each one gates and where it appears.

`SupportSession` is listed here too, but it is a different kind of thing: a
claims-inspection helper a handler reads, not a gating policy the middleware
enforces. It is documented at the end of the section for that reason and is not
interchangeable with the four gating policies above.

`RequireSysAdmin` gates callers who hold the `SysAdmin` system role. The
`MapIdmtSysAdminApi` scaffolding attaches it to the sys-admin group.
A `SysAdmin` user emits a `SysAdmin` role claim (the `SysRoleKind.SysAdmin`
string value matches the policy name directly), so the policy resolves
without a mapping layer.

`RequireSysUser` gates callers who hold any active system role, either
`SysAdmin` or `SysSupport`. Use it on endpoints that system support staff
can reach but that do not require the full `SysAdmin` capability, for
example a read-only support dashboard. Neither entry point attaches this
policy by default; you attach it yourself when you need it.

`RequireTenantManager` gates callers who manage the resolved tenant, that
is, callers whose claims indicate a manager-level role within the current
tenant. Use it on endpoints that a tenant administrator reaches but that
ordinary members cannot, for example an endpoint that changes tenant
settings or invites new members.

`RequireTenantMember` gates callers who are members of the resolved tenant.
The `MapIdmtTenantApi` scaffolding attaches it to the tenant group. Every
route under that group, including any route you add to the returned group,
requires a valid tenant-scoped reference token for the Finbuckle-resolved
tenant.

`SupportSession` is the impersonation-detection helper from the support mint.
It is not a gating authorization policy and is not attached to a route group or
an endpoint; the authorization middleware never evaluates it. A token minted
through the server-side support path carries the `support` scope and an RFC 8693
`act` claim naming the system user. `SupportSession` is a claims-inspection
check you run inside a handler against the current `ClaimsPrincipal`: when those
claims are present, the caller is an impersonating system user, and the handler
can then refuse destructive operations or surface a warning banner to the user.
Do not treat it as interchangeable with the four gating policies above; it gates
nothing on its own and only informs handler logic. See
[the support-token mint doc](08-support-token-mint.md) for the full claim
projection.

## Mounting your own endpoints

You call `MapIdmtTenantApi` or `MapIdmtSysAdminApi` on your
`WebApplication` (which implements `IEndpointRouteBuilder`), capture the
returned group, and map your own endpoints onto it. The group already
carries the attached policy, so your handlers inherit the authorization
requirement with no extra wiring.

Here is a minimal sketch for the tenant surface. The same pattern applies
to the sys-admin surface with `MapIdmtSysAdminApi`.

```csharp
var app = builder.Build();

// Mount the built-in tenant surface with RequireTenantMember attached,
// and capture the group to add consumer endpoints.
RouteGroupBuilder tenantApi = app.MapIdmtTenantApi();

// This endpoint inherits RequireTenantMember from the group.
// No RequireAuthorization call needed here.
tenantApi.MapGet("/profile/preferences", async (HttpContext ctx) =>
{
    // The caller is already validated as a tenant member by the group policy.
    // Access your own services through DI as usual.
    var prefs = await ctx.RequestServices
        .GetRequiredService<IPreferenceService>()
        .GetForCurrentUserAsync(ctx.RequestAborted);
    return Results.Ok(prefs);
});

app.Run();
```

The group prefix from `MapIdmtTenantApi` is prepended automatically, so
the full route for the example above might be `/api/v2/tenant/profile/preferences`.
You choose the sub-path; the umbrella prefix comes from the entry point.

For the sys-admin surface, the same pattern applies:

```csharp
RouteGroupBuilder sysAdminApi = app.MapIdmtSysAdminApi();

// Inherits RequireSysAdmin. Only a caller with the SysAdmin role reaches
// this handler.
sysAdminApi.MapGet("/audit-log", async (HttpContext ctx) =>
{
    var log = await ctx.RequestServices
        .GetRequiredService<IAuditLogService>()
        .GetRecentAsync(ctx.RequestAborted);
    return Results.Ok(log);
});
```

**Vertical-slice consistency.** Each built-in endpoint inside
`MapIdmtTenantApi` and `MapIdmtSysAdminApi` follows the same style as
the current `AuthEndpoints.cs` and the features in
`Idmt.Plugin/Features/Auth/`: a static feature class per operation with
a request record, a response record, a handler interface returning
`ErrorOr<T>`, a sealed internal handler implementation, a FluentValidation
validator registered through DI auto-discovery, and a `Map*Endpoint`
extension method on `IEndpointRouteBuilder`. Follow the same style for
your own handlers when you want to keep the codebase uniform; the
pattern is not enforced on consumer endpoints, but it is the natural fit
for endpoints you contribute back to the plugin.

## Dependencies

The scaffolding builds on several other v2 components. Read these docs
to understand what the attached policies and the built-in routes depend on.

- [Core domain](02-core-domain.md): the `IdmtPolicies` constants and the
  `TenantAccess` entities the policies gate against.
- [Tenant access gate](06-tenant-access-gate.md): the invariant that every
  token-issuance path re-checks `TenantAccess`, which is what makes
  `RequireTenantMember` meaningful at a resource endpoint.
- [Support-token mint](08-support-token-mint.md): the server-side mint
  the sys-admin surface exposes, the `SupportSession` policy, and the
  `support` scope and `act` claim projection.
- [The locked seam](10-locked-seam.md): the `Build()` step that applies
  the locked security invariants, including the MFA fail-fast rule that
  fires when `MapIdmtSysAdminApi` is called without a registered factor
  provider.

## Acceptance criteria

The scaffolding is correct when the checks below hold. Each is a test you
can write against the real middleware stack, not a static assertion.

- An endpoint mounted on the returned `MapIdmtTenantApi` group is
  reachable with a valid tenant-scoped reference token for the resolved
  tenant and returns the expected response.
- An endpoint mounted on the returned `MapIdmtTenantApi` group rejects
  a request with no bearer token with 401.
- An endpoint mounted on the returned `MapIdmtTenantApi` group rejects
  a request with a valid token scoped to a different tenant with 401 from
  the audience handler.
- An endpoint mounted on the returned `MapIdmtSysAdminApi` group is
  reachable with a token that carries the `SysAdmin` role claim.
- An endpoint mounted on the returned `MapIdmtSysAdminApi` group rejects
  a request with a token that carries only `SysSupport` (or no system role)
  with 403 from the `RequireSysAdmin` policy.
- An unauthorized request to any built-in route under either group is
  rejected by the attached policy before it reaches a handler.

## Next steps

With the scaffolding in place, the next concerns are the MFA enforcement
that fires when you map the sys-admin surface, and the seeded registrations
a running authorization server requires before the first request.

- [MFA](12-mfa.md): the second-factor requirement for system users and
  multi-tenant users, and how to register a factor provider.
- [Seeding and bootstrap](13-seeding-bootstrap.md): the `IIdmtApplicationSeeder`
  that provisions the initial OpenIddict registrations, the default
  first-party clients, and the first system administrator.
