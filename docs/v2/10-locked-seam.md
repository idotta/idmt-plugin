# The opinionated-but-customizable seam

Lock the security, open the shape. IDMT v2 solves the central design problem
of a customizable security library structurally: a fixed set of security
invariants is locked and applied unconditionally inside `Build()`, while the
shape and surface of the system stay open as named extension points. You can
add behavior, but you cannot subtract a locked security property. The spike's
gate 5 proved the mechanism: a hostile registration that tries to disable a
locked option either gets overridden by the lock (when it runs before
`AddIdmt`) or fails the host at startup (when it runs after), so
registration-expressed subtraction is caught rather than shipped.

This doc covers the seam itself: the builder, the locked and open sets, the
two-layer lock, and the MFA fail-fast rule. The individual mechanisms it
enforces live in their own docs and are linked from
[the locked set](#the-locked-set).

## What you build

You build one composition root and call it once. The
[`IIdmtBuilder` fluent interface](#the-iidmtbuilder-fluent-interface) names
every seam, so the type system shows which calls add behavior and which
properties are locked. `Build()` then applies the locked configuration as the
last-registered post-configuration, so it wins over any earlier consumer call.
A startup self-check reads the resolved options snapshot and fails the host if
a locked invariant is missing. The
[MFA fail-fast rule](#mfa-fail-fast-rule) fires at build time, but only when
the deployment can actually produce a user that requires a second factor.

The result is a single guarantee you can state plainly: inadvertent
subtraction of a locked security property is impossible, and deliberate
subtraction of the registered options fails fast and is detectable.

## Source of truth

The authority for this seam is ADR 0002 and the spike that proved it. Read the
ADR section first, then the two wiring files and the gate 5 test for the
concrete mechanism.

- [ADR 0002 §2.9, the opinionated and customizable
  seam](../../adr/0002-idmt-v2-openiddict-authorization-layer.md): the locked
  set, the open set, the two-layer lock, the `IIdmtBuilder`, and the MFA
  fail-fast rule.
- `spike/src/Idmt.Spike.Host/Wiring/SpikeWiring.cs`: Layer 1, the last-wins
  `PostConfigure` re-clamps, and the `IStartupFilter` registration.
- `spike/src/Idmt.Spike.Host/Wiring/IdmtSelfCheckStartupFilter.cs`: Layer 2,
  the startup self-check that throws `IdmtSecurityInvariantException`.
- `spike/tests/Idmt.Spike.Tests/Gate5_SelfCheckTests.cs`: gate 5, both layers
  exercised against a hostile override.

## The locked set

These nine invariants are enforced unconditionally in `Build()`. They are
additive-only in the type system: a builder seam can layer behavior on top of
one, but no seam exposes a switch that turns one off. Each links to the doc
that designs and tests it.

1. Uniform `TenantAccess` gate, applied at token issuance for every grant and
   at every server-side support-token mint. See
   [the tenant access gate](06-tenant-access-gate.md).
2. Reference access tokens with `EnableTokenEntryValidation()` and the
   co-hosted local validation handler, so revocation is enforced per request.
   See [the OpenIddict server](04-openiddict-server.md).
3. Refresh-token rotation with reuse detection. See
   [the OpenIddict server](04-openiddict-server.md).
4. The IDMT-owned per-request audience validation handler that binds a token
   to the Finbuckle-resolved tenant. See
   [multitenancy and audience](05-multitenancy-audience.md).
5. The `SecurityStamp`-change revocation hook that drops a user's tokens on a
   credential change. See [revocation hooks](07-revocation-hooks.md).
6. The support-token TTL ceiling, which a consumer can lower but not raise. See
   [the support-token mint](08-support-token-mint.md).
7. Audited support with a required reason, written in the same transaction as
   the token-store insert. See [the support-token mint](08-support-token-mint.md).
8. A mandatory second factor for system users and for users with access to
   more than one tenant. See [MFA](12-mfa.md).
9. Cross-site request forgery protection on the backend-for-frontend session,
   whenever the session surface is enabled. See
   [browser login and the BFF](09-browser-login-bff.md).

## The open set

These are the named extension points on the builder. Each one lets you change
the shape or surface of the system without touching a locked property. Where an
open seam touches a locked one, the lock still applies: MFA factor selection,
for instance, is open, but the requirement that a system user holds a second
factor is not.

- Claims enrichment that adds claims after the `TenantAccess` gate has run.
- Tenant-resolution strategy (route, header, claim, base path, or custom).
- MFA factor selection, subject to the locked system-user requirement.
- Email transport and link generation.
- Additional authorization policies layered on the built-ins.
- Consumer endpoints mounted under the pre-attached policy groups.
- The store backend, through the `Idmt.Core` repository ports.

## The two-layer lock

The lock has two layers because C# dependency injection alone cannot stop a
consumer who deliberately re-registers options after `AddIdmt`. Layer 1 stops
accidental subtraction by running last and winning. Layer 2 turns deliberate
subtraction into a fail-fast startup error you can detect.

### Layer 1: last-wins post-configuration

`Build()` applies the locked configuration as the last-registered options
post-configuration. Options post-configuration runs after all earlier
configuration, so a customization that ran before this (through a builder hook,
or a raw `PostConfigure` registered before `AddIdmt`) cannot subtract a locked
property: the lock runs later and overwrites it. In the spike, this is two
explicit re-clamps:

```csharp
// §2.9 layer 1: last-registered post-configuration re-applies the locked
// options, so a customization that ran before this cannot subtract them.
services.PostConfigure<OpenIddictServerOptions>(o => o.UseReferenceAccessTokens = true);
services.PostConfigure<OpenIddictValidationOptions>(o => o.EnableTokenEntryValidation = true);
```

Gate 5 proves this: a hostile `PostConfigure<OpenIddictServerOptions>(o =>
o.UseReferenceAccessTokens = false)` registered before `AddIdmtSpike()` is
overridden, and the final options snapshot still reports reference tokens
enabled.

### Layer 2: startup self-check

A registration that runs after `AddIdmt` lands past Layer 1's reach, so an
`IStartupFilter` self-check reads the final resolved options snapshot at host
start and throws `IdmtSecurityInvariantException` if a locked invariant is
missing. In the spike, `IdmtSelfCheckStartupFilter` asserts
`UseReferenceAccessTokens` is on, token storage is not disabled, degraded mode
is not enabled, `EnableTokenEntryValidation` is on, and the
`TenantAudienceValidationHandler` is registered.

This layer has an honest limit. It reads a snapshot, so it catches subtraction
expressed as registration, but it cannot catch a consumer who mutates options
at resolve time, through a custom `IPostConfigureOptions` or an options
decorator that runs after the snapshot is read. The guarantee is therefore
"inadvertent subtraction is impossible, and deliberate subtraction of the
registered options fails fast and is detectable," not "subtraction is
impossible." For defense in depth, the audience and revocation invariants also
self-verify inside their own handler execution rather than relying on the
startup snapshot alone, so a resolve-time mutation that defeats Layer 2 still
meets a runtime check at the point the handler actually runs.

## The IIdmtBuilder fluent interface

Registration uses a fluent `IIdmtBuilder` rather than v1's positional delegate
parameters. Each seam is a named, discoverable method, so the locked-versus-open
line is visible in the type system: you find the open seams by reading the
builder surface, and you cannot find a method that disables a locked property,
because none exists.

This is the structural difference from v1. v1 passed configuration as
positional delegates, where the meaning of each argument lived in
documentation and a consumer could quietly hand back a delegate that turned a
security property off. The v2 builder makes the same choice impossible at the
type level: the open set is the method list, the locked set is enforced in
`Build()`, and the two never overlap in a single switch.

## MFA fail-fast rule

The second-factor requirement is a domain invariant in `Idmt.Core`, not a
feature of the opt-in `Idmt.Mfa` package: `Idmt.Mfa` supplies factor
implementations, and the core gate holds the requirement that a system user or
a multi-tenant user must satisfy a second factor before a token issues. The
fail-fast at `Build()` is scoped so a deployment pays the MFA-provider cost
only when it can actually produce a triggering user.

`Build()` throws only when all of these hold:

- MFA enforcement is on, which is the default.
- No factor provider is registered.
- Either the sys-admin surface is mapped, or multi-tenant membership is
  permitted.

A purely single-tenant app with no sys-admin surface never trips the check and
does not pay the MFA-provider tax on day one. A deployment that maps the
sys-admin surface or permits multi-tenant membership and genuinely wants single
factor must opt out explicitly. That explicit opt-out makes the
canonical-identity blast-radius risk a recorded choice rather than an accident,
which is the whole point: the dangerous configuration is reachable, but only on
purpose and only in writing.

The requirement keys on a user's tenant count, which can change after tokens
issue. Granting a second `TenantAccess` to a previously single-tenant user
crosses the one-to-many boundary and makes the second factor newly required,
which fires the [revocation hook](07-revocation-hooks.md) so the user's
existing single-factor tokens drop and the next issuance enforces the factor.

## Dependencies

This seam sits across the whole build rather than inside one component, so it
depends on the mechanisms it enforces already existing. Each locked invariant
is implemented in its own doc; the seam is what guarantees none of them can be
configured away.

- [The OpenIddict server](04-openiddict-server.md): reference tokens,
  `EnableTokenEntryValidation()`, and refresh rotation.
- [Multitenancy and audience](05-multitenancy-audience.md): the per-request
  audience handler.
- [The tenant access gate](06-tenant-access-gate.md): the uniform gate.
- [Revocation hooks](07-revocation-hooks.md): the `SecurityStamp`-change hook.
- [The support-token mint](08-support-token-mint.md): the TTL ceiling and
  audited reason.
- [Browser login and the BFF](09-browser-login-bff.md): the session CSRF
  protection.
- [MFA](12-mfa.md): the second-factor requirement and provider registration.

## Acceptance criteria

The seam is correct when gate 5 holds in both directions and the
configuration-integrity test passes in the suite.

- A hostile override registered after `AddIdmt(...)` fails the startup
  self-check with `IdmtSecurityInvariantException`, and the message names the
  subtracted property. This is `Layer2_SelfCheck_FailsHostStart_OnLaterSubtraction`
  in `spike/tests/Idmt.Spike.Tests/Gate5_SelfCheckTests.cs`.
- An earlier consumer attempt to subtract a locked property is overridden by
  Layer 1, so the final options snapshot still reports the locked value. This
  is `Layer1_LastWinsLock_ReclampsEarlierSubtraction` in the same file.
- The configuration-integrity test in the full suite registers a consumer
  post-configuration after `AddIdmt` that disables a locked property and
  asserts the startup self-check throws. See [the test
  suite](14-test-suite.md).

## Next steps

With the seam established, the open set's most visible payoff is the endpoint
scaffolding: pre-authorized route groups a consumer mounts their own endpoints
under. Continue with [endpoint scaffolding](11-endpoint-scaffolding.md).
