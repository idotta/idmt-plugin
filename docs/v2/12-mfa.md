# Multi-factor authentication

A second authentication factor is locked for the users with the widest blast
radius: any system user, and any user who can reach more than one tenant. The
requirement lives in `Idmt.Core` as a domain invariant the seam enforces; the
factor implementations ship in the separate, opt-in `Idmt.Mfa` package. Core
enforces, the package supplies. This split keeps the WebAuthn dependency off the
main package for consumers who never enroll a user that needs a second factor,
while still making the requirement impossible to forget for the consumers who
do. This document tells you what you build, where the requirement and the
implementations divide, who the requirement covers, and how the build fails fast
when a deployment can produce a user who needs a factor but no provider exists
to satisfy it.

## What you build

You build three things, and only the first of them lives in a package you opt
into. The requirement and its enforcement hook are already in core; you do not
build those, you satisfy them.

- The `Idmt.Mfa` package, with a TOTP factor as the first implementation
  (RFC 6238, the time-based one-time password an authenticator app produces).
  This package carries the WebAuthn dependency later, so a consumer who needs
  only TOTP, or who needs no second factor at all, never pulls it.
- The core enforcement hook, which already lives in `Idmt.Core`. The uniform
  gate refuses to issue a token to a triggering user until a registered factor
  provider confirms the user satisfied a second factor. You wire a provider into
  this hook; you do not write the hook.
- The factor extension point on the builder, where you select which factor or
  factors a deployment offers. This seam is open: you choose factors. It is
  subject to the locked requirement: you cannot turn the second factor off for
  the locked user classes.

## Source of truth

The decision record is ADR 0002. Read the package boundary, the locked invariant
and its fail-fast rule, the blast-radius risk the requirement contains, and the
open question that tracks factor selection. The seam doc holds the full
statement of the fail-fast rule.

- [ADR 0002 §2.2](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#22-module-boundaries-three-packages),
  the module split, with `Idmt.Mfa` as the opt-in factor package (one of the two
  shipped packages; `Idmt.Core` is a project folded into `Idmt.AspNetCore`).
- [ADR 0002 §2.9](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#29-the-opinionated-and-customizable-seam),
  locked invariant 8 (the second-factor requirement) and the MFA fail-fast rule.
- [ADR 0002 §5.2](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#52-risk-and-mitigation),
  the canonical-identity blast-radius risk the second factor mitigates.
- [ADR 0002 §7.1](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#71-open-questions),
  the open question on factor selection and rollout timeline.
- [The opinionated-but-customizable seam](10-locked-seam.md), the full fail-fast
  rule and the two-layer lock that enforces it.

## Requirement versus implementation

The line that matters runs between the requirement and the factors that satisfy
it. The requirement is a domain rule, so it sits in core and binds every
deployment. The factors are infrastructure, so they sit in a package a
deployment adds only when it needs one.

The requirement is that a triggering user must satisfy a second factor before a
token issues. That rule is part of the `TenantAccess` gate in `Idmt.Core`,
alongside the other domain invariants, and it references no factor technology.
It does not know what TOTP is. It knows only that a registered provider must
confirm a second factor for a triggering user, and that no token issues without
that confirmation.

The confirmation happens at the interactive `/connect/authorize` step, where a
user subject is present and the provider can prompt for the factor. Once the
provider confirms, the satisfaction is recorded into the authorization, and the
issuance path reads that recorded state before it mints a token (the issuance
read lives in [the tenant-access gate](06-tenant-access-gate.md), a separate read
at the same handler, not a parameter on the gate). A pure client-credentials
grant has no user subject and no interactive authorize step, so it cannot be a
triggering user and is exempt from the second-factor requirement; only the
user-bearing grants reach this check.

The implementation is the factor itself: the TOTP secret, the enrollment flow,
the six-digit code check, and later the WebAuthn credential. All of that lives
in `Idmt.Mfa`, which references `fido2-net-lib` for the WebAuthn factor. A
consumer who registers a TOTP provider satisfies the core requirement with that
provider; a consumer who registers none, in a deployment that can produce a
triggering user, fails the build. Core enforces the rule, the package supplies
the means, and the architecture test in
[the solution and packages](01-solution-and-packages.md) keeps the package's
infrastructure types out of the domain.

## Who must have a second factor

The requirement covers exactly the two user classes whose single stolen
credential reaches the most ground. Both are defined by the canonical identity
model, not by any factor technology, so both are checkable in core before a
token issues.

- System users: any user holding an active `SysRole`. A system user can reach
  the sys-admin surface, and through a support-token mint can act inside any
  tenant, so a compromised system credential is the widest possible reach.
- Multi-tenant users: any user with more than one active `TenantAccess`. The
  canonical identity model is one row per human across all tenants, so a single
  credential for a user who belongs to several tenants unlocks all of them at
  once.

This is the containment for the blast-radius risk in
[§5.2](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#52-risk-and-mitigation).
The canonical model concentrates reach by design: one identity, one credential,
many tenants. Without a second factor, one phished password for a multi-tenant
user is one breach across every tenant that user belongs to. The second factor
breaks that chain for precisely the users where the chain is longest, and it
does so as a locked invariant so the mitigation cannot be silently absent.

A user's tenant count is not fixed. Granting a second `TenantAccess` to a
previously single-tenant user crosses the one-to-many boundary and makes the
second factor newly required. That crossing fires the
[revocation hook](07-revocation-hooks.md) for the affected user, so the user's
existing single-factor tokens drop and the next issuance enforces the factor.

## The fail-fast rule

The build fails fast only when a deployment can actually produce a triggering
user and has no provider to satisfy the requirement. This scoping means a
deployment pays the MFA-provider cost only when the requirement can bite,
and a deployment that genuinely wants single factor for the locked classes must
record that choice in writing. The full statement lives in
[the opinionated-but-customizable seam](10-locked-seam.md); the summary follows.

`Build()` throws only when all three of these hold at once:

- MFA enforcement is on, which is the default.
- No factor provider is registered.
- Either `EnableSysAdminSurface()` was called on the builder, or multi-tenant
  membership is permitted.

The trigger keys on the registration-time builder flag, not on whether a surface
is mapped. `MapIdmtSysAdminApi` runs after `Build()`, so `Build()` cannot observe
the mapping; the `EnableSysAdminSurface()` flag the builder records at
registration time is the signal `Build()` reads. (`MapIdmtSysAdminApi` in turn
asserts that the same flag was set, so the two stay in step.)

A purely single-tenant app that never calls `EnableSysAdminSurface()` can never
produce a triggering user, so it never trips the check and never pays the
MFA-provider tax on day one. The moment a deployment calls
`EnableSysAdminSurface()` or permits multi-tenant membership, it can produce a
triggering user, so the build demands either a registered provider or an explicit
opt-out.

The opt-out is deliberate friction. A deployment that calls
`EnableSysAdminSurface()` or permits multi-tenant membership and genuinely wants
single factor for the locked classes must opt out explicitly.
That explicit opt-out turns the canonical-identity blast-radius risk into a
recorded choice rather than an accident: the dangerous configuration stays
reachable, but only on purpose and only in writing.

## Factor roadmap

TOTP ships first, WebAuthn follows, and factor selection is an open seam under
the locked requirement. The roadmap matters because it explains why `Idmt.Mfa`
is a separate package: the heavier dependency arrives with the later factor, and
a consumer pulls it only when they adopt that factor.

- TOTP first. RFC 6238 time-based one-time passwords, the standard
  authenticator-app flow: the deployment provisions a shared secret, the user
  scans it into an authenticator app, and the app produces a rotating six-digit
  code the gate checks at issuance.
- WebAuthn and FIDO2 later, through `fido2-net-lib`. This is the stronger,
  phishing-resistant factor, and its dependency is exactly what `Idmt.Mfa` keeps
  off the main package. A consumer who never adopts WebAuthn never carries
  `fido2-net-lib`.
- Factor selection as a builder extension point. The seam is open, so a consumer
  chooses which factor or factors a deployment offers. The seam is subject to
  the locked requirement, so a consumer can pick factors but cannot turn the
  second factor off for system users or multi-tenant users. Open shape, locked
  security, the same rule the rest of the seam follows.

## Status and open question

This is the one area in the v2 design with no spike gate behind it, and you must
read it as net-new product work rather than a promoted spike mechanism. Being
plain about that is the point: everywhere else in these docs a locked invariant
links to the gate that proved it, and here that link does not exist for the
factor implementations.

The spike proved the enforcement seam (gate 5) and the multi-tenant model that
defines who triggers the requirement. It did not build TOTP or WebAuthn. The
hook that refuses a token without a confirmed second factor is the same locked
seam gate 5 exercised, so the enforcement path is proven; the factor
implementations that feed that hook are new work with no prior art in the spike.

The open question is which factors to ship and on what timeline. The requirement
is locked, so the question is never whether a second factor is required, only
which implementations satisfy it and when each lands. That question is tracked
in
[hardening and open questions](15-hardening-and-open-questions.md), carried from
[§7.1](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#71-open-questions).

## Dependencies

The requirement, its enforcement, and the package that supplies factors each
live in their own doc. Read them together: the requirement is a domain rule, the
enforcement is the seam, and the package is the opt-in implementation.

- [The core domain](02-core-domain.md): the second-factor requirement as a domain
  invariant, alongside `SysRole`, `TenantAccess`, and the gate.
- [The opinionated-but-customizable seam](10-locked-seam.md): the enforcement,
  the fail-fast rule, and the factor-selection extension point.
- [The solution and packages](01-solution-and-packages.md): `Idmt.Mfa` as the
  opt-in factor package and the architecture test that bounds it.

## Acceptance criteria

The requirement is correct when the build refuses an unsatisfiable
configuration and the gate refuses an unenforced token. The first criterion is
the fail-fast rule; the second is the MFA-required issuance test from
[§4](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#4-test-strategy).

- With enforcement on and no factor provider registered, a build that called
  `EnableSysAdminSurface()` or permits multi-tenant membership fails fast. A
  single-tenant build that never called `EnableSysAdminSurface()`, under the same
  provider-less configuration, builds without error.
- With a TOTP provider registered and enforcement on, a system user who has not
  enrolled a second factor is not issued a token, and neither is a multi-tenant
  user who has not enrolled one. This is the MFA-required issuance test, and it
  runs in [the test suite](14-test-suite.md).

## Next steps

The requirement and the factors are settled; the next thing a running system
needs is its first administrator and its first registrations, including how
seeding interacts with the second-factor requirement for the bootstrapped system
user. Continue with [seeding and bootstrap](13-seeding-bootstrap.md).
