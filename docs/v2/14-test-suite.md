# The CI-gated test suite

Every locked invariant has a CI-gated test, and the suite is the proof that the
decisions in [ADR 0002 §2.9](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#29-the-opinionated-and-customizable-seam)
are real rather than aspirational. The spike already demonstrated eight of these
mechanisms end to end across its gates; this doc promotes those gates into the
product test suite and adds the remaining [§4](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#4-test-strategy)
tests the spike did not cover. The bottom line: a locked security property that
no test enforces is not locked, so each entry in §4 maps to at least one
failing-on-regression test, and the architecture fitness test fails the build
outright if `Idmt.Core` ever gains an infrastructure reference.

This is a test matrix, not a tutorial. The centerpiece is a table that maps each
§4 test to what it asserts and to the spike gate that already demonstrated the
mechanism, so you can see at a glance which tests are promoted from the spike and
which are net-new.

## What you build

You build two things: one architecture fitness test that runs as a unit test,
and an integration test matrix in the existing xUnit and `WebApplicationFactory`
style. Together they cover every locked invariant in §2.9 and every test listed
in §4.

The architecture fitness test lives in `Idmt.Architecture.Tests` and asserts the
§2.2 dependency rule: `Idmt.Core` references no infrastructure assembly (no
OpenIddict, no Finbuckle, no Entity Framework Core, no ASP.NET Core). This is the
fitness function described in [the solution and packages doc](01-solution-and-packages.md),
and it is the one test in the suite with no spike gate, because it guards a
compile-time boundary rather than a runtime mechanism. It fails the build the
moment a domain type reaches for a vendor type.

The integration matrix runs each remaining invariant against the configured
handlers, not against mocks. You authenticate a client for a tenant, exercise the
real OpenIddict pipeline and the real IDMT-owned audience handler, and assert the
status code or store state the invariant demands. The tests follow the
conventions already in `tests/Idmt.BasicSample.Tests/` and `tests/Idmt.UnitTests/`,
described under [test conventions](#test-conventions) below.

## Source of truth

The authority for this suite is ADR 0002 §4, the eight spike gate test files that
proved the mechanisms, and the existing `tests/` projects whose conventions the
suite matches. Read the ADR section first, then the gate files for the
gate-to-test mapping.

- [ADR 0002 §4, the test strategy](../../adr/0002-idmt-v2-openiddict-authorization-layer.md#4-test-strategy):
  the full list of mandatory CI-gated tests, with one entry per locked invariant.
- The eight spike gate test files, which demonstrate each mechanism against real
  infrastructure:
  - `spike/tests/Idmt.Spike.Tests/Gate1_ReferenceTokenRevocationTests.cs`
  - `spike/tests/Idmt.Spike.Tests/Gate2_TokenExchangeAuditAtomicityTests.cs`
  - `spike/tests/Idmt.Spike.Tests/Gate3_AudienceHandlerTests.cs`
  - `spike/tests/Idmt.Spike.Tests/Gate4_DualContextCompositionTests.cs`
  - `spike/tests/Idmt.Spike.Tests/Gate5_SelfCheckTests.cs`
  - `spike/tests/Idmt.Spike.Tests/Gate6_SecurityStampRevocationTests.cs`
  - `spike/tests/Idmt.Spike.Tests/Gate7_BffSessionTests.cs`
  - `spike/tests/Idmt.Spike.Tests/Gate8_AuthCodePkceTests.cs`
- The existing test projects, whose style the product suite matches:
  `tests/Idmt.BasicSample.Tests/` (integration, `IdmtApiFactory`) and
  `tests/Idmt.UnitTests/` (focused unit tests).

## The invariant test matrix

Each row is one §4 test. The `What it asserts` column states the observable
behavior the test pins, the `ADR §4 item` column names the §4 bullet, and the
`Spike gate` column names the gate that already demonstrated the mechanism (or
notes that the test is net-new). Tests that share a mechanism with a gate but
extend it are noted in the gate column.

| Test | What it asserts | ADR §4 item | Spike gate |
|---|---|---|---|
| Architecture fitness | `Idmt.Core` references zero infrastructure assemblies; vendor types appear only in their owning folder. | Architecture fitness function | None (the §2.2 fitness function; see [solution and packages](01-solution-and-packages.md)) |
| Route-mutation fuzzer | Authenticate for tenant A, mutate the route segment to every other known tenant, and assert 403 or 401 from the real audience handler. | Route-mutation fuzzer | Gate 3 (audience handler) |
| `TenantAccess` gate, parametric | For every grant type, including refresh, plus the server-side support mint, a user with no or expired `TenantAccess` is denied a token. | `TenantAccess` gate, parametric | Gates 2 and 6 |
| Reference-token instant revocation | Mint a token, revoke it, and assert the next request returns 401 before the token's TTL expires, against the configured handler. | Reference-token instant revocation | Gate 1 |
| Refresh reuse detection | Rotate a refresh token, replay the consumed one, and assert rejection plus token-family revocation. | Refresh reuse detection | None (OpenIddict built-in; no dedicated gate, net-new product test) |
| Cross-grant audience isolation | Present a tenant-A refresh token at `/connect/token` resolving tenant B, and assert rejection. | Cross-grant audience isolation | Gate 3 family (audience binding) |
| Support audit atomicity | Force an audit-write failure during a support mint and assert neither the token nor the audit row survives (shared transaction rolls back). | Support audit atomicity | Gate 2 |
| Support TTL cap | Request a lifetime above the ceiling and assert the issued token expires at or below the ceiling. | Support TTL cap | None (net-new product test) |
| Cross-tenant token rejection | Use a tenant-A token against a tenant-B route and assert 401 from the audience handler. | Cross-tenant token rejection | Gate 3 |
| `SecurityStamp` propagation | Rotate a user's `SecurityStamp` and assert all of that user's reference tokens return 401 on the next request. | `SecurityStamp` propagation | Gate 6 |
| MFA-required issuance | With enforcement on, assert no token issues for a system user or a multi-tenant user that has not satisfied a second factor. | MFA-required issuance | None (net-new; see [MFA](12-mfa.md)) |
| Authorize-cookie tenant isolation | Assert an authorize-endpoint sign-in cookie minted for tenant A cannot be replayed against tenant B. | Authorize-cookie tenant isolation | Gate 8 family (interactive authorize session) |
| BFF session isolation | Assert a tenant-A session cookie cannot drive a tenant-B request, and that it resolves through the same audience handler a raw bearer uses (no second validation path). | Backend-for-frontend session isolation | Gate 7 |
| BFF CSRF | With the session surface enabled, assert a cross-site request carrying the session cookie but no anti-forgery token is rejected. | Backend-for-frontend CSRF | Gate 7 |
| No token in the browser | Assert the SPA login response sets only the `httpOnly` session cookie and returns no access or refresh token. | No token in the browser | Gates 7 and 8 |
| Configuration integrity | Register a consumer post-configuration after `AddIdmt` that disables a locked property, and assert the startup self-check throws. | Configuration integrity | Gate 5 |
| OAuth 2.1 posture | Assert the resource-owner password grant is not configured or exposed. | OAuth 2.1 posture | None (net-new; assertion of absence) |

## Promoted from the spike

The eight spike gates map directly into product tests, so promotion is mostly a
relocation rather than a rewrite. Gate 1 becomes the reference-token instant
revocation test, gate 2 becomes the support audit atomicity test and one arm of
the parametric `TenantAccess` gate, gate 3 becomes the cross-tenant rejection and
route-mutation fuzzer and seeds the cross-grant audience-isolation test, gate 4's
dual-context composition underpins the whole token-store layer the matrix
exercises, gate 5 becomes the configuration integrity test, gate 6 becomes the
`SecurityStamp` propagation test and the second arm of the parametric gate, and
gates 7 and 8 become the BFF session isolation, BFF CSRF, no-token-in-the-browser,
and authorize-cookie isolation tests. Each gate already ran against real
OpenIddict, Finbuckle, and SQLite, so the product test inherits a proven
mechanism and changes only the host wiring and the seed data.

## Net-new tests not covered by the spike

Five tests are net-new because the spike did not exercise their mechanism, and
each is a product test you build from scratch rather than a promoted gate. The
MFA-required issuance test asserts that no token issues for a system user or a
multi-tenant user without a second factor; it is net-new because the spike never
wired an MFA provider, and its behavior is described in [the MFA doc](12-mfa.md).
The support TTL cap test asserts a requested lifetime above the ceiling is
clamped, which the spike's support mint did not assert. The refresh reuse
detection test promotes an OpenIddict built-in into an explicit product test, so
a future configuration change cannot silently disable rotation without failing
CI. The OAuth 2.1 posture test asserts the absence of the password grant, which
no gate covered because the spike never registered the grant to begin with.
Finally, the real cross-site `SameSite` redirect is out of scope here: the spike
ran the BFF flow in-process, so a genuine cross-site redirect is deferred to
[hardening and open questions](15-hardening-and-open-questions.md) and is not a
gate in this suite.

## Test conventions

The suite matches the conventions already established in `tests/`, so a reader of
the existing tests reads the new ones without context-switching. You write xUnit
tests, you host the app through a `WebApplicationFactory` derivative, and you run
against the configured handlers rather than mocks.

The integration tests use an `IdmtApiFactory`-style `WebApplicationFactory<Program>`
that boots the real composition root, the same pattern as
`tests/Idmt.BasicSample.Tests/IdmtApiFactory.cs`. Persistence runs against an
in-memory SQLite connection shared across the contexts, and the factory seeds
test tenants, a test client, and a seeded system administrator on startup, the
same shape the spike's `BaseSpikeIntegrationTest` and the existing factory both
use. You authenticate a client for a tenant, then assert against the real
OpenIddict pipeline and the real IDMT-owned audience and revocation handlers. The
revocation, audience, atomicity, and self-check tests in particular must run
against the configured handlers, not a mocked store, because the invariant they
guard is precisely that the wired-up handler behaves correctly. The architecture
fitness test is the one exception to the integration pattern: it is a plain unit
test that reflects over assembly references and needs no host.

## Dependencies

This task validates the whole build rather than a single seam, so it depends on
every other piece of v2 being wired correctly. The locked behavior it asserts is
applied inside `Build()`, described in [the locked seam doc](10-locked-seam.md),
and the suite is the enforcement arm of that seam: the seam locks the invariants,
and these tests prove the lock holds. Because the suite gates CI, it runs
continuously on every merge, not once at the end of the build. A regression in
any seam surfaces as a red test the moment the offending change lands, which is
the point of gating merges on the matrix rather than running it as a release
checklist.

## Acceptance criteria

The suite is done when three conditions hold together, and each is checkable in
CI rather than by inspection.

- The suite is CI-gated: a merge is blocked when any test in the matrix fails.
- Every locked §2.9 invariant has at least one test that fails on regression, so
  subtracting a security property cannot pass CI green.
- The architecture fitness test fails the build if `Idmt.Core` gains an
  infrastructure reference, making the §2.2 boundary a compile-and-test guarantee
  rather than a code-review habit.

## Next steps

The deferred items this suite does not cover (the real cross-site `SameSite`
redirect, the scale-out revocation backplane, and the remaining open questions)
are tracked in [hardening and open questions](15-hardening-and-open-questions.md).
Read it next to see what stays open after the matrix is green.
