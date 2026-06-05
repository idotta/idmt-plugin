# Machine-client authentication

This task gives non-interactive callers, the trusted gateway devices and backend
services that have no human at the keyboard, a first-class way to authenticate
and obtain tenant-scoped tokens. You build it on the OAuth 2.0 client-credentials
grant against the OpenIddict server you already wired, so a machine caller flows
through the exact same reference-token path as every other caller. The design
decision behind this task, including why you do not build a separate token
scheme, is recorded in
[ADR-0003](../../adr/0003-machine-client-authentication.md).

This task resolves the first open question in
[`15-hardening-and-open-questions.md`](15-hardening-and-open-questions.md). It is
not a core-build blocker: the client-credentials grant is already wired in
`04-openiddict-server.md`, so this task adds the machine-client identity, the
per-tenant authorization gate, and the provisioning surface on top of a flow that
already works.

## What you build

You add the pieces that turn a registered confidential client into a managed
machine identity. The grant itself already exists; this task makes it safe and
operable.

- A confidential client registration per trusted gateway or service, with a
  client secret that is the durable credential.
- A machine-client-to-tenant authorization gate, `IClientTenantAccessGate`, the
  client analog of the `TenantAccess` gate, backed by the `ClientTenantAccess`
  entity.
- A provisioning surface on the sys-admin API that creates a client, returns its
  secret once, rotates the secret, and revokes the client.
- A machine-caller marker on the issued token (for example an `auth_type` claim)
  and the scopes a resource endpoint uses to gate machine callers.

## Source of truth

This task implements a recorded decision and reuses a proven flow, so its
authority is an ADR plus the spike, not a fresh design. Read these before you
build.

- [ADR-0003 (machine-client authentication)](../../adr/0003-machine-client-authentication.md):
  the decision, the credential model, and the reasons client-credentials wins
  over a parallel scheme.
- [ADR-0002 §2.4 and §2.6](../../adr/0002-idmt-v2-openiddict-authorization-layer.md):
  the bearer-only resource layer and the tenant audience convention this task
  reuses.
- The spike's proven client-credentials path: the confidential `spike-client` in
  `spike/src/Idmt.Spike.Host/Seeding/IdmtSpikeSeeder.cs`, and
  `AllowClientCredentialsFlow()` in
  `spike/src/Idmt.Spike.Host/Wiring/SpikeWiring.cs`. One deviation: where the
  spike passed the target tenant as a custom `tenant` form field, the product
  registers the tenant URN as an OpenIddict resource and uses the standard RFC
  8707 `resource` parameter instead (decision Ha). Do not carry the custom field
  forward.
- The reference design this models, in `preditor-cloud`:
  `src/Domain/Entities/AssetToken.cs` and
  `src/Infrastructure/Auth/AssetTokenAuthenticationHandler.cs`.

## The client-credentials flow

A machine caller authenticates with its client credentials and receives a
short-lived, tenant-audienced reference token. The flow has no human step and no
refresh token.

1. The gateway calls `/connect/token` with `grant_type=client_credentials`, its
   `client_id` and secret, and the target tenant as the RFC 8707 `resource`
   parameter `urn:idmt:tenant:{identifier}`. The tenant URN is registered as an
   OpenIddict resource (the seeder registers each tenant's URN, see
   [`13-seeding-bootstrap.md`](13-seeding-bootstrap.md)), so this is the standard
   `resource` parameter, not the spike's custom `tenant` form field. Machine
   clients do not rely on that custom field.
2. The machine-client-to-tenant gate runs at issuance and rejects the request if
   the client is not authorized for that tenant.
3. OpenIddict issues a reference access token whose audience is the tenant URN,
   carrying the client's scopes and a machine-caller marker claim.
4. The gateway presents the token as a standard `Bearer` credential. The token is
   validated per request by the reference-token store lookup
   (`EnableTokenEntryValidation()` and the co-hosted `UseLocalServer()` handler)
   and by the per-request `TenantAudienceValidationHandler`, the same path a
   human's token runs (see [`05-multitenancy-audience.md`](05-multitenancy-audience.md)).
5. When the access token nears expiry the gateway requests a new one with its
   secret. It does not hold a refresh token.

The durable credential is the client secret, not the access token. The secret
never travels as a request credential; only the short-lived opaque access token
does. That is the security gain over a model where a long-lived bearer token
rides on every request.

## The durable credential

The client secret is the long-lived credential a gateway holds, and you treat it
the way a password store treats a password. OpenIddict hashes confidential client
secrets at rest by default, so you do not store the raw value.

- Generate the secret server-side with sufficient entropy at provisioning.
- Return the raw secret exactly once, in the provisioning response, and never
  again.
- Rotate the secret on demand. Rotation invalidates the old secret and leaves
  already-issued short-lived tokens to expire or to be revoked explicitly.
- Revoke a gateway by revoking its client and its live access tokens through the
  token store.

## The machine-client-to-tenant gate

A machine token for tenant T is issued only if the client is authorized for
tenant T. The gate is `IClientTenantAccessGate`, the client analog of the
`TenantAccess` gate in [`06-tenant-access-gate.md`](06-tenant-access-gate.md),
declared in [`02-core-domain.md`](02-core-domain.md) with the signature
`Task<bool> CanAccessAsync(string clientId, string tenantIdentifier, CancellationToken ct)`.
It closes the same hole: without it, any registered client could request a token
for any tenant by varying the `resource` parameter.

You store a client-to-tenant authorization in the `ClientTenantAccess` entity
(the client analog of `TenantAccess`, with the same active and optional-expiry
shape), defined in [`02-core-domain.md`](02-core-domain.md) and persisted in the
multi-tenant application context per
[`03-persistence-and-contexts.md`](03-persistence-and-contexts.md). The gate is
the issuance gate for the client-credentials grant: it runs at the single
public-grant `ProcessSignInContext` handler in
[`06-tenant-access-gate.md`](06-tenant-access-gate.md), which routes the
client-credentials grant to `IClientTenantAccessGate` (no user subject) and
rejects denials with `context.Reject(...)`. The `preditor-cloud` handler proves
why this matters: it performs an explicit tenant-match and fails a token
presented under the wrong tenant. In v2 the audience binding plus this issuance
gate give you the same guarantee on the single validation path.

## Provisioning surface

Provisioning a gateway is a sys-admin operation, so it lives on the sys-admin API
from [`11-endpoint-scaffolding.md`](11-endpoint-scaffolding.md) under
`RequireSysAdmin`. The surface mirrors the `AssetToken` lifecycle (create,
regenerate, revoke), expressed as client management.

- Create a confidential client for a gateway, grant it the tenants it serves, and
  return its `client_id` and secret once.
- Rotate a client's secret.
- Revoke a client, which stops new token issuance and drops its live tokens.

Keep provisioning idempotent so it is safe to re-run, the same property the
seeder relies on in [`13-seeding-bootstrap.md`](13-seeding-bootstrap.md). Default
to admin-only provisioning; self-service gateway registration is not part of this
task.

## Scoping machine callers at the resource layer

Resource endpoints often need to separate machine callers from human callers, the
way `preditor-cloud` reserves measurement upload for its device-access policy.
You carry a machine-caller marker claim (for example `auth_type`) and the client's
scopes on the issued token, then gate the relevant endpoints on that claim and
those scopes through the policy surface in
[`11-endpoint-scaffolding.md`](11-endpoint-scaffolding.md).

Asset-level or device-level granularity is not IDMT's concern. IDMT scopes a
machine token to a tenant and a client identity. Any finer binding, such as the
single-asset binding the `AssetToken` model uses, belongs to the consuming
product and is expressed through scopes and claims, not through IDMT identity.

## Dependencies

This task builds on the engine, the tenant model, and the surfaces that already
exist, so complete those first.

- [`04-openiddict-server.md`](04-openiddict-server.md) for the client-credentials
  grant and the reference-token validation path.
- [`05-multitenancy-audience.md`](05-multitenancy-audience.md) for the `resource`
  parameter convention and the audience handler.
- [`06-tenant-access-gate.md`](06-tenant-access-gate.md) for the gate pattern this
  one mirrors.
- [`11-endpoint-scaffolding.md`](11-endpoint-scaffolding.md) and
  [`13-seeding-bootstrap.md`](13-seeding-bootstrap.md) for the provisioning
  surface and idempotent client registration.

## Acceptance criteria

The tests prove that a machine caller gets exactly the access it is authorized
for, on the shared path, with no parallel surface.

- A client authorized for tenant A receives a token through
  `client_credentials` with `resource=urn:idmt:tenant:A`, and that token returns
  `200` on a tenant-A route and `401` on a tenant-B route, rejected by the same
  audience handler a human's token hits.
- A client not authorized for tenant B is denied a token for tenant B at
  issuance, even with a valid secret.
- Revoking the client returns `401` on the client's next request, before the
  token's natural expiry.
- Rotating the secret invalidates the old secret for new token requests.
- The client-credentials grant issues no refresh token.

Add these to the suite in [`14-test-suite.md`](14-test-suite.md), in the same
xUnit and `WebApplicationFactory` style as the other invariant tests.

## Next steps

This task closes machine-client authentication, the first open question in
[`15-hardening-and-open-questions.md`](15-hardening-and-open-questions.md). The
remaining open questions there, the revocation backplane transport, out-of-process
resource servers, per-tenant signing keys, and the multi-factor factor timeline,
stay open and tracked.
