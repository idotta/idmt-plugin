# ADR 0003: Machine-client authentication (trusted gateways and services)

- **Status:** Accepted
- **Date:** June 5, 2026
- **Deciders:** @idotta
- **Affects:** `idmt-plugin` (v2), downstream products with non-interactive callers (for example `preditor-cloud` trusted gateways)
- **Resolves:** [ADR-0002 §7.1](0002-idmt-v2-openiddict-authorization-layer.md#71-open-questions) open question 1, machine-client authentication

## 1. Context

ADR-0002 settled interactive login (authorization code with PKCE behind a
server-side backend-for-frontend session, proven by gate 8) but left
machine-to-machine authentication open. OAuth 2.1 removes the resource-owner
password grant, so non-interactive callers (trusted gateway devices, backend
services, batch jobs) need a first-class way to authenticate and obtain
tenant-scoped tokens. This ADR answers that open question.

The reference for what we want is the `AssetToken` model in `preditor-cloud`. In
that model a trusted gateway device holds a durable credential and uses it to
authenticate as a tenant-scoped, non-human principal. The essential properties
are worth naming, because they are the bar v2 must meet:

- An opaque random token (256 bytes of entropy, Base64-URL encoded), with no
  embedded claims.
- Hashed at rest (HMAC-SHA256 keyed with a server secret); the raw value is
  shown only once at creation.
- Validated by a per-request store lookup (hash compare, plus checks that the
  token is not revoked and not expired).
- Instant revocation by a flag, effective on the next request.
- Rotation on refresh, with a cap on active tokens per asset.
- Scoped to a tenant and an asset, with an explicit tenant-match check that
  rejects a token presented under the wrong tenant.

The model sent as a custom `Authorization: AssetToken ...` scheme, backed by a
bespoke authentication handler and its own database table.

## 2. Decision

Machine clients authenticate with the OAuth 2.0 client-credentials grant against
the existing OpenIddict server. v2 does not build a parallel opaque-token scheme.
Instead it realizes every `AssetToken` property through IDMT's existing
reference-token machinery, because that machinery already provides them.

The shape is:

- Each trusted gateway or service is a registered confidential OpenIddict client
  (a `client_id` and a client secret). The secret is the durable credential: it
  is generated server-side, hashed at rest (OpenIddict's default for confidential
  clients), shown once at provisioning, and rotatable. Rotating the secret is the
  analog of the `AssetToken` regenerate operation.
- The client authenticates at `/connect/token` with
  `grant_type=client_credentials` and the tenant carried as the RFC 8707
  `resource` parameter `urn:idmt:tenant:{identifier}`, and receives a short-lived,
  tenant-audienced reference access token.
- That access token is validated per request through the same path as every
  other token: the reference-token store lookup enforced by
  `EnableTokenEntryValidation()` and the co-hosted `UseLocalServer()` handler, the
  per-request `TenantAudienceValidationHandler` that binds the token to the
  Finbuckle-resolved tenant, and instant revocation from the token store. There
  is one validation path and one revocation story, not a second surface.
- No refresh token is issued for the client-credentials grant, which is the OAuth
  recommendation. When the access token nears expiry the client re-requests one
  with its secret.
- A machine-client-to-tenant gate is the client analog of the `TenantAccess`
  gate: a client is authorized for one or more tenants, and the gate runs at
  token issuance and rejects a client that requests a tenant it is not authorized
  for. This mirrors the `AssetToken` explicit tenant-match.
- Scopes carry capability. The issued access token carries a machine-caller
  marker (for example an `auth_type` claim or a client-type claim) and the
  client's scopes, so resource endpoints can gate machine callers separately from
  human callers. This is the analog of the `AssetToken` device-access policy with
  its `auth_type=device` claim.

## 3. Why client-credentials, not a parallel AssetToken scheme

The decision turns on the v2 thesis of a single token code path, and on the fact
that reference tokens already are what `AssetToken` is.

- A second custom scheme reintroduces the dual-path bug class that
  [ADR-0002 §2.4](0002-idmt-v2-openiddict-authorization-layer.md#24-authentication-model-bearer-only-apis)
  deliberately kills. Every credential type that validates on its own path is a
  place the paths can diverge.
- Reference tokens already provide every `AssetToken` property: an opaque value,
  server-side payload so no token data travels in a readable form, per-request
  validation, instant revocation, tenant audience binding, and audit. v2 gets
  them without new code.
- The posture is stronger than the `AssetToken` literal. The durable, long-lived
  credential (the client secret) never travels as a request credential. Only
  short-lived opaque access tokens travel on requests. In the `AssetToken` model
  the long-lived bearer token itself rides on every request for its full lifetime.
- It stays standard OAuth and OpenID Connect: a conformant discovery document,
  off-the-shelf client libraries, and no bespoke cryptography. The `AssetToken`
  model hand-rolls HMAC-SHA256 hashing and its own handler; OpenIddict's secret
  hashing and token store are vetted and maintained.
- It is already de-risked. The spike's confidential `spike-client` uses
  `AllowClientCredentialsFlow()` and the same reference-token and audience path
  (it backed the gate 7 back-channel), so the grant is proven to compose on the
  real .NET 10 and OpenIddict 7.5.0 stack.

## 4. Credential and lifetime model

The chosen model is a long-lived secret with short tokens. The mapping from the
`AssetToken` model to v2 is direct:

| AssetToken | IDMT v2 |
|---|---|
| The 256-byte opaque token the gateway holds for ~30 days | The client secret (the durable credential, hashed at rest, shown once, rotatable) |
| Custom `AssetToken` scheme and manual hash lookup | Standard `Bearer` reference token and the existing validation path |
| Manual `TenantId` match in the handler | `TenantAudienceValidationHandler` against `urn:idmt:tenant:{id}` |
| `IsRevoked` flag, instant | Token-store revocation, instant (gate 1) |
| Regenerate the token | Rotate the client secret |
| Revoke the asset's tokens | Revoke the client and its live access tokens through the store |
| Per-asset binding | Per-client identity, scoped to authorized tenants |

Provisioning a gateway registers a confidential client and returns its secret
once. Revoking a gateway revokes the client and its live tokens. Rotating the
secret invalidates the old secret while leaving already-issued short-lived tokens
to expire or be revoked explicitly.

## 5. Consequences

The positive consequences follow from reuse: provisioning, rotation, revocation,
and audit all run on the machinery v2 already builds, and machine callers share
the one validation path, the one revocation story, and the one audience model
with every other caller.

The tradeoffs are real and bounded:

- The client makes a token-endpoint round trip to refresh its short-lived access
  token. This is mitigated because the client caches its token until close to
  expiry, so the round trip is infrequent, not per request.
- A client per gateway means client registrations scale with the number of
  devices, so provisioning must be cheap and idempotent. The seeder and the
  sys-admin surface own this.
- Asset-level granularity is not IDMT's concern. IDMT scopes a machine token to a
  tenant and a client identity. Any finer asset-level scope (the `AssetToken`
  model binds to a single asset) belongs to the consuming product and is
  expressed through scopes and claims, not through IDMT identity.
- Constrained devices that cannot perform a token-endpoint round trip are out of
  scope. We chose the long-lived-secret model rather than also supporting a
  long-lived issued token. If such a device becomes a requirement, this ADR is
  the place to revisit it.

## 6. Open and deferred

The decision is settled; the following are implementation details or separate
questions, not reasons to reopen the choice:

- The storage shape of the machine-client-to-tenant authorization (a
  `ClientTenantAccess` analog of `TenantAccess`) is an implementation detail
  carried in the build task, [`docs/v2/16-machine-client-auth.md`](../docs/v2/16-machine-client-auth.md).
- Whether gateway provisioning is self-service or admin-only: the default is
  admin-only through the sys-admin surface.
- Out-of-process resource servers remain separately open in
  [ADR-0002 §7.1](0002-idmt-v2-openiddict-authorization-layer.md#71-open-questions);
  this ADR assumes the co-hosted topology that per-request revocation requires.

## 7. References

- [ADR-0002 §2.3, §2.4, §2.6, §7.1](0002-idmt-v2-openiddict-authorization-layer.md), the OpenIddict engine, the bearer-only model, the tenant audience convention, and the open question this resolves.
- `preditor-cloud` AssetToken model, the reference design: `src/Domain/Entities/AssetToken.cs`, `src/Infrastructure/Auth/AssetTokenAuthenticationHandler.cs`, `src/Application/Assets/CreateAsset.cs`, `RefreshAssetToken.cs`, `RevokeAssetToken.cs`, `src/Application/Common/OpaqueToken.cs`.
- The spike's proven client-credentials path: the confidential `spike-client` in `spike/src/Idmt.Spike.Host/Seeding/IdmtSpikeSeeder.cs` and `AllowClientCredentialsFlow()` in `spike/src/Idmt.Spike.Host/Wiring/SpikeWiring.cs`.
- The build task that implements this decision: [`docs/v2/16-machine-client-auth.md`](../docs/v2/16-machine-client-auth.md).
