# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-29

Phase 1 — Canonical Identity Migration. Major version bump due to
breaking schema, API, and behavior changes. Consumers must run the
canonical identity data migration before deploying this version against
existing data. Multi-instance deployments require blue/green; rolling
restart is unsupported across the v1.x → v2.0.0 boundary.

### Breaking Changes

- `IdmtUser` is global, not per-tenant. The `TenantId` column is dropped
  from `AspNetUsers`. `GetTenantId()` returns null. The
  `(Email, UserName, TenantId)` composite unique index is replaced by a
  global unique index on `NormalizedEmail`. One identity row per human;
  cross-tenant access is gated by `TenantAccess` for every user
  (including SysAdmin) per locked decision #4.
- `IdmtDefaultRoleTypes.DefaultRoles` no longer contains `SysAdmin` or
  `SysSupport`. SysAdmin / SysSupport identities are now expressed via
  `IdmtUser.SysRole` and projected as role-string claims at sign-in.
  The string constants `IdmtDefaultRoleTypes.SysAdmin` /
  `IdmtDefaultRoleTypes.SysSupport` remain unchanged so existing
  `RequireRole` / `RequireSysAdmin` / `RequireSysUser` policies match
  without code change. Pre-existing per-tenant `AspNetRoles` rows for
  SysAdmin / SysSupport become inert after migration.
- `LoginHandler` and `TokenLoginHandler` now reject authentication when
  the credential-verified user has no active `TenantAccess` row for the
  request's resolved tenant. The check fires after
  `CheckPasswordSignInAsync` (no enumeration oracle: tenant mismatch and
  bad password share the `Auth.Unauthorized` response) and before any
  cookie or token is issued. Closes KR-1.
- `RegisterUser` now writes a `TenantAccess` row for the inviting tenant
  in the same transaction as user creation. Without this, the
  TenantAccess gate would lock newly registered users out on their next
  request.
- `CreateTenantHandler` now requires `ICurrentUserService` and inserts
  `TenantAccess(invokerUserId, newTenantId, IsActive=true)` in the same
  inner-scope transaction as default-role seeding. Boot-time seeding
  paths must use `IMultiTenantStore` + `ITenantOperationService`
  directly — the handler is fail-closed when no current user is
  resolved.
- `ConfirmEmailRequest` and `ResetPasswordRequest` no longer accept
  `TenantIdentifier` in the body. Tenant context is derived from the
  ambient request strategy. The body field is silently ignored if sent.
- `IIdmtLinkGenerator.GenerateConfirmEmailLink` /
  `GeneratePasswordResetLink` no longer embed `tenantIdentifier` as a
  query parameter in either the ServerConfirm or ClientForm branches.
  Route-based tenant strategies still inject the configured route
  token, so `/{tenant}/...` links are unaffected. Consumer SPAs that
  read `tenantIdentifier` from the link URL and echoed it back in the
  body must switch to host/path-based tenant routing.
- `ResetPassword` no longer flips `EmailConfirmed = true` as a side
  effect of a successful reset. Email confirmation must travel through
  its own confirm-email flow.
- `PUT /manage/info` no longer mutates `Email` immediately when
  `NewEmail` is set. The new address is staged in
  `IdmtUser.PendingEmail` and a confirmation link is sent to that
  address; `Email` is committed only when the recipient POSTs to
  `POST /auth/confirm-email-change` with the token. The endpoint
  returns `202 Accepted` (Location: `/auth/confirm-email-change`)
  instead of `200 OK` in this case. Existing clients that treated 200
  as success must accept 202 and surface a "check your inbox" prompt.
- `RevokeTenantAccess` revokes by canonical `UserId` only; the prior
  shadow-user deactivation path inside `ExecuteInTenantScopeAsync` is
  removed.
- `GrantTenantAccess` no longer creates shadow `IdmtUser` rows; it
  writes only `TenantAccess` plus optional `IdentityUserRole` rows in
  a single transaction.

### Added

- `Idmt.Plugin/Models/SysRoleKind.cs` — `None=0`, `SysAdmin=1`,
  `SysSupport=2`. Enum string values are deliberately equal to the
  policy strings `"SysAdmin"` / `"SysSupport"` so `RequireRole` matches
  without bridge code.
- `IdmtUser.SysRole` column on `AspNetUsers` — global system-role flag.
- `IdmtUser.PendingEmail` column on `AspNetUsers` — bare nullable
  string staging the next email until OOB confirmation.
- `POST /auth/confirm-email-change` (AllowAnonymous) — verifies the
  Identity-issued token via `ChangeEmailAsync`, atomically commits
  `Email` + `EmailConfirmed`, rotates the security stamp, and clears
  `PendingEmail`.
- `IIdmtLinkGenerator.GenerateConfirmEmailChangeLink` and
  `ApplicationOptions.ConfirmEmailChangeFormPath` (default
  `/confirm-email-change`). No `tenantIdentifier` embedded.
- `Idmt.Plugin/Migration/CanonicalIdentityDataMigrator/` — dry-run /
  apply harness with SHA-256 plan-fingerprint ack handshake. Bulk
  rewrites (`TenantAccess.UserId`, `IdmtAuditLog.UserId`,
  `IdentityUserRole`, `AspNetUserTokens`, legacy `RevokedToken`
  deletion, duplicate `IdmtUser` deletion, `SysRole` fold,
  per-survivor `SecurityStamp` rotation) run inside a single
  `BeginTransactionAsync` / `CommitAsync` block so any
  `SaveChangesAsync` failure rolls everything back.
- `tools/Idmt.Migrator` — net10.0 console host. Args:
  `--dry-run`, `--apply`,
  `--ack-dryrun-fingerprint <sha>`,
  `--accept-cross-tenant-merges <ids>`,
  `--provider {sqlite,sqlserver}`.
- New errors: `Email.NoPendingChange`, `Email.PendingMismatch`.
- `IdmtUserClaimsPrincipalFactory` emits a `SysRole` claim when the
  user's `SysRole != None` and sources the tenant claim from the
  ambient `IMultiTenantContextAccessor`. Throws
  `InvalidOperationException` if the ambient context is null
  (fail-closed, CD-4).

### Removed

- `IdmtUser.TenantId` column.
- `IsMultiTenant()` on `IdmtUser` in `IdmtDbContext`.
- The `(Email, UserName, TenantId)` composite unique index on
  `AspNetUsers`.
- Default per-tenant `SysAdmin` / `SysSupport` rows from
  `IdmtDefaultRoleTypes.DefaultRoles`.
- `tenantIdentifier` query parameter from confirm-email and
  password-reset URLs.
- `TenantIdentifier` field from `ConfirmEmailRequest` and
  `ResetPasswordRequest`.
- The `EmailConfirmed = true` side effect from `ResetPassword`.
- Shadow-user creation in `GrantTenantAccess` and shadow-user
  deactivation in `RevokeTenantAccess`.

### Migration

Required before deploying v2.0.0 against existing v1.x data. Detailed
runbook lives in `SECURITY_PHASE_1_CANONICAL_IDENTITY.md` §5 and the
v3 plan §D / §E. Short version:

1. Snapshot `Phase0SchemaSnapshot.sql` from the v1.x deployment.
2. Stop writes (blue/green cutover; rolling restart is not supported).
3. Backup the database.
4. `dotnet run --project tools/Idmt.Migrator -- --dry-run
   --provider sqlserver --connection "<conn>"`. Review the divergence
   report and capture the SHA-256 plan fingerprint plus any
   cross-tenant merge group ids.
5. `dotnet run --project tools/Idmt.Migrator -- --apply
   --ack-dryrun-fingerprint "<sha>"
   --accept-cross-tenant-merges "${ACCEPT_GROUP_IDS:-}"
   --provider sqlserver --connection "<conn>"`. Migrator refuses to
   run if the recomputed fingerprint diverges from the ack value.
6. Apply the EF schema migration that drops `IdmtUser.TenantId`, adds
   `SysRole` + `PendingEmail`, and replaces the unique index.
7. Deploy the v2.0.0 image into the green slot and cut traffic.

Audit emission during migration uses the literal sentinel TenantId
`"__migration__"` for migrator-emitted rows; query with this sentinel
to isolate migration audit traffic.

Pre-migration password-reset tokens are invalidated by the migration's
per-survivor SecurityStamp rotation. Issue fresh links if any are
in-flight.

### Security Fixes

- **Audit C3** — `ConfirmEmail` no longer trusts `TenantIdentifier`
  from the request body; tenant context is derived from the ambient
  resolver. Closes the cross-tenant confirmation oracle.
- **Audit C4** — `ResetPassword` no longer trusts request-body
  `TenantIdentifier` and no longer flips `EmailConfirmed = true` on
  success. Closes the email-confirm-via-password-reset takeover leg.
- **Audit C7** — `PUT /manage/info` stages email change in
  `PendingEmail` and routes confirmation through OOB
  `POST /auth/confirm-email-change`. An attacker holding a session
  cookie can no longer rebind `Email` to an address they control
  without proving control of the new mailbox.
- **Audit N1** — Login enforces a uniform `TenantAccess` gate (no
  SysRole short-circuit). A user with credentials in tenant A can no
  longer log in to tenant B by hitting B's login endpoint.
- **Audit N3** — `IdmtUserClaimsPrincipalFactory` is fail-closed when
  the ambient `IMultiTenantContextAccessor` is null, preventing
  silently-tenant-less principals from being constructed during
  background work.
- **Audit H7** — `IdmtLinkGenerator` no longer embeds
  `tenantIdentifier` in confirm-email or password-reset URLs;
  hardened `AddTenantRouteParameter` skips injection when a custom
  route strategy is configured under the literal name
  `"tenantIdentifier"`.

### Security Notes

- **R18 (deferred to Phase 4).** `UpdateUserInfo` dropped its
  `FindByEmailAsync` pre-check on `NewEmail` to avoid an enumeration
  oracle. The trade-off is a third-party email-spam vector when
  `PUT /manage/info` is unrate-limited. The in-plugin `RateLimiting`
  option defaults to disabled (post-`cc4ab61`); consumers must opt in
  today. Phase 4 will wire `PUT /manage/info` into a per-user
  rate-limit policy by default.
- **KR-1 / KR-2 / KR-3 (residual).** Bearer / cookie tickets minted
  before TenantAccess revocation, before migration, or against a user
  with `EmailConfirmed=false` post-merge remain valid until natural
  expiry. Phase 2 closes the bearer-revocation enforcement and refresh
  rotation gaps; tests F31, HS-10, and F38 pin the regression windows.
