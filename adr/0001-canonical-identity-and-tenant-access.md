# ADR 0001 — Canonical Identity & Tenant Access

- **Status:** Proposed — superseded in part by ADR-0002
- **Date:** 2026-04-28
- **Deciders:** @idotta
- **Affects:** `idmt-plugin`, `preditor-cloud/src/Persistence`, `preditor-cloud/src/API`
- **Supersedes:** Per-tenant `IdmtUser` shadow-row model
- **Superseded by:** ADR-0002 §2.3–2.4 (`ServerSession`, `/sys-switch`, step-up) — replaced by OpenIddict reference tokens and RFC 8693 token exchange. The canonical identity, `TenantAccess`, and `SysRole` model below remains in force.

## 1. Context

PreditorCloud is a multi-tenant IoT asset platform built on .NET 10 + Finbuckle.MultiTenant with route-based tenancy (`/api/v1/{__tenant__}/...`). Per-row tenant isolation is the agreed strategy for application entities (Asset, Unit, AssetToken, MeasurementSetup) and is **not** under review here.

Identity, however, is currently also per-row. `IdmtUser` carries a `TenantId` column, and `GrantTenantAccess.cs:117-133` creates a **shadow row** in the target tenant when granting cross-tenant access — copying `PasswordHash` and `LockoutEnd` while generating a fresh `Id` and `SecurityStamp`.

This model breaks identity coherence in multi-tenant scenarios:

| Operation | Effect today |
|-----------|-------------|
| Password rotation | Updates only the current-tenant row. Other shadow rows retain old hash. |
| `UpdateSecurityStampAsync` | Affects only the current-tenant row. |
| `TokenRevocationService.RevokeUserTokensAsync(userId, tenantId)` | Keys on the row-specific `userId`; shadow rows have different ids, so revocations never propagate. |
| Lockout state | Locked in tenant A, still active in tenant B. |
| Email change | Updates only one row → drift. |

The product intent is that **system users (SysAdmin / SysSupport) hop into any tenant**, and that regular users may belong to multiple tenants. Both use cases are served better by a canonical identity model than by shadow rows.

## 2. Decision

Adopt a **canonical-identity** model for all Identity tables, with tenant association expressed exclusively via a new `TenantAccess` aggregate. System-level capabilities are expressed via a `SysRole` aggregate orthogonal to tenants. Authorization, session storage, and account-state operations are designed for blast-radius containment commensurate with the elevated coupling that canonicalization introduces.

### 2.1 Schema changes

Drop `TenantId` from **all** Identity tables: `IdmtUser`, `IdmtRole`, `AspNetUserClaims`, `AspNetUserLogins`, `AspNetUserTokens`, `AspNetRoleClaims`. Retire `AspNetUserRoles` (its job moves to `TenantAccessRole`).

> **Superseded for `IdmtRole` by [ADR-0002 §2.7](0002-idmt-v2-openiddict-authorization-layer.md#27-canonical-identity-carried-from-adr-0001).** `IdmtRole` remains per-tenant in v2: it keeps an explicit, declared `TenantId` column (not a Finbuckle shadow column), scoped by explicit query rather than a Finbuckle tenant filter, because issuance projects role claims at the no-ambient-tenant token endpoint. See [docs/v2/03a](../docs/v2/03a-idmtdbcontext-base-class-rectification.md).

```text
IdmtUser
  Id                      uuid PK
  Email                   text UNIQUE                  (globally unique)
  NormalizedEmail         text UNIQUE
  PasswordHash            text
  SecurityStamp           text
  ConcurrencyStamp        text
  LockoutEnd              timestamptz NULL
  AccessFailedCount       int                          (see §2.5)
  EmailConfirmed          bool
  TwoFactorEnabled        bool
  PendingEmail            text NULL                    (see §2.6)
  PendingEmailExpiresAt   timestamptz NULL
  -- no TenantId

TenantAccess
  UserId                  uuid FK → IdmtUser.Id
  TenantId                text FK → TenantInfo.Identifier
  GrantedAt               timestamptz
  GrantedBy               uuid FK → IdmtUser.Id
  PRIMARY KEY (UserId, TenantId)

TenantAccessRole          (junction — replaces AspNetUserRoles)
  UserId                  uuid
  TenantId                text
  RoleName                text FK → IdmtRole.Name
  PRIMARY KEY (UserId, TenantId, RoleName)
  FOREIGN KEY (UserId, TenantId) REFERENCES TenantAccess

SysRoleAssignment         (table, not column — extensibility)
  UserId                  uuid FK → IdmtUser.Id
  SysRoleName             text                          ("SysAdmin" | "SysSupport" | future)
  GrantedAt               timestamptz
  GrantedBy               uuid FK → IdmtUser.Id
  ExpiresAt               timestamptz NULL              (optional time-bounded grants)
  PRIMARY KEY (UserId, SysRoleName)

UserLockout               (per-(user, tenant) — see §2.5)
  UserId                  uuid
  TenantId                text NULL                     (NULL = global lockout from sys-level events)
  AccessFailedCount       int
  LockoutEnd              timestamptz NULL
  PRIMARY KEY (UserId, COALESCE(TenantId, '__global__'))

ServerSession             (see §2.4)
  SessionId               uuid PK
  UserId                  uuid FK → IdmtUser.Id
  TenantId                text                          (which tenant this session is bound to)
  IsSysSession            bool                          (true for sessions minted via /sys-switch)
  CreatedAt               timestamptz
  ExpiresAt               timestamptz                   (≤15 min for IsSysSession=true)
  RevokedAt               timestamptz NULL
  ReasonClaim             text NULL                     (required for IsSysSession=true)
  IpAddress               inet
  UserAgent               text

EmailChangeAudit
  Id                      uuid PK
  UserId                  uuid
  OldEmail                text
  NewEmail                text
  Action                  text                          ("requested" | "confirmed" | "cancelled" | "expired")
  At                      timestamptz
  IpAddress               inet
```

### 2.2 Authorization model

`SysRoleAssignment` grants the **capability** to assume a per-tenant scoped session via the `/sys-switch` endpoint. It does **not** grant ambient access. Every request authorizes against `TenantAccess` for the route tenant, with one of:

- An explicit `TenantAccess(UserId, RouteTenant)` row, **or**
- An active `ServerSession` row where `IsSysSession = true AND TenantId = RouteTenant`.

```csharp
// pseudocode — applied by an authorization handler, not ad hoc
public async Task<bool> CanAccessTenantAsync(Guid userId, string routeTenant, Guid sessionId)
{
    var session = await sessions.FindAsync(sessionId);
    if (session is null || session.RevokedAt is not null || session.ExpiresAt < utcNow)
        return false;

    if (session.TenantId != routeTenant)
        return false; // cookie is scoped — no cross-tenant reuse

    if (session.IsSysSession)
    {
        await audit.LogAsync(userId, routeTenant, "SysSessionAccess", session.ReasonClaim);
        return true;
    }

    return await tenantAccess.ExistsAsync(userId, routeTenant);
}
```

Bypass **on every request** is rejected. Sys access is per-session, time-bounded, and audit-logged with a caller-supplied `Reason`.

### 2.3 Sys-switch flow

A user holding any active `SysRoleAssignment` may request elevated access to a tenant:

```
POST /api/v1/system-tenant/sys-switch
  body: { targetTenant: "acme", reason: "support ticket #1234" }
  requires: valid system-tenant cookie + step-up auth (re-prompt password or WebAuthn)
```

The endpoint:

1. Verifies the caller has a non-expired `SysRoleAssignment`.
2. Requires a step-up auth challenge completed within the last 5 minutes (tracked via `ServerSession.LastStepUpAt`).
3. Mints a new `ServerSession` row with `IsSysSession = true`, `TenantId = targetTenant`, `ExpiresAt = now + 15 min`, `ReasonClaim = req.reason`.
4. Returns `Set-Cookie: .Idmt.Application.{targetTenant}=...` (opaque session id).
5. Writes a tamper-evident audit event to an external sink (Serilog → file + forwarded; replace with append-only store before GA).

Concurrent sys-sessions are allowed (e.g., support engineer holds active sessions in three tenants simultaneously), but each is independently revocable.

### 2.4 Cookie and session model

Cookies remain **per-tenant** (`.Idmt.Application.{tenant}`, `SameSite=Strict`, `HttpOnly`, `Secure` in non-dev). The cookie payload is an **opaque session id**, not a self-contained ticket. Authorization, role membership, and SysRole status are read from the `ServerSession` + `TenantAccess` + `SysRoleAssignment` tables on every authenticated request.

Implementation: cache lookups for ~30s in `IMemoryCache` keyed by `SessionId` to bound the per-request DB cost; cache invalidated on revocation events.

This replaces the stateless ASP.NET Identity cookie model. Justification: the canonical-identity model concentrates blast radius; opaque server-side sessions enable instant revocation and per-(user, tenant) session inspection. Mature identity stacks (Auth0, Okta, Atlassian) follow this pattern for the same reason.

`UpdateSecurityStampAsync` semantics under this model: bumping `SecurityStamp` invalidates **all** `ServerSession` rows for the user. Used for password change, email change, and confirmed account compromise. Not used for tenant-access revocation (see §2.7).

### 2.5 Lockout — per-(user, tenant)

Account lockout becomes a per-(user, tenant) primitive to prevent cross-tenant denial of service. An attacker brute-forcing alice@corp through tenant A's login locks her out only of tenant A. Five failed attempts in five minutes triggers a per-tenant lockout.

A separate **global** lockout (with `TenantId = NULL`) is reserved for sys-level events: confirmed compromise, admin-initiated lock, or anomaly detection signals. Global lockout invalidates all `ServerSession` rows.

Rate limiting at the edge (per-IP, per-device fingerprint) applies in addition to per-account counters and is the first line of defense against credential-stuffing.

### 2.6 Email change — `PendingEmail` column + Identity token

Use ASP.NET Identity's `GenerateChangeEmailTokenAsync` / `ChangeEmailAsync` for cryptographic verification. Add `PendingEmail` and `PendingEmailExpiresAt` columns on `IdmtUser` for state, reservation, and UX.

Flow:

```
1. POST /api/v1/{tenant}/account/email
   - reject if `PendingEmail` or `Email` for newEmail already exists
   - token = GenerateChangeEmailTokenAsync(user, newEmail)
   - user.PendingEmail = newEmail; PendingEmailExpiresAt = now + 24h
   - send verification mail to newEmail
   - audit: requested

2. POST /api/v1/{tenant}/account/email/confirm  { token }
   - if PendingEmailExpiresAt < now → 410 Gone, clear PendingEmail
   - ChangeEmailAsync(user, PendingEmail, token) — Identity bumps SecurityStamp
   - PendingEmail = NULL; PendingEmailExpiresAt = NULL
   - audit: confirmed

3. POST /api/v1/{tenant}/account/email/cancel
   - PendingEmail = NULL; PendingEmailExpiresAt = NULL
   - audit: cancelled
```

Login during pending state continues to use the old confirmed `Email`. Background sweeper (or read-time check) clears expired `PendingEmail` to release the reservation.

Uniqueness invariant: no email may appear in `Email` OR `PendingEmail` of any row twice. Enforced via partial unique index where database supports it (Postgres) or app-layer check + retry (SQLite).

### 2.7 Tenant-access revocation

`RevokeTenantAccess(userId, tenantId)`:

1. Delete `TenantAccess` and `TenantAccessRole` rows for the pair.
2. Mark `RevokedAt = now` on every `ServerSession` row matching `(UserId, TenantId)` where `IsSysSession = false`.
3. Do **not** bump `SecurityStamp` (would kick the user from unrelated tenants).

Sys-session revocation: clearing a `SysRoleAssignment` marks `RevokedAt` on every `ServerSession` row where `IsSysSession = true AND UserId = X`. Other tenant sessions for that user (where they are a regular member) survive.

### 2.8 Discover-tenants — leak prevention

The unauthenticated `/discover-tenants?email=X` endpoint **must not** distinguish sysusers from regular users. It returns the union of:

- `TenantInfo` rows joined to `TenantAccess` rows for the user, **only**.

Sysusers see their cross-tenant inventory only via the **authenticated** `GET /api/v1/system-tenant/tenants` endpoint, accessible after they have completed login + step-up auth. This prevents email-enumeration attacks from exfiltrating the customer list.

Returned shape and response time must be identical regardless of whether the email exists or has SysRole.

### 2.9 Endpoint surface — split

Tenant-membership management (any TenantAdmin within the tenant):

- `POST   /api/v1/{tenant}/grants` — invite / grant. **Reject (409) if target user has any `SysRoleAssignment`.**
- `PATCH  /api/v1/{tenant}/grants/{userId}` — change roles.
- `DELETE /api/v1/{tenant}/grants/{userId}` — revoke (per §2.7).

Sys-user management (system-tenant, requires SysAdmin):

- `POST   /api/v1/system-tenant/sys-users` — create user with SysRole.
- `POST   /api/v1/system-tenant/sys-users/{id}/roles` — add SysRole.
- `DELETE /api/v1/system-tenant/sys-users/{id}/roles/{roleName}` — remove SysRole (revokes sys-sessions per §2.7).
- `POST   /api/v1/system-tenant/sys-switch` — mint scoped session (§2.3).

A user must not simultaneously hold `SysRoleAssignment` rows and `TenantAccess` rows. Enforced by API-layer guard on grant/sys-grant operations.

## 3. Migration plan

This is a destructive schema change. Performed pre-production while data volume is low.

### 3.1 Per-column fold rules (when consolidating shadow rows)

Group existing `IdmtUser` rows by `NormalizedEmail`. For each group, produce one canonical row:

| Column | Fold rule |
|--------|-----------|
| `Id` | New uuid generated; map old (TenantId, OldId) → NewId. |
| `PasswordHash` | Most recently changed (use `SecurityStamp` rotation timestamp if available, else fail and force reset). |
| `SecurityStamp` | New value generated; all sessions invalidated post-migration. |
| `LockoutEnd`, `AccessFailedCount` | **Most restrictive** wins (latest LockoutEnd, highest count). Active locks honored. |
| `TwoFactorEnabled` | **True if any row is true.** Never silently downgrade. |
| `EmailConfirmed` | **False if any row is false.** Force re-confirm on first login if any divergence. |
| `PhoneNumber` | Latest non-null. |

A **dry-run migration** runs first and emits a divergence report listing every email with conflicting columns. Sign-off required before destructive migration runs.

For PreditorCloud's pre-prod state: force a password reset for all users at cutover. Eliminates the `PasswordHash` ambiguity entirely.

### 3.2 Step sequence

1. Add new tables (`TenantAccess`, `TenantAccessRole`, `SysRoleAssignment`, `UserLockout`, `ServerSession`, `EmailChangeAudit`).
2. Run dry-run consolidation; review divergence report.
3. Enter maintenance window. Drop active sessions.
4. Consolidate `IdmtUser` rows; populate `TenantAccess`, `TenantAccessRole`, `SysRoleAssignment` from the old shadow-row + role tables.
5. Drop `TenantId` from Identity tables; drop `AspNetUserRoles`. (Superseded for `IdmtRole` by ADR-0002 §2.7: `IdmtRole` keeps an explicit `TenantId` column. v2 is greenfield, so this migration step does not run; see ADR-0002 §3.)
6. Force password reset email to all users.
7. Deploy new authorization stack.
8. Smoke-test §4.

## 4. Test strategy

CI must enforce the new isolation guarantees. Without these, the loss of physical-row defense-in-depth (one row per tenant) is unmitigated.

- **Cross-tenant 403 assertions.** For every Identity-adjacent endpoint, an integration test that authenticates as a user with access to tenant A and asserts 403/404 against tenant B. Generated, not hand-rolled per endpoint.
- **Route-mutation fuzzer.** A CI step that takes the OpenAPI surface, picks an authenticated session for tenant A, and mutates the `__tenant__` segment to every other known tenant, asserting 403/404. Catches accidental Finbuckle-filter bypasses.
- **Sys-session expiry test.** Mint a sys-session, wait past `ExpiresAt`, assert 401 on next request even if the cookie is still in the browser.
- **Sys-revocation propagation test.** Mint sys-sessions in tenants A, B, C; revoke `SysRoleAssignment`; assert all three sessions 401 within the cache TTL.
- **Email-reservation race test.** Two concurrent change-email requests to the same `newEmail`; assert exactly one wins and the other gets 409 before sending verification mail.
- **Lockout scope test.** Trigger per-tenant lockout in tenant A; assert login still works in tenant B for the same user.

## 5. Consequences

### 5.1 Positive

- Password rotation, security-stamp bumps, lockouts, and email changes propagate correctly across tenants by construction (single row).
- `TokenRevocationService` becomes coherent: revoke by canonical `UserId` and all sessions die.
- Shadow-row copy logic in `GrantTenantAccess.cs` is deleted; the endpoint becomes a single `INSERT INTO TenantAccess`.
- Discover-tenants becomes a one-line query against `TenantAccess`.
- Sys-user management has a dedicated endpoint surface, separated from tenant membership.
- Per-(user, tenant) lockout and per-tenant cookies preserve isolation where it matters.
- Server-side sessions enable instant revocation, audit forensics, and concurrent-session inspection.

### 5.2 Negative / risk

- **Credential blast radius increases.** A stolen `PasswordHash` grants access to all of the user's tenants. Mitigations: mandate WebAuthn or TOTP for any user with `TenantAccess` in more than one tenant; mandate WebAuthn for `SysRoleAssignment` holders; per-tenant session binding so a stolen *session* cannot port; anomaly detection on first-tenant-access-from-unfamiliar-device.
- **Defense-in-depth from physical row separation is lost.** Compensated by the §4 test strategy and consideration of database-level RLS on Identity tables (deferred — Postgres-only, evaluate when the platform commits to a single DB engine).
- **Server-side sessions add a per-request lookup cost.** Mitigated by 30s `IMemoryCache`. At expected scale (≤10⁴ concurrent sessions) this is below noise.
- **Migration is destructive.** Mitigated by pre-prod state, dry-run, forced password reset.
- **Operational complexity.** Step-up auth, sys-session TTL, and audit-log shipping add infra. Acceptable cost for a platform that ships SysAdmin capability to vendor staff.

### 5.3 Explicitly out of scope

- Database-level row security policies on Identity tables (revisit if Postgres becomes the single supported engine).
- Granular per-(sysuser, tenant) deny lists. If granular denial is needed, demote the user from SysRole to per-tenant `TenantAccess` membership.
- Same-human-multiple-identities. One email = one canonical user. Users needing distinct identities use distinct emails.

## 6. Alternatives considered

1. **Keep shadow-row model, add a "sync" service** that propagates password / stamp / lockout changes across rows. Rejected: synchronization across rows has its own race conditions and recovery semantics; the bug class is intrinsic to the model.
2. **Canonical user, but require explicit `TenantAccess` row even for sysusers** (no bypass). Rejected: contradicts "SysUsers hop into any tenant" product intent; auto-grant logic on every new-tenant creation is a recurring drift surface; sys-scoped behavior should be expressed explicitly via `SysRoleAssignment`, not duplicated as TenantAccess rows.
3. **Canonical user, ambient SysRole bypass on every request.** Rejected: 1990s root-account anti-pattern; one stolen sysuser cookie compromises the entire platform with no time bound; matches the shape of the Okta October 2023 incident.
4. **Stateless ASP.NET Identity cookies** (no `ServerSession` table). Rejected: sysrole revocation gap (a revoked sysuser's existing cookies remain valid until expiry) is unacceptable for an admin platform.
5. **`TenantAccess.Roles[]` as array column** instead of `TenantAccessRole` junction. Rejected: breaks referential integrity, complicates role rename, and re-introduces the "string column with structure" smell that AspNetUserRoles existed to solve.
6. **`SysRole` as nullable column** on `IdmtUser` instead of `SysRoleAssignment` table. Rejected: a future "SysBilling" or "SysAuditor" role triggers a schema migration; expressing as a join table keeps the catalog open.
7. **Pending-email change in a separate `PendingEmailChange` table**. Rejected for current scope: one-pending-at-a-time semantics fit a column. Revisit if multi-channel verification (verify both old and new) becomes a requirement.

## 7. Open questions

- Audit log destination: Serilog file + forwarder is sufficient short-term. Long-term sink (S3 with object-lock, dedicated SIEM, immutable PG table) is unresolved.
- WebAuthn enforcement timeline. Recommended at GA for any user with `TenantAccess` in >1 tenant and unconditionally for `SysRoleAssignment` holders. Implementation is non-trivial; track separately.
- Anomaly detection for first-tenant-access-from-unfamiliar-device. Out of scope for this ADR; raise as a follow-on once observability is in place.

## 8. References

- `idmt-plugin/src/.../GrantTenantAccess.cs:117-133` — current shadow-row implementation.
- `preditor-cloud/src/Persistence/Configuration/AssetTokenConfiguration.cs` — example per-row tenant config pattern (retained for app entities).
- CLAUDE.md §"Auth Flow" — current login flow.
- Okta October 2023 security incident — root-account model failure mode (cited as anti-pattern, not as direct precedent).
- ASP.NET Core Identity — `UserManager.GenerateChangeEmailTokenAsync` / `ChangeEmailAsync`.
- Finbuckle.MultiTenant — `IsMultiTenant()` is **not** applied to any IDMT Identity table under this design (including `IdmtRole`, whose tenant scoping is an explicit `TenantId` column queried explicitly). `IdmtDbContext` implements `IMultiTenantDbContext` so that `IsMultiTenant()` remains available to consumers for their own application entities; see [docs/v2/03a](../docs/v2/03a-idmtdbcontext-base-class-rectification.md).
