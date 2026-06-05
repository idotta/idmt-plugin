# IDMT v2 planning review: findings and decisions tracker

This tracker captures a pre-implementation review of the v2 build playbook
(`docs/v2/00-overview.md` through `16-machine-client-auth.md`) plus ADR 0002 and
ADR 0003. Three specialist reviews fed it: an architecture lens, a
.NET/framework-API feasibility lens (verified against the checked-in spike at
`spike/`), and a C# code-level lens.

The review found the thesis sound ("own the policy, rent the protocol") with no
redesign required. The work below is about making prose-level guarantees concrete
and reconciling places where the docs claim the spike proved more than it did.

All cross-fork decisions are made (see the decision log). What remains is the
doc-edit work listed under each finding.

## Status

The doc edits for all 27 findings have been applied across the v2 playbook
(`00` through `16`). The checklists below describe those edits. Two kinds of
checklist item are written into the docs as commitments but are NOT yet executed
as code, because they are implementation and test work the playbook now prescribes
rather than doc edits:

- The OpenIddict 7.5.0 confirmation in F2 (that `CreateAsync` with a
  principal-bearing descriptor yields a presentable reference handle) is a build
  step to perform during implementation; the doc now prescribes the principal
  approach and the end-to-end acceptance criterion.
- The CI tests in F2, F4, F12, F20, and the ordering-regression guard are now
  specified as planned matrix rows in `14-test-suite.md`; writing the test code is
  implementation work.

Everything else (contradictions resolved, types and ports defined, package and
middleware wiring stated, invariants reclassified) is now in the docs.

## How to use this tracker

Each finding has an ID, the reviewer source, the affected docs, the decision, and
a checklist of concrete edits. Work top to bottom by tier. Check items as the
owning doc is edited. A finding is done when every box under it is checked and the
affected docs no longer contradict the decision.

## Decision log

| # | Topic | Decision |
|---|-------|----------|
| 1 | Core infrastructure dependency | Accept ASP.NET Core Identity in `Idmt.Core`. `IdmtUser : IdentityUser<Guid>` and `IdmtRole : IdentityRole<Guid>` stay. Fitness deny-list carves out Identity abstractions (`Microsoft.Extensions.Identity.Stores`, `Microsoft.AspNetCore.Identity`) but keeps denying `Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore`, `OpenIddict`, and `Finbuckle`. |
| 2 | Support-token mint mechanism | 2a. Mint via `CreateAsync` with a `ClaimsPrincipal` on `descriptor.Principal` that carries audiences and destinations (the descriptor has no `Audiences` field). Prove end to end (present minted token then 200, revoke then 401) before promoting. Keep audit atomicity in the same transaction. |
| 3 | How `Build()` learns a surface is enabled | 3a. Registration-time builder opt-in flags (`EnableSysAdminSurface()`, `EnableBffSession()`). `Build()` reads the flags; `MapIdmt*` asserts the matching flag was set. |
| 4 | Public-grant gate denial mechanism | 4a. A single OpenIddict server event handler on the sign-in path calls the gate and uses `context.Reject(...)` so denials are OAuth-compliant. Covers every grant uniformly. |
| 7 | App EF context split | 7a. Physical context split as the spike proved it. Do not consolidate into one `MultiTenantDbContext`. |
| 9 | Tenant-member / manager policy backing | 9a. Project the user's `IdmtRole` assignments for the resolved tenant as role claims at issuance (access-token destination). `RequireTenantManager` maps to a designated manager role; `RequireTenantMember` requires presence of any projected tenant-role claim for the resolved tenant (not just "authenticated", which the audience handler already enforces). Consumers extend via a delegate hook on the builder (`WithAccessTokenClaims(...)`), not a named interface. |
| MFA | Enforcement point (invariant 8) | Ga. Confirm the second factor at interactive `/connect/authorize`, record satisfaction into the authorization, and read it at issuance. Pure client-credentials (no user subject) is exempt. |
| SecStamp | Revocation hook interception (invariant 5) | Fa. Custom `UserManager<IdmtUser>` override on the credential-change paths fires the revoke. Add a dedicated test because the startup self-check cannot observe the override. |
| resource | Tenant binding parameter | Ha. Register the tenant URN as an OpenIddict resource and use the standard RFC 8707 `resource` parameter. Drop the spike's custom `tenant` form field. |
| tenant store | Tenant metadata persistence | Ia. A dedicated third EF context for the tenant store. Update the "two EF contexts" headline to three. |
| 18 | Repository ports | Drop `IUserRepository` and `ITenantAccessRepository`. Repository-over-EF-Core is redundant (`DbContext`/`DbSet`/`UserManager` are already the abstractions) and nothing in Core called them. Keep only the gate service ports and the clock port. |
| 19 | Core project vs package | `Idmt.Core` stays a separate project (so the assembly-level engine-isolation fitness test stays trivial) but is no longer a shipped package: no consumer references the domain without the host. Its assembly is folded into the `Idmt.AspNetCore` package via `BuildOutputInPackage`. `Idmt.Mfa` references the `Idmt.AspNetCore` package (carrying Core transitively), not Core directly, so the domain assembly ships in exactly one place. v2 ships two packages, not three. |

Open sub-item: the manager role name for 9a. Default is to add `Manager` to
`IdmtDefaultRoleTypes.DefaultRoles` and map `RequireTenantManager` to it. Confirm
or override at edit time.

## Tier 1 blockers

### F1. Core takes the Identity dependency (decided #1)

Source: architecture, C#. Docs: `02-core-domain.md`, `01-solution-and-packages.md`, `14-test-suite.md`.

Resolves the POCO-versus-`IdentityUser` contradiction and unblocks every
`UserManager`/`SignInManager` flow (seeder, hooks).

- [ ] `02`: keep the `IdmtUser : IdentityUser<Guid>` and `IdmtRole : IdentityRole<Guid>` sketch; remove the POCO-pure recommendation text and the "implementer records the choice" hedge.
- [ ] `01`: change the fitness deny-list to allow `Microsoft.Extensions.Identity.Stores` and `Microsoft.AspNetCore.Identity` while still denying `Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore`, `OpenIddict*`, and `Finbuckle*`.
- [ ] `14`: confirm the fitness test asserts the carve-out (the allowed Identity abstraction assemblies are not flagged, the denied infrastructure ones still are).

### F2. Support-token mint must yield a validatable token (decided 2a)

Source: framework (verified against `spike/src/Idmt.Spike.Host/Server/UserTokenMint.cs` and `SupportTokenService.cs`). Docs: `08-support-token-mint.md`, `06-tenant-access-gate.md`.

The spike mint creates a store row that is explicitly not bearer-validatable and
sets no audience. Doc 08's premise (an ordinary reference token on the same
validation path) is not what the spike proved.

Correction (from tracker validation): `OpenIddictTokenDescriptor` has no
`Audiences` property. Audiences and destinations live on a `ClaimsPrincipal`
(`SetAudiences`, `SetDestinations`), which is what the spike's public-grant path
already does (`Program.cs`: `identity.SetAudiences(TenantUrns.For(tenant))`). The
mint must build that principal and assign it to `descriptor.Principal`.

- [ ] `08`: specify the mint builds a `ClaimsPrincipal`, calls `SetAudiences(TenantUrns.For(tenantIdentifier))` and `SetDestinations(_ => [Destinations.AccessToken])` on the identity, and assigns it to `descriptor.Principal` before `CreateAsync`. Do not reference a descriptor `Audiences` field.
- [ ] `08`: state that the audit row write stays in the same owned transaction as the token insert (atomicity preserved).
- [ ] `14`: the acceptance criterion is end to end, not a descriptor-field check: present a minted support token to a tenant-scoped route (expect 200), revoke it, re-present (expect 401). Do not mark invariant 7 proven until this passes.
- [ ] Confirm against OpenIddict 7.5.0 that `CreateAsync` with a principal-bearing descriptor yields a presentable reference handle; if not, fall back to a server-side sign-in capture and re-prove atomicity.

### F3. `Build()` cannot observe surface mapping; use builder flags (decided 3a)

Source: architecture, framework, C#. Docs: `10-locked-seam.md`, `11-endpoint-scaffolding.md`, `12-mfa.md`.

`MapIdmtSysAdminApi` and the BFF mapping run after `Build()`, so the MFA
(invariant 8) and CSRF (invariant 9) fail-fast cannot key on them as written.

- [ ] `10`: add `EnableSysAdminSurface()` and `EnableBffSession()` to `IIdmtBuilder`; `Build()` reads these flags to drive the MFA and CSRF fail-fast.
- [ ] `11`: `MapIdmtSysAdminApi` asserts `EnableSysAdminSurface()` was called; the BFF mapping asserts `EnableBffSession()`.
- [ ] `12`: restate the MFA fail-fast trigger in terms of the builder flag plus multi-tenant-membership permission, not "surface mapped."

### F4. Public-grant gate wiring via a server event handler (decided 4a)

Source: framework (verified `spike/.../Program.cs` token handler never calls the gate). Docs: `06-tenant-access-gate.md`, `16-machine-client-auth.md`.

Invariant 1 ("gate at every grant") is cited as proven by gates 2 and 6, which
prove only the server-side mint, not any public grant.

- [ ] `06`: specify a single `IOpenIddictServerHandler<ProcessSignInContext>` (fires after grant-specific handling, once a principal is established, for all three grants) that calls the gate and rejects with `context.Reject(...)`.
- [ ] `06`: for refresh, read the original `aud` from the decrypted presented token and re-run the gate against that tenant.
- [ ] `06`: reconcile the client-credentials path with F-ClientGate: a pure machine token with no user subject uses the client-to-tenant gate (`IClientTenantAccessGate`), not the user gate. Remove the "out of scope" wording that leaves the machine path ungated.
- [ ] `14`: add parametric gate-denial tests for auth-code, refresh, and client-credentials. Stop citing invariant 1 as proven until these pass.

## Tier 2 blockers (undefined types and contradictions)

### F5. Define `IIdmtBuilder`

Source: C#. Docs: `10-locked-seam.md`, `01-solution-and-packages.md`.

The type the whole locked-but-customizable guarantee rests on has no declared
surface.

- [ ] `10`: sketch `IIdmtBuilder`. Open seams are fluent methods returning `IIdmtBuilder` (including `EnableSysAdminSurface`, `EnableBffSession`, claims-enricher registration, tenant-resolution strategy, email transport). Locked invariants are deliberately absent as methods (no subtraction API).
- [ ] `10`: declare `Build()` return type (`IServiceCollection`) and how `AddIdmt<TDbContext>()` produces the builder.

### F6. Fix `SupportAudit` table placement contradiction

Source: architecture. Docs: `03-persistence-and-contexts.md`, `08-support-token-mint.md`, `02-core-domain.md`.

Doc 03 lists the audit table under `IdmtDbContext`; doc 08 requires it in the
OpenIddict context for transaction enlistment. Invariant 7 depends on 08.

- [ ] `03`: remove `SupportAudit` from the `IdmtDbContext` table list; state it is owned by the OpenIddict context migration history for atomicity.
- [ ] `08`: keep the unconditional OpenIddict-context placement as authoritative.

### F7. Resolve one-versus-two app context; adopt physical split (decided 7a)

Source: architecture, framework. Docs: `03-persistence-and-contexts.md`.

The spike proof only holds for the split (the gate queries `TenantAccess` by
`(userId, tenantId)` with no ambient tenant).

- [ ] `03`: state the product ships the physical context split, not a "conceptually consolidated" `IdmtDbContext`. Name the contexts honestly.
- [ ] `03`: with the tenant store (F-TenantStore) this is three contexts. Update any "two EF contexts" claim here and in `00-overview.md`.
- [ ] `03`: add per-context `MigrationsHistoryTable` (or schema) so the histories do not collide in a shared database. Note the spike used separate connections and did not exercise the shared-DB case.

### F8. Split the nine invariants by enforcement class

Source: architecture. Docs: `00-overview.md`, `10-locked-seam.md`.

Only the options-flag invariants are caught by the `Build()` last-wins plus
snapshot self-check. The rest are guaranteed structurally (no disable API plus
IDMT-owned call site plus a CI test), which is a different guarantee.

- [ ] `10`: split the list into class A (snapshot-enforced options flags: reference tokens, token-entry validation, refresh rotation, audience handler registration) and class B (structurally locked: uniform gate, TTL ceiling, atomic audit, MFA, CSRF).
- [ ] `10`: state the self-check covers class A and that class B is guaranteed by the absence of a subtraction seam plus the test suite.
- [ ] `00`: correct the claim that all nine are enforced in `Build()`.

### F9. Tenant policies: project `IdmtRole` claims at issuance (decided 9a)

Source: architecture, C#. Docs: `02-core-domain.md`, `06-tenant-access-gate.md`, `11-endpoint-scaffolding.md`.

`RequireTenantManager` and `RequireTenantMember` have no specified claim source.
`SupportSession` conflates an authorization policy with a handler claims check.

- [ ] `06`: at issuance, project the user's `IdmtRole` assignments for the resolved tenant as role claims with access-token destinations.
- [ ] `02`: define `RequireTenantManager` as `RequireRole(<manager role>)` and `RequireTenantMember` as requiring at least one projected tenant-role claim for the resolved tenant. Do not define it as merely authenticated plus audience-bound (the audience handler already enforces that, so it would be redundant). Add the manager role to `IdmtDefaultRoleTypes.DefaultRoles` (default name `Manager`).
- [ ] `10`: expose the existing open-set claims-enrichment point as a delegate hook on `IIdmtBuilder` (e.g. `WithAccessTokenClaims(Action<ClaimsPrincipal, ProcessSignInContext>)`), called after IDMT writes its locked claims. Do not introduce a named `IIdmtTokenClaimsEnricher` interface for first ship. Note custom claims must set destinations and that claims are snapshot-at-issuance for reference tokens; live eval needs a per-request handler.
- [ ] `11`/`02`: clarify `SupportSession` is a claims-inspection helper read inside a handler, not a gating authorization policy. Stop listing it beside the gating policies as interchangeable.

## Tier 3 gaps (production wiring the in-process spike skipped)

### F10. Data Protection key persistence

Source: framework. Docs: `09-browser-login-bff.md`, `01-solution-and-packages.md`.

The BFF session, anti-forgery, and login cookies all depend on a shared,
persisted key ring; the default ephemeral ring causes silent random logout across
instances.

- [ ] `09`: require a persisted, shared Data Protection key ring (database or key vault).
- [ ] `01`: add the Data Protection persistence package.

### F11. CORS for the SPA

Source: framework. Docs: `09-browser-login-bff.md`.

- [ ] `09`: add a CORS section (allowed origins from config, `AllowCredentials` for the cookie, placement before `UseAuthentication`). Pair it with the deferred cross-site `SameSite` redirect test in `15`.

### F12. SecurityStamp revocation hook interception (decided Fa)

Source: framework, C#. Docs: `07-revocation-hooks.md`.

Identity has no built-in "stamp changed" event; the spike hook is wired only from
its test.

- [ ] `07`: specify a custom `UserManager<IdmtUser>` override on `UpdateSecurityStampAsync`, password change, email change, and deactivation that fires the revoke. It is the single chokepoint credential changes funnel through.
- [ ] `14`: add a test that the override fires the revoke, since the self-check cannot see the override is installed.

### F13. MFA enforcement point (decided Ga)

Source: framework, architecture. Docs: `12-mfa.md`, `06-tenant-access-gate.md`, `09-browser-login-bff.md`.

- [ ] `12`/`09`: confirm the second factor at interactive `/connect/authorize`, record satisfaction into the authorization.
- [ ] `06`: read the recorded factor state at issuance for the user grants. Exempt pure client-credentials (no user subject).
- [ ] `06`/`02`: keep the `TenantAccess` gate a synchronous `(userId, tenant)` decision; the MFA check is a separate read at the same handler, not a parameter on the gate.

### F14. Middleware order

Source: framework. Docs: `09-browser-login-bff.md`, `05-multitenancy-audience.md`.

- [ ] `09`: add a definitive order: exception handler, security headers, CORS, rate limiter (global), `UseMultiTenant`, BFF session resolver, `UseAuthentication`, `UseAuthorization`. Default global rate limiting before tenant resolution; note the per-tenant-limiter alternative resolves after routing.

### F15. Protocol endpoints versus the audience handler

Source: framework. Docs: `05-multitenancy-audience.md`.

`TenantAudienceValidationHandler` rejects any authenticated request with no
resolved tenant, which would break `/connect/introspect`, `/connect/revoke`, and
`/connect/userinfo`.

- [ ] `05`: scope the audience handler to resource APIs, not OpenIddict's own protocol endpoints.

### F16. Package references

Source: framework. Docs: `01-solution-and-packages.md`.

- [ ] `01`: add concrete `PackageReference` entries with versions for `Idmt.AspNetCore` (OpenIddict.AspNetCore, OpenIddict.EntityFrameworkCore, Finbuckle.MultiTenant.AspNetCore, Finbuckle.MultiTenant.EntityFrameworkCore, Finbuckle.MultiTenant.Identity.EntityFrameworkCore, Microsoft.AspNetCore.Identity.EntityFrameworkCore, the Data Protection persistence package) and `Idmt.Mfa` (a TOTP source now, fido2-net-lib later), matching the spike pins.

## Tier 4 smaller gaps and risks

### F17. resource parameter convention (decided Ha)

Source: framework. Docs: `05-multitenancy-audience.md`, `16-machine-client-auth.md`.

- [ ] `05`/`16`: register the tenant URN as an OpenIddict resource and use the standard RFC 8707 `resource` parameter. Remove the spike's custom `tenant` form-field approach.
- [ ] `13`: the seeder registers each tenant's URN as a resource.

### F18. Drop the repository ports; keep only gate service ports

Source: C#, plus a follow-up architecture decision (decision 18 below). Docs: `02-core-domain.md`, `01-solution-and-packages.md`, `08-support-token-mint.md`.

Superseded the original "type every port" item. Repository-over-EF-Core is a
redundant abstraction (`DbContext` is the unit of work, `DbSet<T>` the repository,
`UserManager` the user store), and nothing in Core called the repository ports, so
they are removed rather than typed.

- [x] `02`: remove `IUserRepository` and `ITenantAccessRepository`. Data access lives in `Idmt.AspNetCore` against `DbContext` / `UserManager` directly.
- [x] `02`: keep `ITenantAccessGate` and `IClientTenantAccessGate` (gate is a domain decision) plus the `TimeProvider` clock port, with real signatures and no OpenIddict/EF types.
- [x] `01`: remove `IUserRepository.cs` / `ITenantAccessRepository.cs` from the Core folder tree.
- [x] `02`: remove `ISupportAuditPort` from Core (the audit write is transaction-coupled by design); the mint service in `Idmt.AspNetCore` owns it.
- [x] `02`: declare the support-capability rule as a concrete shape, for example `static bool SupportCapability.CanMint(SysRoleKind sysRole, bool tenantAccessGranted)` (pure; the gate result is passed in by the caller).

### F19. ClientTenantAccess entity and gate

Source: architecture, C#. Docs: `16-machine-client-auth.md`, `02-core-domain.md`, `03-persistence-and-contexts.md`, `06-tenant-access-gate.md`.

- [ ] `02`: add the `ClientTenantAccess` entity (active plus optional expiry, mirroring `TenantAccess`) and `IClientTenantAccessGate` (`Task<bool> CanAccessAsync(string clientId, string tenantIdentifier, CancellationToken ct)`).
- [ ] `03`: assign `ClientTenantAccess` a context and migration history.
- [ ] `06`: add the client gate as the issuance gate for the client-credentials grant (see F4).

### F20. State the gate predicate explicitly (no new type)

Source: C#. Docs: `02-core-domain.md`, `06-tenant-access-gate.md`.

Revised after validation: a dedicated `TenantAccessRule` static class is ceremony
for a three-condition boolean. State the predicate inline and test it through the
gate port.

- [ ] `06`: state the gate decision as the explicit predicate `isActive && (expiresAt is null || expiresAt > now)`, and that SQLite evaluates the expiry comparison in memory.
- [ ] `14`: verify the three outcomes (active-unexpired passes, expired fails, missing fails) through the gate port's unit tests, per the acceptance criteria already in `02`. Do not add a separate `TenantAccessRule` type.

### F21. TenantAccess.TenantId identifier semantics

Source: C#. Docs: `02-core-domain.md`, `06-tenant-access-gate.md`, `13-seeding-bootstrap.md`.

- [ ] `02`/`06`: state `TenantAccess.TenantId` stores the Finbuckle identifier (not the Finbuckle `Id`), matching how the gate is called.
- [ ] `13`: the seeder writes the same value.

### F22. ErrorOr taxonomy for v2 flows

Source: C#. Docs: `02-core-domain.md`, plus each flow doc.

- [ ] Add `IdmtErrors` members for tenant-access denial, audience mismatch, support-mint denial and required-reason, MFA-required at issuance, and client-tenant denial.
- [ ] State which denials surface as `ErrorOr` (handler path) versus OpenIddict `context.Reject` (pipeline). They are different mechanisms.

### F23. Reclassify two items from hardening to blocker

Source: architecture. Docs: `15-hardening-and-open-questions.md`, `09-browser-login-bff.md`, `07-revocation-hooks.md`.

- [ ] State-to-browser binding: move from near-term hardening to a blocking requirement of the BFF task (`09`). It is a single-instance login-CSRF defect, not scale-out polish. Add an acceptance test.
- [ ] Authorization uniqueness guard on `(subject, tenant)`: move from hardening to a build requirement of `07`. Duplicate authorizations make single-tenant revocation under-revoke. Add a concurrent-mint test and a unique constraint or upsert.

### F24. Unowned cross-cutting surfaces

Source: architecture. Docs: `11-endpoint-scaffolding.md`, `10-locked-seam.md`.

- [ ] Email transport, link generation, and the out-of-band email-change flow: assign an owner (a section in `11` or a new task), reusing the v1 `IIdmtLinkGenerator` and `PiiMasker` shapes. They are currently mounted but unbuilt.
- [ ] Rate limiting: define `IdmtOptions.RateLimiting` and where the limiter policy is registered (builder doc `10`).
- [ ] Tenant store and `IdmtTenantInfo`: a dedicated third EF context (decided Ia) plus the builder seam for resolution strategy.

### F25. refresh aud source reconciliation

Source: architecture. Docs: `05-multitenancy-audience.md`, `07-revocation-hooks.md`.

- [ ] `05`: add one sentence that the refresh handler reads `aud` from the decrypted presented token at exchange time, not from a store query. Cross-link `07`'s "no audience column" claim so the two read as consistent.

### F26. Request and response record shapes for locked-invariant operations

Source: C#. Docs: `11-endpoint-scaffolding.md`.

- [ ] `11`: pin the support-mint request record (`required Guid TargetUserId`, `required string TenantIdentifier`, `required string Reason`, optional TTL) with a FluentValidation `NotEmpty` rule on Reason, and the TenantAccess grant/revoke records. The rest of the slice records can be left to the implementer.

### F27. C# 14 idioms

Source: C#. Docs: `02-core-domain.md`, `01`, `12`.

- [ ] Prescribe `required` members in place of `= null!;` initializers for non-null-without-default properties (`TenantId`, `UserName`, `Email`, support-mint `Reason`).

## Risks accepted as-is (no edit beyond a note)

- Single issuer with tenant as audience concentrates blast radius; production key custody (key vault, rotation) is elevated from polish to a primary control. Note in `04`/`15`. Per-tenant signing keys remain open question 4.
- Reference-token store-read-per-request plus co-hosting is a designed-in scaling ceiling. Already documented in `04`; keep it prominent. Backplane transport remains open question 3.
- Validation event-handler order relies on a magic `SetOrder` constant and Finbuckle-before-auth. Keep fail-closed; add a same-tenant 200 integration test so an ordering regression fails CI (`14`).

## Out of scope / genuinely deferrable

- Out-of-process resource servers (open question 2): co-hosting is a clean assumption for v1-scale.
- Real cross-site `SameSite` redirect test (deferred test gap, provided F23 state-binding is built).
- MFA factor selection (TOTP versus WebAuthn) and timeline (open question 5); the enforcement path is addressed by F13.
