# Credential-change token revocation

When a user's credential changes, every token that change should invalidate has
to drop, and it has to drop now. ASP.NET Core Identity rotates the user's
`SecurityStamp` on a password change, an email change, or a deactivation, but
that rotation does not touch the OpenIddict token store, so it does not revoke a
single reference token on its own. IDMT owns this gap. IDMT registers a hook on
the credential-change paths that calls into the OpenIddict token store to drop
the affected tokens, and the whole job comes down to two store calls: one that
drops every token a user holds, and one that drops only a single tenant's
tokens. The spike proved both against real infrastructure, including a user
holding 100 tokens, in gate 6.

This page tells you what to build, the exact OpenIddict APIs you call, and the
one concurrency hazard you must close before this ships. The instant part of
"instant revocation" comes from reference tokens plus `EnableTokenEntryValidation()`,
which `04-openiddict-server.md` locks: a revoked token entry is seen on the very
next request.

## What you build

This section names the concrete deliverables so you can scope the work before
reading the detail. The pieces are small: a grouping decision at mint time, two
thin revoke methods over the token manager, and a hook that wires them onto the
Identity credential-change paths.

You build three things:

- Authorization grouping at mint. Every tenant-scoped token a user holds is
  minted under one OpenIddict authorization keyed to `(user, tenant)`, marked
  with a scope so you can find it again. This is what makes per-tenant
  revocation possible.
- The two revoke paths. Full revocation drops every token the subject holds in
  one call. Single-tenant revocation finds the `(user, tenant)` authorization
  and drops the tokens grouped under it.
- The `SecurityStamp` hook, wired through a custom `UserManager<IdmtUser>`
  override. The override is the single chokepoint on the credential-change paths
  (password change, email change, `UpdateSecurityStampAsync`, deactivation) that
  calls the full or per-tenant revoke depending on the scope of the change. This
  is locked invariant 5.
- An authorization uniqueness guard on `(subject, tenant)`. A unique constraint
  or upsert that holds the at-most-one-authorization invariant the per-tenant
  revoke depends on. This is a build requirement of this task, not deferred
  hardening (see the section below).

## Source of truth

Read these artifacts before you implement, so the grouping mechanism, the API
names, and the locked status all match the ADR and the proven spike exactly. The
documents below are authoritative; this page summarizes them rather than
restating them.

- [ADR 0002 §2.7](../../adr/0002-idmt-v2-openiddict-authorization-layer.md):
  credential-change revocation, why a token entry has no audience to filter on,
  and the authorization-grouping mechanism for single-tenant revocation.
- [ADR 0002 §2.9](../../adr/0002-idmt-v2-openiddict-authorization-layer.md):
  locked invariant 5, the `SecurityStamp`-change propagation hook, stated as
  `RevokeBySubjectAsync` for a full credential change and
  `RevokeByAuthorizationIdAsync` on the per-tenant authorization for a
  single-tenant revoke.
- `spike/src/Idmt.Spike.Host/Server/UserTokenMint.cs`: the authorization
  grouping at mint, including the find-or-create that links each token to its
  `(subject, tenant)` authorization, and the concurrency note this page promotes
  to a hardening requirement.
- `spike/src/Idmt.Spike.Host/Server/TokenRevocationHook.cs`: the two revoke
  methods, `RevokeAllForUserAsync` and `RevokeForUserTenantAsync`.
- `spike/tests/Idmt.Spike.Tests/Gate6_SecurityStampRevocationTests.cs`: gate 6,
  the 100-token full-revoke proof and the single-tenant revoke that leaves the
  other tenant valid.

## Authorization grouping

The grouping decision happens at mint time, well before any revocation. You mint
every tenant-scoped token under one OpenIddict authorization keyed to
`(user, tenant)`, and you mark that authorization with a scope you can search
for later. Get this right at mint or single-tenant revocation has nothing to
target.

The reason you group rather than filter is structural. The OpenIddict token
entry records no audience column: the token's audience lives only in the
encrypted payload, which the store cannot query. So you cannot ask the store for
"every tenant-B token this user holds" by audience. Instead, you make the
`(user, tenant)` authorization the thing you can query, and you revoke by that.

In `UserTokenMint.cs` the spike does this with a marker scope. Every
`(subject, tenant)` authorization carries a scope of the form
`idmt:authz:tenant:<tenant>`, and finding the authorization later is a scan of
the subject's authorizations for that marker:

- `EnsureTenantAuthorizationAsync(subject, tenant, ct)` finds or creates the
  authorization. Creation calls
  `IOpenIddictAuthorizationManager.CreateAsync(OpenIddictAuthorizationDescriptor)`
  with `Subject` set to the user, `Scopes` carrying the
  `idmt:authz:tenant:<tenant>` marker, and `Type = AuthorizationTypes.Permanent`.
- `FindTenantAuthorizationIdAsync(subject, tenant, ct)` walks
  `IOpenIddictAuthorizationManager.FindBySubjectAsync(subject, ct)`, reads each
  authorization's scopes with `GetScopesAsync`, matches the marker, and returns
  the id from `GetIdAsync`.
- `MintAsync(subject, tenant, ct)` calls `EnsureTenantAuthorizationAsync` first,
  then creates the token with `AuthorizationId` set to the returned id, so the
  token is linked to its `(user, tenant)` group.

Every token a user holds for a tenant therefore hangs off one authorization, and
that authorization is the handle single-tenant revocation reaches for.

## Full revocation

Full revocation is the path for a full credential change: a password reset, a
deactivation, or a confirmed compromise. Every token the user holds, across
every tenant, must drop. You do not enumerate tokens and revoke them one by one.

You make one store call. `RevokeAllForUserAsync` in `TokenRevocationHook.cs`
calls `IOpenIddictTokenManager.RevokeBySubjectAsync(subject, ct)`, which revokes
every token the subject holds and returns the count revoked. Because it is a
single store operation, its cost does not scale with the number of tokens the
user holds: the spike revoked a 100-token user in one call and asserted the
returned count was exactly 100.

One correction the spike pinned down: OpenIddict 7.5.0 does expose
`RevokeBySubjectAsync` and `RevokeByAuthorizationIdAsync`. An earlier ADR draft
claimed otherwise and described a manual enumerate-and-revoke loop. The spike
verified both single-call APIs against real infrastructure, so you use them
directly and skip the loop. The single call also sidesteps mutating a live store
enumeration on the shared connection, which the loop would have done.

## Single-tenant revocation

Single-tenant revocation is the path for a change scoped to one tenant: a
`TenantAccess` revoke, or a multi-tenant boundary crossing that must drop one
tenant's tokens while leaving the others valid. You target the tokens through
the authorization they were grouped under, not through their audience.

You make two calls, both in `RevokeForUserTenantAsync` in
`TokenRevocationHook.cs`. First, find the `(user, tenant)` authorization by its
marker scope through `mint.FindTenantAuthorizationIdAsync(subject, tenant, ct)`.
If that returns null, the user holds no tokens for that tenant and the method
returns false without touching the store. Otherwise, call
`IOpenIddictTokenManager.RevokeByAuthorizationIdAsync(authorizationId, ct)`,
which drops every token linked to that authorization and leaves the user's other
tenants untouched.

## The SecurityStamp hook

The hook is the enforcement that ties Identity's credential signal to the
OpenIddict store. The `SecurityStamp` stays the source-of-truth signal that a
credential changed; the hook is the action that propagates that signal to issued
tokens, because the engine does not.

### Where the hook is wired

Identity exposes no built-in "stamp changed" event, so there is no callback to
subscribe to. The interception point IDMT uses is a custom `UserManager<IdmtUser>`
override. Every credential change funnels through `UserManager<IdmtUser>`, so
overriding the credential-change methods on a derived manager is the single
chokepoint where the revoke can fire without scattering call sites:

- Override `UpdateSecurityStampAsync` (the method every credential rotation
  ultimately calls) to run the base rotation and then fire the full revoke.
- Override the password-change, email-change, and deactivation paths the same
  way, choosing the full or per-tenant revoke for the scope of the change, then
  delegating to `base`.

Register the derived manager in DI (for example with
`AddUserManager<IdmtUserManager>()` on the Identity builder) so it replaces the
default `UserManager<IdmtUser>` everywhere IDMT and consumers resolve it. The
override is the only thing that guarantees a credential change reaches the
OpenIddict store.

The startup self-check cannot observe that this override is installed: the
self-check inspects options, and a `UserManager` substitution is a DI
registration, not an options flag. A dedicated test therefore covers that the
override fires the revoke. That test lives in
[the test suite](14-test-suite.md); this page only requires the override.

The hook chooses its revoke path by the scope of the change:

- A full credential change calls the full path, `RevokeBySubjectAsync`, so every
  token the user holds drops.
- A change scoped to one tenant calls the per-tenant path,
  `RevokeByAuthorizationIdAsync` on the `(user, tenant)` authorization, so only
  that tenant's tokens drop.

This hook is locked invariant 5 in ADR §2.9: it is applied unconditionally and a
consumer cannot subtract it. Revocation is instant because access tokens are
reference tokens validated with `EnableTokenEntryValidation()` (locked in
`04-openiddict-server.md`): the revoked status lives in the token entry, and the
local validation handler reads that entry on the very next request, so a revoked
token returns 401 before its TTL would have expired.

## Authorization uniqueness: a build requirement

This is a build requirement of this task, not deferred hardening. The spike's
find-or-create authorization is correct only when mints run sequentially, and the
production implementation must close that gap before it ships. Duplicate
authorizations make single-tenant revocation under-revoke and leave live tokens,
so the guard is part of what "the per-tenant revoke works" means.

The hazard is in `EnsureTenantAuthorizationAsync`. It is a check-then-create:
find the `(subject, tenant)` authorization, and create one if none exists. The
spike comment states the limit plainly: the check-then-create is idempotent only
sequentially, and concurrent mints for the same `(subject, tenant)` can create
duplicate authorizations. The spike is single-threaded, so its proof holds, but
two concurrent mints in production could each see no existing authorization and
each create one.

Duplicate authorizations break single-tenant revocation specifically. A later
`RevokeForUserTenantAsync` finds and revokes one authorization and misses the
duplicate, so it under-revokes: tokens grouped under the missed authorization
stay valid after a revoke that was supposed to drop them. Full revocation is
unaffected, because `RevokeBySubjectAsync` drops every token regardless of how
many authorizations group them.

The production implementation must guarantee at most one authorization per
`(subject, tenant)`. You add a unique constraint or an upsert on
`(subject, tenant)` authorizations so concurrent mints converge on one row
rather than racing to create two. This is a correctness requirement for
single-tenant revocation, not an optimization, and it ships with this task.

A concurrent-mint test proves the guard holds: two parallel mints for the same
`(subject, tenant)` must converge on exactly one authorization, so a later
single-tenant revoke drops every token rather than missing a duplicate's group.
That test lives in [the test suite](14-test-suite.md).

## Dependencies

This page assumes two earlier pieces are already in place. Revocation is only
instant because of the first, and the per-tenant path only exists because of the
gate that produces the per-tenant authorizations.

- [Reference tokens and `EnableTokenEntryValidation()`](04-openiddict-server.md):
  the validation that makes a revoked token entry take effect on the next
  request.
- [The uniform `TenantAccess` gate](06-tenant-access-gate.md): the issuance gate
  whose `TenantAccess` revoke is the trigger for single-tenant revocation.

## Acceptance criteria

These criteria are gate 6 from the spike, and they are the bar this work meets.
Both assert against the real OpenIddict store, reading token status rather than
mocking it.

- Full revocation at bounded cost. A user holding 100 tokens (split across two
  tenants) is fully revoked by one `RevokeBySubjectAsync` call, the returned
  count is 100, and every one of the 100 token entries reads `Revoked`.
- Single-tenant isolation. After a single-tenant revoke of tenant A for a user
  who holds tokens for tenant A and tenant B, every tenant-A token reads
  `Revoked` and every tenant-B token still reads `Valid`.

## Next steps

The next page covers the other side of server-side token creation, where the
same authorization-grouping and revocation guarantees apply to an impersonating
system user.

- [Server-side support-token mint](08-support-token-mint.md).
