# ADR 0002 — Evaluation of the three v2 sketches

- **Status:** Decision aid
- **Date:** 2026-06-04
- **Author:** Claude (synthesis pass)
- **Reads:** `0002-v2-sketch-dotnet-expert.md`, `0002-v2-sketch-architect-reviewer.md`, `0002-v2-sketch-code-architect.md`

> Purpose: score the three sketches against the owner's *stated* goals, surface
> where they actually disagree (most of it is the same design), and give a
> recommendation with a concrete way to combine them. This is not a tie-breaker
> vote — it's a map of which sketch is right about what.

---

## 0. The goals being scored against

Pulled from the owner's own words across the discussion:

1. **Simple** "plugin" library/service.
2. **Perfect balance: opinionated ↔ customizable.**
3. **Secure** (the audit backlog must structurally close, not be re-implemented).
4. **Multi-tenant** capable.
5. Library consumer can build **endpoints for both the tenant side and the sys-admin side.**
6. **Sys-admin supports a tenant cleanly** — no account duplication.
7. **Own the infra**, pure .NET, self-hosted (OpenIddict chosen; no Keycloak/Duende/managed).
8. Greenfield, low sunk cost (AI-written, cheap to rewrite).

---

## 1. Where all three already agree (the settled core)

Treat this as decided — three independent passes converged on it:

- **OpenIddict owns the OAuth/OIDC protocol**; IDMT owns the multi-tenant authorization model + endpoint scaffolding. ("Own the policy, rent the protocol.")
- **Reference (opaque) access tokens** are the default/locked choice → instant revocation. This is the single biggest security win and it deletes the entire C1/N5/M2/`TokenRevocationService` backlog.
- **Sys-support = RFC 8693 token exchange** minting a tenant-scoped, time-bound, **audited** token. No shadow rows. All three carry the actor/`support_of`/`support_invoker` claim and write audit *before* returning the token.
- **`ValidateBearerTokenTenantMiddleware` dies**, replaced by token-tenant binding (audience or a validation handler).
- **Canonical `IdmtUser` + `TenantAccess` + `SysRole` + Finbuckle + ASP.NET Identity user store** all survive. The uniform TenantAccess gate stays, now also enforced at token issuance.
- **`AddIdmt` + `Map*` endpoint scaffolding** with policies pre-attached; `ErrorOr` + FluentValidation + vertical slices for the remaining business endpoints.
- **DP key persistence / fail-fast on prod keys** called out by all three.

If the sketches agree on it, it's low-risk. The decision is really about the **three axes where they diverge**.

---

## 2. The three real disagreements

### Axis A — Package granularity

| Sketch | Shape | Stance |
|---|---|---|
| dotnet-expert | **5 packages**: Abstractions ← Core ← {Server, Persistence, Mfa} | OpenIddict isolated in `Idmt.Server`; Abstractions has zero infra deps |
| architect-reviewer | **4 (+1 persistence) assemblies**: Core, MultiTenancy, OpenIddict, AspNetCore, Persistence.EF | Each vendor (OpenIddict/Finbuckle/EF) named in *exactly one* assembly, enforced by an architecture-test fitness function |
| code-architect | **1 package** (`Idmt.Plugin`), optional Abstractions later | Keep v1's single-package shape; minimize consumer migration surface |

This is the **central tension vs. goal #1 (simple)**. More packages = cleaner blast radius and compile-time firewalls (reviewer's strongest argument: a Finbuckle or OpenIddict major bump touches one package), but more ceremony for a solo owner shipping a "simple plugin." Fewer packages = simpler to ship and reason about, but vendor types can leak across folders by accident (exactly how v1's `GrantTenantAccess.cs` ended up doing shadow-row surgery).

### Axis B — The cookie / auth model

| Sketch | Stance |
|---|---|
| dotnet-expert | **Drops per-tenant cookies for APIs entirely.** Cookies survive only for the interactive sign-in UI; all API traffic is bearer reference tokens. Collapses v1's hybrid cookie/bearer complexity. |
| architect-reviewer | Same direction — cookies become a "thin first-party-client convenience over the same token store, not a parallel auth universe." |
| code-architect | **Keeps** the `CookieOrBearer` PolicyScheme and per-tenant cookie isolation; bearer simply forwards to OpenIddict's validation scheme. |

This is a genuine fork. expert/reviewer argue the hybrid model is a bug-class generator ("cookie path vs bearer path diverge") and should go. code-architect argues for continuity and minimal migration. **Goal #3 (secure) leans expert/reviewer; goal #1/#8 lean code-architect.**

### Axis C — Migration philosophy

| Sketch | Stance |
|---|---|
| dotnet-expert | Greenfield-leaning; new package names, fluent builder, force re-auth at cutover |
| architect-reviewer | Greenfield decomposition; explicitly notes schema is *largely preserved* so data migration is lower-risk than ADR-0001's reshape |
| code-architect | **Maximum continuity**: identical `AddIdmt` signature (adds one optional `CustomizeOpenIddict` delegate), file-by-file fate map, ~70% of code KEPT |

Given goal #8 (cheap to rewrite, greenfield, low sunk cost), continuity is *less* valuable than it looks — the owner explicitly said preserving v1 is not a constraint.

---

## 3. Scorecard

Scored 1–5 against each goal (5 = best serves it). These are judgments, not arithmetic truth — read the reasoning, not the totals.

| Goal | dotnet-expert | architect-reviewer | code-architect |
|---|:---:|:---:|:---:|
| 1. Simple plugin | 3 | 2 | **5** |
| 2. Opinionated ↔ customizable | **5** (fluent builder + typed escape hatch) | **5** (structurally locked in `Build()`) | 3 (keeps v1's positional-delegate soup + new delegate) |
| 3. Secure (closes backlog structurally) | 4 | **5** (locked/open line is the sharpest; fitness functions) | 4 |
| 4. Multi-tenant | 4 | **5** (names Finbuckle↔OpenIddict reconciliation as *the* risk; aud = source of truth + route-mutation fuzzer) | 4 (concrete `TenantValidationHandler`, but middleware-style) |
| 5. Tenant + sys endpoints | 4 | **5** (`IdmtTenantEndpoints`/`IdmtSystemEndpoints` expose sub-groups for consumer endpoints) | 4 (real mapper code, less explicit on consumer-extension seam) |
| 6. Clean sys-support | 4 | **5** (support token = just a tenant-audienced reference token; one code path, deletes `IsSysSession` branch) | **5** (full working slice; most concrete) |
| 7. Own infra / pure .NET | 5 | 5 | 5 |
| 8. Greenfield value | 4 | 4 | 3 (optimizes for a migration the owner doesn't need) |
| **Distinctiveness / depth** | builder ergonomics + AOT realism | decomposition rigor + fitness functions | runnable concreteness + file-level map |

**読み (read):**
- **architect-reviewer** is strongest on the things that bite later: the opinionated/customizable line (goal #2) drawn *structurally* so a consumer can't subtract a security property, the tenancy-reconciliation risk (goal #4) named and guarded with a CI fuzzer, and the cleanest sys-support model (support token is not a special object). Weakest on goal #1 — five assemblies is a lot of ceremony for a solo "simple plugin."
- **dotnet-expert** is the best *.NET-idiomatic* design: the fluent `IIdmtBuilder`, the "wrap OpenIddict, don't hide it, consumer-wins-last" escape hatch, and the only sketch honest about AOT being out of reach. Middle on simplicity.
- **code-architect** is the most *actionable*: a real `SupportTenant.cs` you could almost compile, a file-by-file fate map, and the lowest-friction path. But it optimizes for migration continuity (goal #8 says you don't need that) and keeps the `CookieOrBearer` hybrid + positional-delegate registration that the other two deliberately kill.

---

## 4. Recommendation: a hybrid, biased to architect-reviewer's spine

No single sketch is the answer. The right v2 is **architect-reviewer's boundaries and locked/open security model, dialed down on package count toward code-architect's pragmatism, with dotnet-expert's fluent builder as the registration surface.** Concretely:

1. **Boundaries from architect-reviewer, but 3 packages not 5.** Collapse to:
   - `Idmt.Core` — domain (IdmtUser/TenantAccess/SysRole, policies, `ISupportPolicy`, ports). Zero infra. *Keep this boundary hard — it's the firewall that stops the next `GrantTenantAccess.cs`.*
   - `Idmt.AspNetCore` — composition root: OpenIddict + Finbuckle + EF + endpoints + MFA + email, organized in folders (Server/, MultiTenancy/, Persistence/, Endpoints/). Vendors live here, isolated by folder + the one architecture-test.
   - `Idmt.Mfa` — opt-in (keeps the fido2 dependency off the main package).
   
   This honors goal #1 (a consumer adds **one** package, `Idmt.AspNetCore`) while keeping the *one* boundary that actually matters (Core can't see infra). Adopt the **`Idmt.Architecture.Tests` fitness function** regardless of package count — it's cheap insurance against leakage.

2. **Security model: architect-reviewer's LOCKED/OPEN line verbatim** (§4 of that sketch). This *is* the answer to goal #2. Reference tokens, the gate, refresh rotation, support-TTL ceiling, audience isolation, audited support → locked in `Build()`, not configurable. Claims/MFA-factors/transport/extra-endpoints → open. This is the single most important idea across all three docs.

3. **Registration surface: dotnet-expert's fluent `IIdmtBuilder`** (not code-architect's positional delegates — that's the one place code-architect's continuity bias actively hurts). Fluent + named seams makes the locked/open line *visible in the type system*.

4. **Sys-support: architect-reviewer's "just a tenant-audienced reference token"** model, implemented with **code-architect's concrete slice** as the starting code. Best of both — right abstraction, runnable shape.

5. **Cookie model: side with expert/reviewer — kill the hybrid.** APIs are bearer reference tokens; cookies only for the interactive sign-in surface if you even keep one. This closes a whole bug class and you're greenfield, so there's no migration cost to fear (goal #8).

6. **Endpoint scaffolding: architect-reviewer's `IdmtTenantEndpoints`/`IdmtSystemEndpoints`** returning sub-groups, so the consumer mounts their own tenant-side and sys-side endpoints under the pre-attached policy (goal #5). dotnet-expert's `RouteGroupBuilder` return is equivalent and simpler — either works.

---

## 5. The open questions you must resolve before building (all three raised these)

These are not sketch-specific — they're real and a prototype should de-risk them **first**:

1. **Finbuckle global query filters vs. OpenIddict EF stores.** If the multi-tenant query filter touches the OpenIddict token tables, token validation breaks silently. Keep OpenIddict tables out of the tenant filter. *Prototype this composition first — it's the #1 integration risk and every sketch flagged it.*
2. **Tenant resolution for the token endpoint.** Route-based `/{tenant}/connect/token` breaks standard OIDC discovery; header/`resource`-based is cleaner but needs IDMT-aware clients. Pick one, document the OIDC-conformance tradeoff.
3. **`password` grant + OAuth 2.1.** It's being removed. Don't build login on the password grant; use authorization-code + PKCE (or a custom credential-exchange that issues a code). code-architect §7.2 is right to flag this — decide early because it shapes the login slice.
4. **Reference-token read amplification + multi-instance revocation.** One DB read per request; "instant" revocation degrades to cache-TTL across scaled-out instances without a backplane (Redis pub/sub or DB polling). dotnet-expert calls this the #1 production risk. Decide your scale-out story before committing to a cache.
5. **Per-tenant signing keys?** All three say: single issuer, tenant-as-claim/audience, one trust domain. Only revisit if hard cryptographic tenant isolation becomes a requirement.

---

## 6. One-line verdict

> Build **architect-reviewer's bounded, locked/open design** with **dotnet-expert's fluent builder**, packaged at **code-architect's lower ceremony (≈3 packages)**, and seed the sys-support slice from **code-architect's concrete `SupportTenant.cs`** — but prototype the Finbuckle×OpenIddict EF-store composition *before* writing anything else.

The most valuable single idea in the whole set: **architect-reviewer's "security invariants are locked and additive-only; the type system makes subtraction impossible."** That sentence is the answer to "opinionated but customizable."
