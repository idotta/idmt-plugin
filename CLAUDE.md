# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IDMT (Identity MultiTenant) Plugin — a reusable NuGet library for ASP.NET Core providing multi-tenant identity management. Built on Finbuckle.MultiTenant and ASP.NET Core Identity with per-tenant cookie isolation, hybrid cookie/bearer authentication, and vertical slice architecture. Uses ErrorOr for result handling and FluentValidation for request validation.

**Target:** net10.0

## Build & Development Commands

```bash
# Build
dotnet build Idmt.slnx
dotnet build Idmt.slnx --configuration Release

# Format (CI enforces this)
dotnet format Idmt.slnx --verify-no-changes --verbosity diagnostic  # check
dotnet format Idmt.slnx                                              # fix

# Test
dotnet test Idmt.slnx
dotnet test tests/Idmt.UnitTests/Idmt.UnitTests.csproj             # unit only
dotnet test tests/Idmt.BasicSample.Tests/Idmt.BasicSample.Tests.csproj  # integration only
dotnet test --filter "FullyQualifiedName~TenantAccessServiceTests"      # single test class

# Pack
dotnet pack Idmt.Plugin/Idmt.Plugin.csproj --configuration Release
```

CI runs: format check → build (warnings as errors) → analyzers → tests → pack.

## Architecture

### Vertical Slice Pattern

Each feature (Login, ForgotPassword, CreateTenant, etc.) is a self-contained static class in `Idmt.Plugin/Features/` containing:

- Request/Response records
- Handler interface returning `ErrorOr<T>`
- Internal sealed handler implementation
- FluentValidation validator (registered via DI auto-discovery)
- Endpoint mapping method using Minimal APIs

Features are grouped into: `Auth/`, `Manage/`, `Admin/`, `Health/`. Endpoints are mapped via `AuthEndpoints.cs`, `ManageEndpoints.cs`, and `AdminEndpoints.cs`.

### Error Handling

All handlers return `ErrorOr<T>`. Centralized error definitions in `Idmt.Plugin/Errors/IdmtErrors.cs` organized by domain (Auth, Tenant, User, Token, Email, Password, General). Endpoint delegates map `ErrorType` to HTTP status codes.

### Multi-Tenancy

- **Finbuckle.MultiTenant** resolves tenants via configurable strategies (Header, Route, Claim, BasePath)
- `IdmtUser` extends `IdentityUser<Guid>` and is **global** (not multi-tenant). `GetTenantId()` returns null. One identity row per human; `NormalizedEmail` is globally unique.
- `IdmtRole` remains per-tenant. The default role catalog (`IdmtDefaultRoleTypes.DefaultRoles`) was shrunk and no longer seeds `SysAdmin` / `SysSupport` per tenant.
- `IdmtUser.SysRole` (`SysRoleKind` enum: `None` / `SysAdmin` / `SysSupport`) is a global system-role flag projected as a role-string claim at sign-in. Enum string values equal the policy strings so `RequireRole` / `RequireSysAdmin` / `RequireSysUser` match without bridge code.
- `TenantAccess` maps users to tenants with `IsActive` and optional `ExpiresAt`. The TenantAccess gate is **uniform** across all users (including SysAdmin) per locked decision #4 — there is no SysRole short-circuit. `LoginHandler` / `TokenLoginHandler` enforce it after `CheckPasswordSignInAsync` and before any cookie/token is issued.
- Password and `SecurityStamp` are single-source on the canonical user row. Rotations propagate everywhere automatically — no shadow rows to keep in sync.
- `IdmtUser.PendingEmail` (nullable string) stages the next email during the OOB email-change flow. `Email` is committed only when the recipient POSTs to `/auth/confirm-email-change` with the Identity-issued token (returns 202 Accepted from `PUT /manage/info` while staged).
- Per-tenant cookie isolation: each tenant gets a separate authentication cookie name
- `ValidateBearerTokenTenantMiddleware` ensures bearer token tenant matches request tenant
- Two EF contexts: `IdmtDbContext` (multi-tenant app data) and `IdmtTenantStoreDbContext` (tenant metadata)
- `ITenantOperationService` executes code within a tenant-scoped DI scope. Invariant: inner-scope `CurrentUserService.User` must stay null; capture invoker context outside `ExecuteInTenantScopeAsync`.

### Authentication & Authorization

- **PolicyScheme** (`CookieOrBearerScheme`) auto-selects cookie vs bearer based on `Authorization` header
- Pre-configured policies: `RequireSysAdmin`, `RequireSysUser`, `RequireTenantManager`, `CookieOnly`, `BearerOnly`
- Token revocation via `ITokenRevocationService` with background cleanup (`TokenRevocationCleanupService`)

### Key Services

- `ICurrentUserService` (scoped) — current user, tenant, IP, user agent context
- `ITenantAccessService` — tenant access validation
- `ITokenRevocationService` — bearer token revocation store
- `IIdmtLinkGenerator` — email confirmation/password reset link generation
- `PiiMasker` — masks emails in structured logs

### DI Entry Point

`AddIdmt<TDbContext>()` extension method in `ServiceCollectionExtensions` with parameters: `configuration`, `configureDb`, `configureOptions`, `customizeAuthentication`, `customizeAuthorization`.

## Testing

- **Unit tests** (`tests/Idmt.UnitTests`): xUnit + Moq + EF InMemory + TimeProvider.Testing
- **Integration tests** (`tests/Idmt.BasicSample.Tests`): xUnit + `Microsoft.AspNetCore.Mvc.Testing` with in-memory SQLite
  - `IdmtApiFactory` — WebApplicationFactory with mocked email sender and test data seeding
  - `BaseIntegrationTest` — helpers for authenticated requests and token extraction

## Key References

- [Finbuckle.MultiTenant Docs](https://www.finbuckle.com/MultiTenant/Docs/)
- [Finbuckle GitHub](https://github.com/Finbuckle/Finbuckle.MultiTenant) (check older tag samples like v8.0.0)
- [ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)

## Commit Conventions

- Do NOT add `Co-Authored-By: Claude` (or any AI attribution) trailers to commit messages. Author the commit as the user only.
