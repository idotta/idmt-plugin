using ErrorOr;

namespace Idmt.Core.Errors;

/// <summary>
/// Canonical error catalog, organized by domain. Handlers return one canonical
/// <see cref="Error"/> per outcome rather than ad hoc strings; endpoint delegates
/// map <see cref="ErrorType"/> to an HTTP status. The v2 denial members are added
/// alongside the catalog carried forward from 2.0.0.
/// </summary>
public static class IdmtErrors
{
    public static class Auth
    {
        public static Error Unauthorized => Error.Unauthorized(
            code: "Auth.Unauthorized",
            description: "Unauthorized");

        public static Error Forbidden => Error.Forbidden(
            code: "Auth.Forbidden",
            description: "Forbidden");

        public static Error UserDeactivated => Error.Forbidden(
            code: "Auth.UserDeactivated",
            description: "User is deactivated");

        public static Error TwoFactorRequired => Error.Custom(
            type: 42,
            code: "Auth.TwoFactorRequired",
            description: "Two-factor authentication is required");

        public static Error InvalidCredentials => Error.Unauthorized(
            code: "Auth.InvalidCredentials",
            description: "Invalid credentials");

        public static Error LockedOut => Error.Custom(
            type: 43,
            code: "Auth.LockedOut",
            description: "Account is locked out due to too many failed attempts");

        // v2 denial outcomes.

        public static Error SupportMintDenied => Error.Forbidden(
            code: "Auth.SupportMintDenied",
            description: "Support token mint denied for this user and tenant");

        public static Error SupportReasonRequired => Error.Validation(
            code: "Auth.SupportReasonRequired",
            description: "A reason is required to mint a support token");

        public static Error MfaRequired => Error.Forbidden(
            code: "Auth.MfaRequired",
            description: "A second authentication factor is required before a token can be issued");

        public static Error ClientTenantAccessDenied => Error.Forbidden(
            code: "Auth.ClientTenantAccessDenied",
            description: "Client is not granted access to this tenant");
    }

    public static class Tenant
    {
        public static Error NotFound => Error.NotFound(
            code: "Tenant.NotFound",
            description: "Tenant not found");

        public static Error Inactive => Error.Forbidden(
            code: "Tenant.Inactive",
            description: "Tenant is not active");

        public static Error NotResolved => Error.Validation(
            code: "Tenant.NotResolved",
            description: "Tenant not resolved");

        public static Error CannotDeleteDefault => Error.Forbidden(
            code: "Tenant.CannotDeleteDefault",
            description: "Cannot delete the default tenant");

        public static Error CreationFailed => Error.Failure(
            code: "Tenant.CreationFailed",
            description: "Failed to create tenant");

        public static Error UpdateFailed => Error.Failure(
            code: "Tenant.UpdateFailed",
            description: "Failed to update tenant");

        public static Error DeletionFailed => Error.Failure(
            code: "Tenant.DeletionFailed",
            description: "Failed to delete tenant");

        public static Error RoleSeedFailed => Error.Failure(
            code: "Tenant.RoleSeedFailed",
            description: "Failed to guarantee tenant roles");

        public static Error AccessError => Error.Failure(
            code: "Tenant.AccessError",
            description: "An error occurred while managing tenant access");

        public static Error AlreadyExists => Error.Conflict(
            code: "Tenant.AlreadyExists",
            description: "A tenant with this identifier already exists");

        public static Error AccessNotFound => Error.NotFound(
            code: "Tenant.AccessNotFound",
            description: "No tenant access record found for this user");

        // v2 denial outcome: the uniform gate failed for (user, tenant).
        public static Error AccessDenied => Error.Forbidden(
            code: "Tenant.AccessDenied",
            description: "User is not granted access to this tenant");
    }

    public static class User
    {
        public static Error NotFound => Error.NotFound(
            code: "User.NotFound",
            description: "User not found");

        public static Error CreationFailed => Error.Failure(
            code: "User.CreationFailed",
            description: "Failed to create user");

        public static Error UpdateFailed => Error.Failure(
            code: "User.UpdateFailed",
            description: "Failed to update user");

        public static Error RoleNotFound => Error.Validation(
            code: "User.RoleNotFound",
            description: "Role not found");

        public static Error InsufficientPermissions => Error.Forbidden(
            code: "User.InsufficientPermissions",
            description: "Insufficient permissions");

        public static Error NoRolesAssigned => Error.Validation(
            code: "User.NoRolesAssigned",
            description: "User has no roles assigned");

        public static Error ClaimsNotFound => Error.Validation(
            code: "User.ClaimsNotFound",
            description: "User claims not found");

        public static Error Inactive => Error.Forbidden(
            code: "User.Inactive",
            description: "User is not active");

        public static Error DeletionFailed => Error.Failure(
            code: "User.DeletionFailed",
            description: "Failed to delete user");
    }

    public static class Token
    {
        public static Error Invalid => Error.Validation(
            code: "Token.Invalid",
            description: "Invalid token");

        public static Error Revoked => Error.Unauthorized(
            code: "Token.Revoked",
            description: "Token has been revoked");

        // v2 denial outcome: a presented token's aud does not match the resolved tenant.
        public static Error AudienceMismatch => Error.Unauthorized(
            code: "Token.AudienceMismatch",
            description: "Token audience does not match the resolved tenant");
    }

    public static class Email
    {
        public static Error ConfirmationFailed => Error.Failure(
            code: "Email.ConfirmationFailed",
            description: "Unable to confirm email");

        public static Error NoPendingChange => Error.Validation(
            code: "Email.NoPendingChange",
            description: "No pending email change to confirm.");

        public static Error PendingMismatch => Error.Validation(
            code: "Email.PendingMismatch",
            description: "Pending email does not match request.");
    }

    public static class Password
    {
        public static Error ResetFailed => Error.Failure(
            code: "Password.ResetFailed",
            description: "Unable to reset password");
    }

    public static class General
    {
        public static Error Unexpected => Error.Unexpected(
            code: "General.Unexpected",
            description: "An unexpected error occurred");

        public static Error SelfTarget => Error.Forbidden(
            code: "General.SelfTarget",
            description: "This operation cannot target the caller");
    }
}
