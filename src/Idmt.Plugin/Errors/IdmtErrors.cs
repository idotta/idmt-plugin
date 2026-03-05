using ErrorOr;

namespace Idmt.Plugin.Errors;

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
    }

    public static class Email
    {
        public static Error ConfirmationFailed => Error.Failure(
            code: "Email.ConfirmationFailed",
            description: "Unable to confirm email");
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
    }
}
