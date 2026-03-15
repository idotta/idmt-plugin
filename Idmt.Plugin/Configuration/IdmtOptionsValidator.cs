using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Configuration;

/// <summary>
/// Validates <see cref="IdmtOptions"/> at application startup so that
/// misconfigured options are reported immediately rather than causing
/// unexpected failures at runtime.
/// </summary>
public sealed class IdmtOptionsValidator : IValidateOptions<IdmtOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, IdmtOptions options)
    {
        var failures = new List<string>();

        ValidateApplicationOptions(options.Application, failures);
        ValidateMultiTenantOptions(options.MultiTenant, failures);

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }

    private static void ValidateApplicationOptions(ApplicationOptions application, List<string> failures)
    {
        // Rule 1: ApiPrefix must not be null or empty.
        // An empty string is the documented opt-out for legacy unprefixed behavior,
        // but null indicates the property was explicitly cleared and is misconfigured.
        if (application.ApiPrefix is null)
        {
            failures.Add(
                $"{nameof(IdmtOptions.Application)}.{nameof(ApplicationOptions.ApiPrefix)} must not be null. " +
                "Use an empty string \"\" to disable the prefix or provide a value such as \"/api/v1\".");
        }

        // Rule 2: ClientUrl is always required because password reset links always use
        // client form URLs (GeneratePasswordResetLink), regardless of EmailConfirmationMode.
        if (string.IsNullOrWhiteSpace(application.ClientUrl))
        {
            failures.Add(
                $"{nameof(IdmtOptions.Application)}.{nameof(ApplicationOptions.ClientUrl)} must not be null or empty. " +
                "It is required for password reset links and for email confirmation when " +
                $"{nameof(ApplicationOptions.EmailConfirmationMode)} is {nameof(EmailConfirmationMode.ClientForm)}.");
        }

        // Rule 3: When ClientUrl is set, the client-side form paths must also be configured.
        if (!string.IsNullOrWhiteSpace(application.ClientUrl))
        {
            if (string.IsNullOrWhiteSpace(application.ConfirmEmailFormPath))
            {
                failures.Add(
                    $"{nameof(IdmtOptions.Application)}.{nameof(ApplicationOptions.ConfirmEmailFormPath)} must not be null or empty " +
                    $"when {nameof(ApplicationOptions.ClientUrl)} is set.");
            }

            if (string.IsNullOrWhiteSpace(application.ResetPasswordFormPath))
            {
                failures.Add(
                    $"{nameof(IdmtOptions.Application)}.{nameof(ApplicationOptions.ResetPasswordFormPath)} must not be null or empty " +
                    $"when {nameof(ApplicationOptions.ClientUrl)} is set.");
            }
        }
    }

    private static void ValidateMultiTenantOptions(MultiTenantOptions multiTenant, List<string> failures)
    {
        // Rule 4: The constant DefaultTenantIdentifier is a compile-time value and cannot be
        // null or empty. Validate it defensively so that any future refactor to an instance
        // property is caught immediately.
        if (string.IsNullOrWhiteSpace(MultiTenantOptions.DefaultTenantIdentifier))
        {
            failures.Add(
                $"{nameof(IdmtOptions.MultiTenant)}.{nameof(MultiTenantOptions.DefaultTenantIdentifier)} must not be null or empty.");
        }

        // Rule 5: DefaultTenantName is configurable and must not be null or empty.
        if (string.IsNullOrWhiteSpace(multiTenant.DefaultTenantName))
        {
            failures.Add(
                $"{nameof(IdmtOptions.MultiTenant)}.{nameof(MultiTenantOptions.DefaultTenantName)} must not be null or empty.");
        }

        // Rule 6: At least one tenant resolution strategy must be configured.
        // The Strategies array controls which strategies (header, claim, route, basepath) are
        // active. An empty array means no tenant can ever be resolved, which is always a
        // misconfiguration. StrategyOptions holds per-strategy overrides and may be empty.
        if (multiTenant.Strategies.Length == 0)
        {
            failures.Add(
                $"{nameof(IdmtOptions.MultiTenant)}.{nameof(MultiTenantOptions.Strategies)} must contain at least one entry. " +
                $"Supported values: {IdmtMultiTenantStrategy.Header}, {IdmtMultiTenantStrategy.Claim}, " +
                $"{IdmtMultiTenantStrategy.Route}, {IdmtMultiTenantStrategy.BasePath}.");
        }
    }
}
