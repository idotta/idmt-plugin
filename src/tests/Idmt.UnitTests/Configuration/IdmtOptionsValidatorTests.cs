using Idmt.Plugin.Configuration;
using Microsoft.Extensions.Options;

namespace Idmt.UnitTests.Configuration;

/// <summary>
/// Unit tests for <see cref="IdmtOptionsValidator"/>.
/// Each test group targets one of the six validation rules so that failures
/// pinpoint the exact rule that is violated.
/// </summary>
public class IdmtOptionsValidatorTests
{
    private readonly IdmtOptionsValidator _sut = new();

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Builds the minimum-valid options that satisfy every rule.
    /// Individual tests mutate copies of this to isolate the rule under test.
    /// </summary>
    private static IdmtOptions ValidOptions() => new()
    {
        Application = new ApplicationOptions
        {
            ApiPrefix = "/api/v1",
            EmailConfirmationMode = EmailConfirmationMode.ClientForm,
            ClientUrl = "https://myapp.com",
            ConfirmEmailFormPath = "/confirm-email",
            ResetPasswordFormPath = "/reset-password"
        },
        MultiTenant = new MultiTenantOptions
        {
            DefaultTenantName = "System Tenant",
            Strategies = [IdmtMultiTenantStrategy.Header]
        }
    };

    private ValidateOptionsResult Validate(IdmtOptions options) =>
        _sut.Validate(null, options);

    // ---------------------------------------------------------------------------
    // Baseline: fully valid options produce no failures
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_Succeeds_WhenAllRulesAreSatisfied()
    {
        var result = Validate(ValidOptions());

        Assert.False(result.Failed);
    }

    // ---------------------------------------------------------------------------
    // Rule 1 — ApiPrefix must not be null
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_Fails_WhenApiPrefixIsNull()
    {
        var options = ValidOptions();
        options.Application.ApiPrefix = null!;

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ApiPrefix)));
    }

    [Fact]
    public void Validate_Succeeds_WhenApiPrefixIsEmptyString()
    {
        // Empty string is the documented opt-out for the legacy unprefixed behavior.
        var options = ValidOptions();
        options.Application.ApiPrefix = string.Empty;

        var result = Validate(options);

        Assert.False(result.Failed);
    }

    [Fact]
    public void Validate_Succeeds_WhenApiPrefixHasValue()
    {
        var options = ValidOptions();
        options.Application.ApiPrefix = "/v2";

        var result = Validate(options);

        Assert.False(result.Failed);
    }

    // ---------------------------------------------------------------------------
    // Rule 2 — ClientUrl is required when EmailConfirmationMode == ClientForm
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_Fails_WhenClientFormModeAndClientUrlIsNull()
    {
        var options = ValidOptions();
        options.Application.EmailConfirmationMode = EmailConfirmationMode.ClientForm;
        options.Application.ClientUrl = null;

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ClientUrl)));
    }

    [Fact]
    public void Validate_Fails_WhenClientFormModeAndClientUrlIsWhitespace()
    {
        var options = ValidOptions();
        options.Application.EmailConfirmationMode = EmailConfirmationMode.ClientForm;
        options.Application.ClientUrl = "   ";

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ClientUrl)));
    }

    [Fact]
    public void Validate_Succeeds_WhenServerConfirmModeAndClientUrlIsNull()
    {
        // ClientUrl is only required for ClientForm mode; ServerConfirm does not need it.
        var options = ValidOptions();
        options.Application.EmailConfirmationMode = EmailConfirmationMode.ServerConfirm;
        options.Application.ClientUrl = null;

        var result = Validate(options);

        Assert.False(result.Failed);
    }

    // ---------------------------------------------------------------------------
    // Rule 3 — Form paths are required when ClientUrl is set
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_Fails_WhenClientUrlSetAndConfirmEmailFormPathIsNull()
    {
        var options = ValidOptions();
        options.Application.ClientUrl = "https://myapp.com";
        options.Application.ConfirmEmailFormPath = null!;

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ConfirmEmailFormPath)));
    }

    [Fact]
    public void Validate_Fails_WhenClientUrlSetAndConfirmEmailFormPathIsWhitespace()
    {
        var options = ValidOptions();
        options.Application.ClientUrl = "https://myapp.com";
        options.Application.ConfirmEmailFormPath = "  ";

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ConfirmEmailFormPath)));
    }

    [Fact]
    public void Validate_Fails_WhenClientUrlSetAndResetPasswordFormPathIsNull()
    {
        var options = ValidOptions();
        options.Application.ClientUrl = "https://myapp.com";
        options.Application.ResetPasswordFormPath = null!;

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ResetPasswordFormPath)));
    }

    [Fact]
    public void Validate_Fails_WhenClientUrlSetAndResetPasswordFormPathIsWhitespace()
    {
        var options = ValidOptions();
        options.Application.ClientUrl = "https://myapp.com";
        options.Application.ResetPasswordFormPath = "   ";

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ResetPasswordFormPath)));
    }

    [Fact]
    public void Validate_Fails_WhenClientUrlSetAndBothFormPathsAreInvalid()
    {
        var options = ValidOptions();
        options.Application.ClientUrl = "https://myapp.com";
        options.Application.ConfirmEmailFormPath = null!;
        options.Application.ResetPasswordFormPath = null!;

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ConfirmEmailFormPath)));
        Assert.Contains(result.Failures!, f => f.Contains(nameof(ApplicationOptions.ResetPasswordFormPath)));
    }

    [Fact]
    public void Validate_Succeeds_WhenClientUrlNullAndFormPathsAreNotChecked()
    {
        // When ClientUrl is null / not set, form paths are irrelevant and should not be checked.
        var options = ValidOptions();
        options.Application.EmailConfirmationMode = EmailConfirmationMode.ServerConfirm;
        options.Application.ClientUrl = null;
        options.Application.ConfirmEmailFormPath = null!;
        options.Application.ResetPasswordFormPath = null!;

        var result = Validate(options);

        Assert.False(result.Failed);
    }

    // ---------------------------------------------------------------------------
    // Rule 4 — DefaultTenantIdentifier must not be null or empty (const guard)
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_Succeeds_BecauseDefaultTenantIdentifierConstIsNeverNullOrEmpty()
    {
        // MultiTenantOptions.DefaultTenantIdentifier is a compile-time constant.
        // The validator checks it defensively; this test documents that the
        // constant is correctly set and the rule never fails under normal usage.
        var result = Validate(ValidOptions());

        Assert.False(result.Failed);
        Assert.False(string.IsNullOrWhiteSpace(MultiTenantOptions.DefaultTenantIdentifier));
    }

    // ---------------------------------------------------------------------------
    // Rule 5 — DefaultTenantName must not be null or empty
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_Fails_WhenDefaultTenantNameIsNull()
    {
        var options = ValidOptions();
        options.MultiTenant.DefaultTenantName = null!;

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(MultiTenantOptions.DefaultTenantName)));
    }

    [Fact]
    public void Validate_Fails_WhenDefaultTenantNameIsEmpty()
    {
        var options = ValidOptions();
        options.MultiTenant.DefaultTenantName = string.Empty;

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(MultiTenantOptions.DefaultTenantName)));
    }

    [Fact]
    public void Validate_Fails_WhenDefaultTenantNameIsWhitespace()
    {
        var options = ValidOptions();
        options.MultiTenant.DefaultTenantName = "   ";

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(MultiTenantOptions.DefaultTenantName)));
    }

    [Fact]
    public void Validate_Succeeds_WhenDefaultTenantNameHasValue()
    {
        var options = ValidOptions();
        options.MultiTenant.DefaultTenantName = "My System Tenant";

        var result = Validate(options);

        Assert.False(result.Failed);
    }

    // ---------------------------------------------------------------------------
    // Rule 6 — At least one strategy must be configured
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_Fails_WhenStrategiesIsEmpty()
    {
        var options = ValidOptions();
        options.MultiTenant.Strategies = [];

        var result = Validate(options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(MultiTenantOptions.Strategies)));
    }

    [Fact]
    public void Validate_Succeeds_WhenSingleStrategyConfigured()
    {
        var options = ValidOptions();
        options.MultiTenant.Strategies = [IdmtMultiTenantStrategy.Claim];

        var result = Validate(options);

        Assert.False(result.Failed);
    }

    [Fact]
    public void Validate_Succeeds_WhenMultipleStrategiesConfigured()
    {
        var options = ValidOptions();
        options.MultiTenant.Strategies =
        [
            IdmtMultiTenantStrategy.Header,
            IdmtMultiTenantStrategy.Claim,
            IdmtMultiTenantStrategy.Route
        ];

        var result = Validate(options);

        Assert.False(result.Failed);
    }

    // ---------------------------------------------------------------------------
    // Multiple failures — all violations are reported in a single pass
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_ReportsAllFailures_WhenMultipleRulesAreViolated()
    {
        var options = new IdmtOptions
        {
            Application = new ApplicationOptions
            {
                ApiPrefix = null!,
                EmailConfirmationMode = EmailConfirmationMode.ClientForm,
                ClientUrl = null          // violates rule 2
                                          // form paths are null but not checked because ClientUrl is null
            },
            MultiTenant = new MultiTenantOptions
            {
                DefaultTenantName = string.Empty,  // violates rule 5
                Strategies = []                    // violates rule 6
            }
        };

        var result = Validate(options);

        Assert.True(result.Failed);

        var failures = result.Failures!.ToList();

        // Rule 1: ApiPrefix is null
        Assert.Contains(failures, f => f.Contains(nameof(ApplicationOptions.ApiPrefix)));
        // Rule 2: ClientUrl missing for ClientForm mode
        Assert.Contains(failures, f => f.Contains(nameof(ApplicationOptions.ClientUrl)));
        // Rule 5: DefaultTenantName is empty
        Assert.Contains(failures, f => f.Contains(nameof(MultiTenantOptions.DefaultTenantName)));
        // Rule 6: no strategies
        Assert.Contains(failures, f => f.Contains(nameof(MultiTenantOptions.Strategies)));
    }

    // ---------------------------------------------------------------------------
    // Named-instance validation — validator handles null option name gracefully
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_Succeeds_WhenCalledWithExplicitNamedInstance()
    {
        var result = _sut.Validate("CustomName", ValidOptions());

        Assert.False(result.Failed);
    }

    [Fact]
    public void Validate_Fails_WithExplicitNamedInstance_WhenRulesAreViolated()
    {
        var options = ValidOptions();
        options.MultiTenant.Strategies = [];

        var result = _sut.Validate("CustomName", options);

        Assert.True(result.Failed);
    }
}
