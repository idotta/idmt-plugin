using FluentValidation;
using Idmt.Plugin.Features.Auth;

namespace Idmt.Plugin.Validation;

public class ConfirmEmailRequestValidator : AbstractValidator<ConfirmEmail.ConfirmEmailRequest>
{
    public ConfirmEmailRequestValidator()
    {
        RuleFor(x => x.TenantIdentifier).NotEmpty()
            .WithMessage("Tenant identifier is required");

        RuleFor(x => x.Email).NotEmpty()
            .WithMessage("Email is required")
            .Must(Validators.IsValidEmail)
            .WithMessage("Invalid email address");

        RuleFor(x => x.Token).NotEmpty()
            .WithMessage("Token is required");
    }
}
