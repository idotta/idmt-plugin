using FluentValidation;
using Idmt.Plugin.Features.Auth;

namespace Idmt.Plugin.Validation;

public class ConfirmEmailChangeRequestValidator : AbstractValidator<ConfirmEmailChange.ConfirmEmailChangeRequest>
{
    public ConfirmEmailChangeRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty()
            .WithMessage("Email is required")
            .Must(Validators.IsValidEmail)
            .WithMessage("Invalid email address");

        RuleFor(x => x.NewEmail).NotEmpty()
            .WithMessage("New email is required")
            .Must(Validators.IsValidEmail)
            .WithMessage("Invalid new email address");

        RuleFor(x => x.Token).NotEmpty()
            .WithMessage("Token is required");
    }
}
