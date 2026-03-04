using FluentValidation;
using Idmt.Plugin.Features.Auth;

namespace Idmt.Plugin.Validation;

public class ResendConfirmationEmailRequestValidator : AbstractValidator<ResendConfirmationEmail.ResendConfirmationEmailRequest>
{
    public ResendConfirmationEmailRequestValidator()
    {
        RuleFor(x => x.Email).Must(Validators.IsValidEmail)
            .WithMessage("Invalid email address.");
    }
}
