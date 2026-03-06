using FluentValidation;
using Idmt.Plugin.Features.Auth;

namespace Idmt.Plugin.Validation;

public class ForgotPasswordRequestValidator : AbstractValidator<ForgotPassword.ForgotPasswordRequest>
{
    public ForgotPasswordRequestValidator()
    {
        RuleFor(x => x.Email).Must(Validators.IsValidEmail)
            .WithMessage("Invalid email address.");
    }
}
