using FluentValidation;
using Idmt.Plugin.Features.Auth;

namespace Idmt.Plugin.Validation;

public class LoginRequestValidator : AbstractValidator<Login.LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x).Must(x => x.Email is not null || x.Username is not null)
            .WithMessage("Email or Username is required.")
            .WithName("Identifier");

        When(x => x.Email is not null, () =>
        {
            RuleFor(x => x.Email).Must(Validators.IsValidEmail)
                .WithMessage("Invalid email.");
        });

        When(x => x.Username is not null, () =>
        {
            RuleFor(x => x.Username).Must(Validators.IsValidUsername)
                .WithMessage("Invalid username.");
        });

        RuleFor(x => x.Password).NotEmpty()
            .WithMessage("Password is required.");
    }
}
