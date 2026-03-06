using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Auth;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Validation;

public class ResetPasswordRequestValidator : AbstractValidator<ResetPassword.ResetPasswordRequest>
{
    public ResetPasswordRequestValidator(IOptions<IdmtOptions> options)
    {
        RuleFor(x => x.TenantIdentifier).NotEmpty()
            .WithMessage("Tenant identifier is required.");

        RuleFor(x => x.Email).NotEmpty()
            .WithMessage("Email is required.")
            .Must(Validators.IsValidEmail)
            .WithMessage("Invalid email address.");

        RuleFor(x => x.Token).NotEmpty()
            .WithMessage("Token is required.");

        RuleFor(x => x.NewPassword).Must(password =>
            Validators.IsValidNewPassword(password, options.Value.Identity.Password, out _))
            .WithMessage("Password does not meet requirements.");
    }
}
