using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Auth;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Validation;

public class ResetPasswordRequestValidator : AbstractValidator<ResetPassword.ResetPasswordRequest>
{
    public ResetPasswordRequestValidator(IOptions<IdmtOptions> options)
    {
        RuleFor(x => x.NewPassword).Must(password =>
            Validators.IsValidNewPassword(password, options.Value.Identity.Password, out _))
            .WithMessage("Password does not meet requirements.");
    }
}
