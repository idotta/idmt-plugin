using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Manage;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Validation;

public class UpdateUserInfoRequestValidator : AbstractValidator<UpdateUserInfo.UpdateUserInfoRequest>
{
    public UpdateUserInfoRequestValidator(IOptions<IdmtOptions> options)
    {
        When(x => !string.IsNullOrEmpty(x.NewPassword), () =>
        {
            RuleFor(x => x.OldPassword).NotEmpty()
                .WithMessage("Old password is required to change password");
        });

        When(x => x.NewEmail is not null, () =>
        {
            RuleFor(x => x.NewEmail).Must(Validators.IsValidEmail)
                .WithMessage("New email is not valid");
        });

        When(x => x.NewPassword is not null, () =>
        {
            RuleFor(x => x.NewPassword).Must(password =>
                Validators.IsValidNewPassword(password, options.Value.Identity.Password, out _))
                .WithMessage("Password does not meet requirements.");
        });
    }
}
