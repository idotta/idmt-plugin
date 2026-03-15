using FluentValidation;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Manage;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Validation;

public class RegisterUserRequestValidator : AbstractValidator<RegisterUser.RegisterUserRequest>
{
    public RegisterUserRequestValidator(IOptions<IdmtOptions> options)
    {
        RuleFor(x => x.Email).Must(Validators.IsValidEmail)
            .WithMessage("Invalid email address.");

        When(x => x.Username is not null, () =>
        {
            var allowedChars = options.Value.Identity.User.AllowedUserNameCharacters;
            When(_ => !string.IsNullOrEmpty(allowedChars), () =>
            {
                RuleFor(x => x.Username)
                    .Must(username => username!.All(c => allowedChars.Contains(c)))
                    .WithMessage($"Username must contain only the following characters: {allowedChars}");
            });
        });

        RuleFor(x => x.Role).NotEmpty()
            .WithMessage("Role is required.");
    }
}
