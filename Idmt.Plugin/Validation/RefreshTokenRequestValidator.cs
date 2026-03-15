using FluentValidation;
using Idmt.Plugin.Features.Auth;

namespace Idmt.Plugin.Validation;

public class RefreshTokenRequestValidator : AbstractValidator<RefreshToken.RefreshTokenRequest>
{
    public RefreshTokenRequestValidator()
    {
        RuleFor(x => x.RefreshToken).NotEmpty()
            .WithMessage("Refresh token is required.");
    }
}
