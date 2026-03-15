using FluentValidation;
using Idmt.Plugin.Features.Auth;

namespace Idmt.Plugin.Validation;

public class DiscoverTenantsRequestValidator : AbstractValidator<DiscoverTenants.DiscoverTenantsRequest>
{
    public DiscoverTenantsRequestValidator()
    {
        RuleFor(x => x.Email).Must(Validators.IsValidEmail)
            .WithMessage("Invalid email address.");
    }
}
