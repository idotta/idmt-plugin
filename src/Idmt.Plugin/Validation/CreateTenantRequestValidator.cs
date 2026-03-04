using FluentValidation;
using Idmt.Plugin.Features.Admin;

namespace Idmt.Plugin.Validation;

public class CreateTenantRequestValidator : AbstractValidator<CreateTenant.CreateTenantRequest>
{
    public CreateTenantRequestValidator()
    {
        RuleFor(x => x.Identifier).NotEmpty()
            .WithMessage("Identifier is required")
            .Must(Validators.IsValidTenantIdentifier)
            .WithMessage("Identifier can only contain lowercase alphanumeric characters, dashes, and underscores");

        RuleFor(x => x.Name).NotEmpty()
            .WithMessage("Name is required");

        RuleFor(x => x.DisplayName).NotEmpty()
            .WithMessage("Display Name is required");
    }
}
