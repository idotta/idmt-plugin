using FluentValidation;
using Idmt.Plugin.Features.Admin;

namespace Idmt.Plugin.Validation;

public class CreateTenantRequestValidator : AbstractValidator<CreateTenant.CreateTenantRequest>
{
    public CreateTenantRequestValidator()
    {
        RuleFor(x => x.Identifier).NotEmpty()
            .WithMessage("Identifier is required")
            .MinimumLength(3)
            .WithMessage("Identifier must be at least 3 characters")
            .Must(Validators.IsValidTenantIdentifier)
            .WithMessage("Identifier can only contain lowercase alphanumeric characters, dashes, and underscores");

        RuleFor(x => x.Name).NotEmpty()
            .WithMessage("Name is required")
            .MaximumLength(200)
            .WithMessage("Name must not exceed 200 characters");
    }
}
