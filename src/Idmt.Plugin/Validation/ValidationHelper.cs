using FluentValidation;

namespace Idmt.Plugin.Validation;

public static class ValidationHelper
{
    public static Dictionary<string, string[]>? Validate<T>(T instance, IValidator<T> validator)
    {
        var result = validator.Validate(instance);
        if (result.IsValid)
            return null;

        return result.Errors
            .GroupBy(e => e.PropertyName)
            .ToDictionary(
                g => g.Key,
                g => g.Select(e => e.ErrorMessage).ToArray());
    }
}
