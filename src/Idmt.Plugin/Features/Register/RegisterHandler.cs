namespace Idmt.Plugin.Features.Register;

internal sealed class RegisterHandler : IRegisterHandler
{
    public async Task<RegisterResponse> HandleAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            return new RegisterResponse
            {
            };
        }
        catch (Exception ex)
        {
            return new RegisterResponse
            {
                Success = false,
                ErrorMessage = "An error occurred during registration",
                Errors = [ex.Message]
            };
        }
    }
}