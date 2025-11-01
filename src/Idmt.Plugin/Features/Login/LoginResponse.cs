using Microsoft.AspNetCore.Http;

namespace Idmt.Plugin.Features.Login;

public sealed record LoginResponse
{
    public bool Succeeded { get; init; }
    public bool IsLockedOut { get; init; }
    public bool IsNotAllowed { get; init; }
    public bool RequiresTwoFactor { get; init; }
    public int StatusCode { get; init; } = StatusCodes.Status401Unauthorized;
    public string? ErrorMessage { get; init; }
    public Dictionary<string, string>? ValidationErrors { get; init; }
}
