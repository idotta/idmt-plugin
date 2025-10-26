namespace Idmt.Plugin.Features.Logout;

/// <summary>
/// Logout request model
/// </summary>
public class LogoutRequest
{
    /// <summary>
    /// Optional refresh token to invalidate
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Whether to sign out from all devices
    /// </summary>
    public bool SignOutEverywhere { get; set; } = false;
}

/// <summary>
/// Logout response model
/// </summary>
public class LogoutResponse
{
    /// <summary>
    /// Indicates if logout was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Success message
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Error message if logout failed
    /// </summary>
    public string? ErrorMessage { get; set; }
}