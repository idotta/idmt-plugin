namespace Idmt.Plugin.Services;

/// <summary>
/// Utility for masking personally identifiable information in log output.
/// </summary>
internal static class PiiMasker
{
    /// <summary>
    /// Masks an email address, keeping only the first 3 characters visible.
    /// </summary>
    public static string MaskEmail(string? email)
    {
        if (string.IsNullOrEmpty(email)) return "***";
        return email.Length > 3 ? string.Concat(email.AsSpan(0, 3), "***") : "***";
    }
}
