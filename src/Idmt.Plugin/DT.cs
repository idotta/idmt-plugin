namespace Idmt.Plugin;

/// <summary>
/// DateTime substiute to guarantee UTC timezone
/// </summary>
public static class DT
{
    public static DateTime UtcNow => DateTime.UtcNow;
    public static DateTimeOffset UtcNowOffset => DateTimeOffset.UtcNow;
}