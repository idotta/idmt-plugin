using System.Text;
using Microsoft.AspNetCore.WebUtilities;

internal static class Base64Service
{
    internal static string DecodeBase64UrlToken(string encodedToken)
    {
        var bytes = WebEncoders.Base64UrlDecode(encodedToken);
        return Encoding.UTF8.GetString(bytes);
    }
}