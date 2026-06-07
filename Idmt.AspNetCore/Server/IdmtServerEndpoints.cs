namespace Idmt.AspNetCore.Server;

/// <summary>
/// The interactive protocol endpoint URIs set explicitly on the server. The
/// remaining endpoints (introspection, revocation, userinfo) follow OpenIddict's
/// standard <c>/connect/*</c> conventions.
/// </summary>
public static class IdmtServerEndpoints
{
    /// <summary>Where all grants exchange for tokens.</summary>
    public const string Token = "/connect/token";

    /// <summary>Where the authorization-code flow runs the interactive sign-in.</summary>
    public const string Authorization = "/connect/authorize";
}
