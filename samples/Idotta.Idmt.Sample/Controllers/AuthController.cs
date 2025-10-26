using Microsoft.AspNetCore.Mvc;
using Idotta.Idmt.Plugin.Features.Login;
using Idotta.Idmt.Plugin.Features.Register;
using Idotta.Idmt.Plugin.Features.Logout;

namespace Idotta.Idmt.Sample.Controllers;

/// <summary>
/// Authentication controller demonstrating vertical slice handlers
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly LoginHandler _loginHandler;
    private readonly RegisterHandler _registerHandler;
    private readonly LogoutHandler _logoutHandler;

    public AuthController(
        LoginHandler loginHandler,
        RegisterHandler registerHandler,
        LogoutHandler logoutHandler)
    {
        _loginHandler = loginHandler;
        _registerHandler = registerHandler;
        _logoutHandler = logoutHandler;
    }

    /// <summary>
    /// Authenticates a user and returns a JWT token
    /// </summary>
    /// <param name="request">Login credentials</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Authentication response with token</returns>
    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), 200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<LoginResponse>> Login(
        [FromBody] LoginRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var response = await _loginHandler.HandleAsync(request, cancellationToken);
        
        if (!response.Success)
        {
            return BadRequest(response);
        }

        return Ok(response);
    }

    /// <summary>
    /// Registers a new user account
    /// </summary>
    /// <param name="request">Registration details</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Registration response</returns>
    [HttpPost("register")]
    [ProducesResponseType(typeof(RegisterResponse), 200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<RegisterResponse>> Register(
        [FromBody] RegisterRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var response = await _registerHandler.HandleAsync(request, cancellationToken);
        
        if (!response.Success)
        {
            return BadRequest(response);
        }

        return Ok(response);
    }

    /// <summary>
    /// Logs out the current user
    /// </summary>
    /// <param name="request">Logout request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Logout response</returns>
    [HttpPost("logout")]
    [ProducesResponseType(typeof(LogoutResponse), 200)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<LogoutResponse>> Logout(
        [FromBody] LogoutRequest request,
        CancellationToken cancellationToken = default)
    {
        var userId = HttpContext.User?.FindFirst("sub")?.Value;
        
        var response = await _logoutHandler.HandleAsync(request, userId, cancellationToken);
        
        if (!response.Success)
        {
            return BadRequest(response);
        }

        return Ok(response);
    }

    /// <summary>
    /// Confirms a user's email address
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="token">Confirmation token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Confirmation result</returns>
    [HttpGet("confirm-email")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> ConfirmEmail(
        string userId,
        string token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            return BadRequest("User ID and token are required");
        }

        var success = await _registerHandler.ConfirmEmailAsync(userId, token, cancellationToken);
        
        if (!success)
        {
            return BadRequest("Email confirmation failed");
        }

        return Ok(new { message = "Email confirmed successfully" });
    }
}