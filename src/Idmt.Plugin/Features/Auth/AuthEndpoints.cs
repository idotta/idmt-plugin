using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Auth.Manage;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Idmt.Plugin.Features.Auth;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var auth = endpoints.MapGroup("/auth")
            .WithTags("Authentication")
            .WithOpenApi();

        auth.MapPost("/login", LoginAsync)
            .WithSummary("Login user")
            .WithDescription("Authenticate user and return bearer token or cookie");

        auth.MapPost("/logout", LogoutAsync)
            .WithSummary("Logout user")
            .WithDescription("Logout user and invalidate bearer token or cookie");

        auth.MapPost("/refresh", RefreshAsync)
            .WithSummary("Refresh token")
            .WithDescription("Refresh JWT token using refresh token");

        auth.MapGet("/confirmEmail", ConfirmEmailAsync)
            .WithName(ApplicationOptions.ConfirmEmailEndpointName)
            .WithSummary("Confirm email")
            .WithDescription("Confirm user email address");

        auth.MapPost("/resendConfirmationEmail", ResendConfirmationEmailAsync)
            .WithSummary("Resend confirmation email")
            .WithDescription("Resend email confirmation link");

        auth.MapPost("/forgotPassword", ForgotPasswordAsync)
            .WithSummary("Forgot password")
            .WithDescription("Initiate password reset process");

        auth.MapPost("/resetPassword", ResetPasswordAsync)
            .WithName(ApplicationOptions.PasswordResetEndpointName)
            .WithSummary("Reset password")
            .WithDescription("Reset password using reset token");

        auth.MapGet("/resetPassword", RedirectToResetPasswordForm)
            .WithName(ApplicationOptions.PasswordResetEndpointName + "-form")
            .WithSummary("Redirect to reset password form")
            .WithDescription("Redirect to reset password form");

        auth.MapAuthManage();
    }

    private static async Task<Results<Ok<AccessTokenResponse>, ValidationProblem, EmptyHttpResult, ProblemHttpResult>> LoginAsync(
        [FromBody] Login.LoginRequest request,
        [FromServices] Login.ILoginHandler loginHandler,
        HttpContext context,
        [FromQuery] bool useCookies = false,
        [FromQuery] bool useSessionCookies = false)
    {
        if (request.Validate() is { } validationErrors)
        {
            return TypedResults.ValidationProblem(validationErrors);
        }

        var response = await loginHandler.HandleAsync(request, useCookies, useSessionCookies, cancellationToken: context.RequestAborted);

        if (!response.Succeeded)
        {
            return TypedResults.Problem(response.ErrorMessage, statusCode: response.StatusCode);
        }

        return TypedResults.Empty;
    }

    private static async Task<NoContent> LogoutAsync(
        [FromServices] Logout.ILogoutHandler logoutHandler,
        CancellationToken cancellationToken = default)
    {
        await logoutHandler.HandleAsync(cancellationToken);
        return TypedResults.NoContent();
    }

    private static async Task<Results<Ok<AccessTokenResponse>, SignInHttpResult, ChallengeHttpResult, ValidationProblem>> RefreshAsync(
        [FromBody] RefreshToken.RefreshTokenRequest request,
        [FromServices] RefreshToken.IRefreshTokenHandler handler,
        HttpContext context)
    {
        if (request.Validate() is { } validationErrors)
        {
            return TypedResults.ValidationProblem(validationErrors);
        }

        var response = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
        if (!response.Succeeded)
        {
            return TypedResults.Challenge();
        }
        return TypedResults.SignIn(response.ClaimsPrincipal!, authenticationScheme: IdentityConstants.BearerScheme);
    }

    private static async Task<Results<Ok<ConfirmEmail.ConfirmEmailResponse>, ValidationProblem>> ConfirmEmailAsync(
        [FromQuery] string tenantId,
        [FromQuery] string email,
        [FromQuery] string token,
        [FromServices] ConfirmEmail.IConfirmEmailHandler handler,
        HttpContext context)
    {
        var request = new ConfirmEmail.ConfirmEmailRequest(tenantId, email, token);
        if (request.Validate() is { } validationErrors)
        {
            return TypedResults.ValidationProblem(validationErrors);
        }
        try
        {
            using var _ = new ManualTenantResolver(context, tenantId);
            var result = await handler.HandleAsync(request, cancellationToken: context.RequestAborted);
            return TypedResults.Ok(result);
        }
        catch (InvalidOperationException)
        {
            return TypedResults.Ok(new ConfirmEmail.ConfirmEmailResponse(false, "Invalid tenant context"));
        }
    }

    private static async Task<Results<Ok<ResendConfirmationEmail.ResendConfirmationEmailResponse>, ValidationProblem>> ResendConfirmationEmailAsync(
        [FromQuery] bool useApiLinks,
        [FromBody] ResendConfirmationEmail.ResendConfirmationEmailRequest request,
        [FromServices] ResendConfirmationEmail.IResendConfirmationEmailHandler handler,
        HttpContext context)
    {
        if (request.Validate() is { } validationErrors)
        {
            return TypedResults.ValidationProblem(validationErrors);
        }

        var result = await handler.HandleAsync(useApiLinks, request, cancellationToken: context.RequestAborted);
        return TypedResults.Ok(result);
    }

    private static async Task<Results<Ok<ForgotPassword.ForgotPasswordResponse>, ValidationProblem>> ForgotPasswordAsync(
        [FromQuery] bool useApiLinks,
        [FromBody] ForgotPassword.ForgotPasswordRequest request,
        [FromServices] ForgotPassword.IForgotPasswordHandler handler,
        HttpContext context)
    {
        if (request.Validate() is { } validationErrors)
        {
            return TypedResults.ValidationProblem(validationErrors);
        }

        var result = await handler.HandleAsync(useApiLinks, request, cancellationToken: context.RequestAborted);
        return TypedResults.Ok(result);
    }

    private static async Task<Results<Ok<ResetPassword.ResetPasswordResponse>, ValidationProblem, ForbidHttpResult>> ResetPasswordAsync(
        [FromQuery] string tenantId,
        [FromQuery] string email,
        [FromQuery] string token,
        [FromBody] ResetPassword.ResetPasswordRequest request,
        [FromServices] ResetPassword.IResetPasswordHandler handler,
        [FromServices] IOptions<IdmtOptions> options,
        HttpContext context)
    {
        if (request.Validate(tenantId, email, token, options.Value.Identity.Password) is { } validationErrors)
        {
            return TypedResults.ValidationProblem(validationErrors);
        }
        try
        {
            using var _ = new ManualTenantResolver(context, tenantId);
            var result = await handler.HandleAsync(tenantId, email, token, request, cancellationToken: context.RequestAborted);
            if (!result.Success)
            {
                return TypedResults.Forbid();
            }
            return TypedResults.Ok(result);
        }
        catch (InvalidOperationException)
        {
            return TypedResults.Forbid();
        }
    }

    private static Results<RedirectHttpResult, ProblemHttpResult> RedirectToResetPasswordForm(
        [FromQuery] string tenantId,
        [FromQuery] string email,
        [FromQuery] string token,
        [FromServices] IOptions<IdmtOptions> options,
        HttpContext context)
    {
        var clientUrl = options.Value.Application.ClientUrl;
        var resetPasswordPath = options.Value.Application.ResetPasswordFormPath;

        if (string.IsNullOrEmpty(clientUrl))
        {
            return TypedResults.Problem("Client URL is not configured.");
        }

        var queryParams = new Dictionary<string, string?>
        {
            ["tenantId"] = tenantId,
            ["email"] = email,
            ["token"] = token
        };

        var uri = Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(
            $"{clientUrl.TrimEnd('/')}/{resetPasswordPath.TrimStart('/')}",
            queryParams);

        return TypedResults.Redirect(uri);
    }
}