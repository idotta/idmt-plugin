using FluentValidation.TestHelper;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Features.Admin;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Validation;
using Microsoft.Extensions.Options;
using Moq;

namespace Idmt.UnitTests.Validation;

public class FluentValidatorTests
{
    private static IOptions<IdmtOptions> DefaultOptions()
    {
        var mock = new Mock<IOptions<IdmtOptions>>();
        mock.Setup(x => x.Value).Returns(new IdmtOptions());
        return mock.Object;
    }

    #region LoginRequestValidator

    [Fact]
    public void LoginRequestValidator_Fails_WhenNeitherEmailNorUsername()
    {
        var validator = new LoginRequestValidator();
        var request = new Login.LoginRequest { Password = "Test1234!" };
        var result = validator.TestValidate(request);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void LoginRequestValidator_Passes_WithEmail()
    {
        var validator = new LoginRequestValidator();
        var request = new Login.LoginRequest { Email = "user@example.com", Password = "Test1234!" };
        var result = validator.TestValidate(request);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void LoginRequestValidator_Passes_WithUsername()
    {
        var validator = new LoginRequestValidator();
        var request = new Login.LoginRequest { Username = "testuser", Password = "Test1234!" };
        var result = validator.TestValidate(request);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void LoginRequestValidator_Fails_WithEmptyPassword()
    {
        var validator = new LoginRequestValidator();
        var request = new Login.LoginRequest { Email = "user@example.com", Password = "" };
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Password);
    }

    #endregion

    #region CreateTenantRequestValidator

    [Fact]
    public void CreateTenantRequestValidator_Fails_WithUppercaseIdentifier()
    {
        var validator = new CreateTenantRequestValidator();
        var request = new CreateTenant.CreateTenantRequest("UPPERCASE", "Name");
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Identifier);
    }

    [Fact]
    public void CreateTenantRequestValidator_Passes_WithValidData()
    {
        var validator = new CreateTenantRequestValidator();
        var request = new CreateTenant.CreateTenantRequest("valid-tenant_1", "Name");
        var result = validator.TestValidate(request);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void CreateTenantRequestValidator_Fails_WithEmptyIdentifier()
    {
        var validator = new CreateTenantRequestValidator();
        var request = new CreateTenant.CreateTenantRequest("", "Name");
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Identifier);
    }

    #endregion

    #region RegisterUserRequestValidator

    [Fact]
    public void RegisterUserRequestValidator_Fails_WithInvalidEmail()
    {
        var validator = new RegisterUserRequestValidator(DefaultOptions());
        var request = new RegisterUser.RegisterUserRequest { Email = "not-an-email", Role = "Admin" };
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Email);
    }

    [Fact]
    public void RegisterUserRequestValidator_Fails_WithDisallowedUsernameChars()
    {
        var options = DefaultOptions();
        var validator = new RegisterUserRequestValidator(options);
        var request = new RegisterUser.RegisterUserRequest
        {
            Email = "user@example.com",
            Username = "user<script>",
            Role = "Admin"
        };
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Username);
    }

    [Fact]
    public void RegisterUserRequestValidator_Passes_WithValidData()
    {
        var validator = new RegisterUserRequestValidator(DefaultOptions());
        var request = new RegisterUser.RegisterUserRequest { Email = "user@example.com", Role = "Admin" };
        var result = validator.TestValidate(request);
        result.ShouldNotHaveAnyValidationErrors();
    }

    #endregion

    #region UpdateUserInfoRequestValidator

    [Fact]
    public void UpdateUserInfoRequestValidator_Fails_WhenNewPasswordWithoutOldPassword()
    {
        var validator = new UpdateUserInfoRequestValidator(DefaultOptions());
        var request = new UpdateUserInfo.UpdateUserInfoRequest(NewPassword: "NewPass1!");
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.OldPassword);
    }

    [Fact]
    public void UpdateUserInfoRequestValidator_Passes_WhenAllFieldsNull()
    {
        var validator = new UpdateUserInfoRequestValidator(DefaultOptions());
        var request = new UpdateUserInfo.UpdateUserInfoRequest();
        var result = validator.TestValidate(request);
        result.ShouldNotHaveAnyValidationErrors();
    }

    #endregion

    #region ConfirmEmailRequestValidator

    [Fact]
    public void ConfirmEmailRequestValidator_Fails_WithEmptyFields()
    {
        var validator = new ConfirmEmailRequestValidator();
        var request = new ConfirmEmail.ConfirmEmailRequest("", "", "");
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.TenantIdentifier);
        result.ShouldHaveValidationErrorFor(x => x.Email);
        result.ShouldHaveValidationErrorFor(x => x.Token);
    }

    #endregion

    #region ForgotPasswordRequestValidator

    [Fact]
    public void ForgotPasswordRequestValidator_Fails_WithInvalidEmail()
    {
        var validator = new ForgotPasswordRequestValidator();
        var request = new ForgotPassword.ForgotPasswordRequest("not-an-email");
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Email);
    }

    #endregion

    #region RefreshTokenRequestValidator

    [Fact]
    public void RefreshTokenRequestValidator_Fails_WithEmptyToken()
    {
        var validator = new RefreshTokenRequestValidator();
        var request = new RefreshToken.RefreshTokenRequest("");
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.RefreshToken);
    }

    #endregion

    #region ResetPasswordRequestValidator

    [Fact]
    public void ResetPasswordRequestValidator_Fails_WithWeakPassword()
    {
        var validator = new ResetPasswordRequestValidator(DefaultOptions());
        var request = new ResetPassword.ResetPasswordRequest("tenant1", "user@example.com", "valid-token", "weak");
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.NewPassword);
    }

    #endregion

    #region ResendConfirmationEmailRequestValidator

    [Fact]
    public void ResendConfirmationEmailRequestValidator_Fails_WithInvalidEmail()
    {
        var validator = new ResendConfirmationEmailRequestValidator();
        var request = new ResendConfirmationEmail.ResendConfirmationEmailRequest("invalid");
        var result = validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Email);
    }

    #endregion
}
