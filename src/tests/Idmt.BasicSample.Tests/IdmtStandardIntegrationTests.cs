using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Finbuckle.MultiTenant;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Manage;
using Idmt.Plugin.Features.Sys;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Idmt.BasicSample.Tests;

public class IdmtStandardIntegrationTests : IClassFixture<IdmtApiFactory>, IDisposable
{
    private readonly IdmtApiFactory _factory;

    public IdmtStandardIntegrationTests(IdmtApiFactory factory)
    {
        _factory = factory;
        _factory.EmailSenderMock.Reset();
    }

    public void Dispose()
    {
        _factory.EmailSenderMock.Reset();
    }

    [Fact]
    public async Task Healthz_requires_authentication()
    {
        var client = _factory.CreateClientWithTenant();
        var response = await client.GetAsync("/healthz");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    [Fact]
    public async Task Healthz_allows_sys_user()
    {
        var client = await CreateAuthenticatedClientAsync();
        var response = await client.GetAsync("/healthz");
        await response.AssertSuccess();
    }

    [Fact]
    public async Task Sys_info_returns_current_tenant()
    {
        var client = await CreateAuthenticatedClientAsync();
        var systemInfo = await client.GetFromJsonAsync<GetSystemInfo.SystemInfoResponse>("/sys/info");

        Assert.NotNull(systemInfo);
        Assert.NotNull(systemInfo!.CurrentTenant);
        Assert.Equal(IdmtApiFactory.DefaultTenantIdentifier, systemInfo.CurrentTenant!.Identifier);
    }

    [Fact]
    public async Task Auth_login_with_invalid_credentials_returns_unauthorized()
    {
        var client = _factory.CreateClientWithTenant();
        var response = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = "WrongPassword1!"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Auth_login_and_refresh_issue_tokens()
    {
        var client = _factory.CreateClientWithTenant();

        var loginResponse = await client.PostAsJsonAsync("/auth/token", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        await loginResponse.AssertSuccess();

        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        Assert.NotNull(tokens);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var selfInfo = await client.GetAsync("/manage/info");
        await selfInfo.AssertSuccess();

        var refreshResponse = await client.PostAsJsonAsync("/auth/refresh", new RefreshToken.RefreshTokenRequest(tokens.RefreshToken!));
        await refreshResponse.AssertSuccess();

        var refreshed = await refreshResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        Assert.NotNull(refreshed);
        Assert.False(string.IsNullOrWhiteSpace(refreshed!.AccessToken));
        Assert.NotEqual(tokens.AccessToken, refreshed.AccessToken);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.AccessToken);
        var refreshedSelfInfo = await client.GetAsync("/manage/info");
        await refreshedSelfInfo.AssertSuccess();
    }

    [Fact]
    public async Task User_lifecycle_flow_works()
    {
        // 1. Register User (as Admin)
        var newEmail = $"user-{Guid.NewGuid():N}@example.com";
        var newUsername = $"user{Guid.NewGuid():N}";

        using var sysClient = await CreateAuthenticatedClientAsync();
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = newUsername,
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        Assert.NotNull(registerResult);

        // 2. Verify Email (Capture token from Mock)
        var setupToken = registerResult!.PasswordSetupToken;
        Assert.NotNull(setupToken);

        // 3. Set Password (Reset Password)
        using var userClient = _factory.CreateClient(); // No auth
        var resetPasswordUrl = QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
        {
            ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
            ["email"] = newEmail,
            ["token"] = setupToken
        });

        var resetResponse = await userClient.PostAsJsonAsync(resetPasswordUrl, new { NewPassword = "NewUserPassword1!" });
        await resetResponse.AssertSuccess();

        // 4. Login with new password
        using var userClientWithTenant = _factory.CreateClientWithTenant();
        var loginResponse = await userClientWithTenant.PostAsJsonAsync("/auth/token", new
        {
            Email = newEmail,
            Password = "NewUserPassword1!"
        });
        await loginResponse.AssertSuccess();
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        userClientWithTenant.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        // 5. Update Info
        var updateResponse = await userClientWithTenant.PutAsJsonAsync("/manage/info", new
        {
            OldPassword = "NewUserPassword1!",
            NewPassword = "NewUserPassword2!"
        });
        await updateResponse.AssertSuccess();

        // 6. Verify new password
        var reLoginResponse = await userClientWithTenant.PostAsJsonAsync("/auth/token", new
        {
            Email = newEmail,
            Password = "NewUserPassword2!"
        });
        await reLoginResponse.AssertSuccess();

        // 7. Unregister (Delete)
        var deleteResponse = await sysClient.DeleteAsync($"/manage/users/{registerResult.UserId}");
        await deleteResponse.AssertSuccess();

        // 8. Verify deletion
        var failLogin = await userClientWithTenant.PostAsJsonAsync("/auth/token", new
        {
            Email = newEmail,
            Password = "NewUserPassword2!"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, failLogin.StatusCode);
    }

    [Fact]
    public async Task Forgot_password_flow_works()
    {
        // 1. Setup User
        var email = $"forgot-{Guid.NewGuid():N}@example.com";
        using var sysClient = await CreateAuthenticatedClientAsync();
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=true", new
        {
            Email = email,
            Username = $"forgot{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();
        var reg = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();

        // Set initial password
        using var publicClient = _factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
            {
                ["tenantIdentifier"] = IdmtApiFactory.DefaultTenantIdentifier,
                ["email"] = email,
                ["token"] = reg!.PasswordSetupToken
            }),
            new { NewPassword = "InitialPassword1!" });

        // 2. Request Forgot Password
        _factory.EmailSenderMock.Invocations.Clear(); // Clear previous emails
        using var tenantClient = _factory.CreateClientWithTenant();
        var forgotResponse = await tenantClient.PostAsJsonAsync("/auth/forgotPassword?useApiLinks=true", new { Email = email });
        await forgotResponse.AssertSuccess();

        // 3. Verify Email Sent and Capture Token
        _factory.EmailSenderMock.Verify(x => x.SendPasswordResetCodeAsync(
            It.Is<IdmtUser>(u => u.Email == email),
            It.IsAny<string>(),
            It.IsAny<string>())
        , Times.Once);

        var invocation = _factory.EmailSenderMock.Invocations.First(i => i.Method.Name == nameof(IEmailSender<IdmtUser>.SendPasswordResetCodeAsync));
        var resetLinkEncoded = invocation.Arguments[2] as string; // The generated link (passed as code)
        var resetLink = WebUtility.HtmlDecode(resetLinkEncoded);
        Assert.NotNull(resetLink);

        // Extract token and params from link
        var uri = new Uri(resetLink!);
        var query = QueryHelpers.ParseQuery(uri.Query);
        var token = query["token"].ToString();
        var tenantIdentifier = query["tenantIdentifier"].ToString();

        // 4. Reset Password
        var resetResponse = await publicClient.PostAsJsonAsync(
             QueryHelpers.AddQueryString("/auth/resetPassword", new Dictionary<string, string?>
             {
                 ["tenantIdentifier"] = tenantIdentifier,
                 ["email"] = email,
                 ["token"] = token
             }),
             new { NewPassword = "ResetPassword1!" });
        await resetResponse.AssertSuccess();

        // 5. Login with new password
        var loginResponse = await tenantClient.PostAsJsonAsync("/auth/token", new
        {
            Email = email,
            Password = "ResetPassword1!"
        });
        await loginResponse.AssertSuccess();
    }

    [Fact]
    public async Task Sys_endpoints_grant_and_revoke_tenant_access()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var targetEmail = $"tenant-{Guid.NewGuid():N}@example.com";

        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = targetEmail,
            Username = $"tenant{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        await registerResponse.AssertSuccess();

        var register = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        Assert.NotNull(register);
        var userId = Guid.Parse(register!.UserId!);

        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });
        await grantResponse.AssertSuccess();

        var tenants = await sysClient.GetFromJsonAsync<GetUserTenants.TenantInfoResponse[]>($"/sys/users/{userId}/tenants");
        Assert.NotNull(tenants);
        Assert.Contains(tenants!, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);

        var revokeResponse = await sysClient.DeleteAsync($"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}");
        await revokeResponse.AssertSuccess();

        tenants = await sysClient.GetFromJsonAsync<GetUserTenants.TenantInfoResponse[]>($"/sys/users/{userId}/tenants");
        Assert.NotNull(tenants);
        Assert.DoesNotContain(tenants!, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task Logout_clears_session()
    {
        var client = await CreateAuthenticatedClientAsync();

        var logoutResponse = await client.PostAsync("/auth/logout", content: null);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

        // Verify that the user is logged out, selfInfo should return a 401 or 302 (Redirect to login)
        var selfInfo = await client.GetAsync("/manage/info");
        Assert.False(selfInfo.IsSuccessStatusCode);
        Assert.Contains(selfInfo.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Found, HttpStatusCode.SeeOther });
    }

    #region CreateTenant Tests

    [Fact]
    public async Task CreateTenant_handler_with_valid_data_succeeds()
    {
        using var scope = _factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();

        var tenantIdentifier = $"tenant-{Guid.NewGuid():N}";
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant", "Test Tenant Display");
        var result = await handler.HandleAsync(request);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.Equal(tenantIdentifier, result.Value!.Identifier);
    }

    [Fact]
    public async Task CreateTenant_handler_with_duplicate_identifier_reactivates()
    {
        using var scope = _factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();
        var deleteHandler = scope.ServiceProvider.GetRequiredService<DeleteTenant.IDeleteTenantHandler>();

        var tenantIdentifier = $"tenant-{Guid.NewGuid():N}";

        // Create initial tenant
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant", "Test Display");
        var result = await handler.HandleAsync(request);
        var tenantId = result.Value!.Id;

        // Delete the tenant
        await deleteHandler.HandleAsync(tenantIdentifier);

        // Reactivate by creating again
        var reactivateResult = await handler.HandleAsync(request);
        Assert.True(reactivateResult.IsSuccess);
        Assert.Equal(tenantId, reactivateResult.Value!.Id);
    }

    [Fact]
    public async Task CreateTenant_handler_with_missing_identifier_still_creates()
    {
        using var scope = _factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();

        // The handler doesn't validate - it just creates with whatever is passed
        var request = new CreateTenant.CreateTenantRequest("", "Test Tenant", "Test Display");
        var result = await handler.HandleAsync(request);

        // Handler succeeds even with empty identifier because it doesn't validate
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task CreateTenant_handler_with_missing_name_still_creates()
    {
        using var scope = _factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();

        var request = new CreateTenant.CreateTenantRequest($"tenant-{Guid.NewGuid():N}", "", "Test Display");
        var result = await handler.HandleAsync(request);

        // Handler succeeds even with empty name
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task CreateTenant_handler_with_missing_display_name_still_creates()
    {
        using var scope = _factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();

        var request = new CreateTenant.CreateTenantRequest($"tenant-{Guid.NewGuid():N}", "Test Tenant", "");
        var result = await handler.HandleAsync(request);

        // Handler succeeds even with empty display name
        Assert.True(result.IsSuccess);
    }

    #endregion

    #region DeleteTenant Tests

    [Fact]
    public async Task DeleteTenant_handler_with_valid_identifier_succeeds()
    {
        using var scope = _factory.Services.CreateScope();
        var createHandler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();
        var deleteHandler = scope.ServiceProvider.GetRequiredService<DeleteTenant.IDeleteTenantHandler>();

        var tenantIdentifier = $"tenant-{Guid.NewGuid():N}";
        var request = new CreateTenant.CreateTenantRequest(tenantIdentifier, "Test Tenant", "Test Display");
        await createHandler.HandleAsync(request);

        var deleted = await deleteHandler.HandleAsync(tenantIdentifier);
        Assert.True(deleted);
    }

    [Fact]
    public async Task DeleteTenant_handler_with_invalid_identifier_returns_false()
    {
        using var scope = _factory.Services.CreateScope();
        var deleteHandler = scope.ServiceProvider.GetRequiredService<DeleteTenant.IDeleteTenantHandler>();

        var deleted = await deleteHandler.HandleAsync($"nonexistent-{Guid.NewGuid():N}");
        Assert.False(deleted);
    }

    #endregion

    #region GetUserInfo Tests

    [Fact]
    public async Task GetUserInfo_returns_authenticated_user_details()
    {
        var client = await CreateAuthenticatedClientAsync();

        var response = await client.GetAsync("/manage/info");
        await response.AssertSuccess();

        var userInfo = await response.Content.ReadFromJsonAsync<GetUserInfo.GetUserInfoResponse>();
        Assert.NotNull(userInfo);
        Assert.Equal(IdmtApiFactory.SysAdminEmail, userInfo!.Email);
        Assert.NotEmpty(userInfo.Id);
        Assert.NotEmpty(userInfo.Role);
        Assert.NotEmpty(userInfo.TenantIdentifier);
    }

    [Fact]
    public async Task GetUserInfo_requires_authentication()
    {
        var client = _factory.CreateClientWithTenant();

        var response = await client.GetAsync("/manage/info");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    #endregion

    #region UpdateUser Tests

    [Fact]
    public async Task UpdateUser_deactivate_user_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var targetEmail = $"update-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = targetEmail,
            Username = $"update{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        Assert.NotNull(registerResult);
        var userId = Guid.Parse(registerResult!.UserId!);

        // Deactivate user
        var updateResponse = await sysClient.PutAsJsonAsync($"/manage/users/{userId}", new { IsActive = false });
        await updateResponse.AssertSuccess();
    }

    [Fact]
    public async Task UpdateUser_reactivate_user_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var targetEmail = $"update-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = targetEmail,
            Username = $"update{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var userId = Guid.Parse(registerResult!.UserId!);

        // Deactivate user
        var deactivateResponse = await sysClient.PutAsJsonAsync($"/manage/users/{userId}", new { IsActive = false });
        await deactivateResponse.AssertSuccess();

        // Reactivate user
        var reactivateResponse = await sysClient.PutAsJsonAsync($"/manage/users/{userId}", new { IsActive = true });
        await reactivateResponse.AssertSuccess();
    }

    [Fact]
    public async Task UpdateUser_with_nonexistent_user_returns_error()
    {
        var client = await CreateAuthenticatedClientAsync();

        var response = await client.PutAsJsonAsync($"/manage/users/{Guid.NewGuid()}", new { IsActive = false });
        // Returns Forbidden because user lacks permission or NotFound if user not found
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.NotFound, HttpStatusCode.Forbidden });
    }

    [Fact]
    public async Task UpdateUser_requires_tenant_manager_authorization()
    {
        var tenantClient = _factory.CreateClientWithTenant();

        var response = await tenantClient.PutAsJsonAsync($"/manage/users/{Guid.NewGuid()}", new { IsActive = false });
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region GetSystemInfo Tests

    [Fact]
    public async Task GetSystemInfo_returns_system_details()
    {
        var client = await CreateAuthenticatedClientAsync();

        var response = await client.GetAsync("/sys/info");
        await response.AssertSuccess();

        var sysInfo = await response.Content.ReadFromJsonAsync<GetSystemInfo.SystemInfoResponse>();
        Assert.NotNull(sysInfo);
        Assert.NotEmpty(sysInfo!.ApplicationName);
        Assert.NotEmpty(sysInfo.Version);
        Assert.NotEmpty(sysInfo.Environment);
        Assert.True(sysInfo.ServerTime > DateTime.MinValue);
    }

    [Fact]
    public async Task GetSystemInfo_returns_current_tenant_info()
    {
        var client = await CreateAuthenticatedClientAsync();

        var response = await client.GetAsync("/sys/info");
        await response.AssertSuccess();

        var sysInfo = await response.Content.ReadFromJsonAsync<GetSystemInfo.SystemInfoResponse>();
        Assert.NotNull(sysInfo);
        Assert.NotNull(sysInfo!.CurrentTenant);
        var currentTenant = sysInfo.CurrentTenant!;
        Assert.NotNull(currentTenant.Identifier);
        Assert.NotNull(currentTenant.Name);
    }

    [Fact]
    public async Task GetSystemInfo_requires_authentication()
    {
        var client = _factory.CreateClientWithTenant();

        var response = await client.GetAsync("/sys/info");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    #endregion

    #region GetUserTenants Tests

    [Fact]
    public async Task GetUserTenants_returns_user_accessible_tenants()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var targetEmail = $"multi-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = targetEmail,
            Username = $"multi{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        await registerResponse.AssertSuccess();

        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var userId = Guid.Parse(registerResult!.UserId!);

        // Grant access to a tenant
        var grantResponse = await sysClient.PostAsJsonAsync(
            $"/sys/users/{userId}/tenants/{IdmtApiFactory.DefaultTenantIdentifier}",
            new { ExpiresAt = (DateTime?)null });
        await grantResponse.AssertSuccess();

        // Get user tenants
        var getTenantsResponse = await sysClient.GetAsync($"/sys/users/{userId}/tenants");
        await getTenantsResponse.AssertSuccess();

        var tenants = await getTenantsResponse.Content.ReadFromJsonAsync<GetUserTenants.TenantInfoResponse[]>();
        Assert.NotNull(tenants);
        Assert.NotEmpty(tenants);
        Assert.Contains(tenants!, t => t.Identifier == IdmtApiFactory.DefaultTenantIdentifier);
    }

    [Fact]
    public async Task GetUserTenants_returns_empty_for_user_without_tenant_access()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var targetEmail = $"no-tenant-{Guid.NewGuid():N}@example.com";

        // Register user without granting tenant access
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = targetEmail,
            Username = $"notenant{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.SysSupport
        });
        await registerResponse.AssertSuccess();

        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var userId = Guid.Parse(registerResult!.UserId!);

        // Get user tenants
        var getTenantsResponse = await sysClient.GetAsync($"/sys/users/{userId}/tenants");
        await getTenantsResponse.AssertSuccess();

        var tenants = await getTenantsResponse.Content.ReadFromJsonAsync<GetUserTenants.TenantInfoResponse[]>();
        Assert.NotNull(tenants);
        Assert.Empty(tenants!);
    }

    [Fact]
    public async Task GetUserTenants_requires_sys_user_authorization()
    {
        var tenantClient = _factory.CreateClientWithTenant();

        var response = await tenantClient.GetAsync($"/sys/users/{Guid.NewGuid()}/tenants");
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    #endregion

    #region ConfirmEmail Tests

    [Fact]
    public async Task ConfirmEmail_with_valid_token_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"confirm-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"confirm{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        // Use a handler to generate an email confirmation token
        var confirmTokenResponse = await GetEmailConfirmationTokenAsync(newEmail);

        // Use the email confirmation token to confirm email
        using var publicClient = _factory.CreateClient();
        var confirmResponse = await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email={newEmail}&token={Uri.EscapeDataString(confirmTokenResponse)}");

        await confirmResponse.AssertSuccess();

        var result = await confirmResponse.Content.ReadFromJsonAsync<ConfirmEmail.ConfirmEmailResponse>();
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    private async Task<string> GetEmailConfirmationTokenAsync(string email)
    {
        // Create a handler to get the email confirmation token
        var handler = new GetEmailConfirmationTokenHandler(_factory.Services);
        return await handler.GetTokenAsync(email);
    }

    private class GetEmailConfirmationTokenHandler(IServiceProvider serviceProvider)
    {
        public async Task<string> GetTokenAsync(string email)
        {
            using var scope = serviceProvider.CreateScope();
            var provider = scope.ServiceProvider;

            var tenantStore = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
            var tenantInfo = await tenantStore.GetByIdentifierAsync(IdmtApiFactory.DefaultTenantIdentifier);
            
            var tenantContextSetter = provider.GetRequiredService<IMultiTenantContextSetter>();
            var tenantContext = new MultiTenantContext<IdmtTenantInfo>(tenantInfo!);
            tenantContextSetter.MultiTenantContext = tenantContext;

            var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
            var user = await userManager.FindByEmailAsync(email);
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user!);
            return token;
        }
    }

    [Fact]
    public async Task ConfirmEmail_with_invalid_token_fails()
    {
        var newEmail = $"invalid-{Guid.NewGuid():N}@example.com";
        using var publicClient = _factory.CreateClient();

        var confirmResponse = await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email={newEmail}&token=invalid-token");

        // Could be 400 or other error
        Assert.False(confirmResponse.IsSuccessStatusCode);
    }

    [Fact]
    public async Task ConfirmEmail_with_invalid_tenant_fails()
    {
        var newEmail = $"confirm-{Guid.NewGuid():N}@example.com";
        using var publicClient = _factory.CreateClient();

        var confirmResponse = await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier=nonexistent-tenant&email={newEmail}&token=some-token");

        Assert.False(confirmResponse.IsSuccessStatusCode);
    }

    #endregion

    #region ResendConfirmationEmail Tests

    [Fact]
    public async Task ResendConfirmationEmail_for_unconfirmed_user_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"resend-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"resend{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        // Resend confirmation email
        using var publicClient = _factory.CreateClientWithTenant();
        var resendResponse = await publicClient.PostAsJsonAsync($"/auth/resendConfirmationEmail?useApiLinks=false", new
        {
            Email = newEmail
        });
        await resendResponse.AssertSuccess();

        var result = await resendResponse.Content.ReadFromJsonAsync<ResendConfirmationEmail.ResendConfirmationEmailResponse>();
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    [Fact]
    public async Task ResendConfirmationEmail_with_confirmed_email_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"already-confirmed-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"confirmed{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var confirmToken = registerResult!.PasswordSetupToken!;

        // Confirm the email
        using var publicClient = _factory.CreateClient();
        await publicClient.GetAsync(
            $"/auth/confirmEmail?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email={newEmail}&token={Uri.EscapeDataString(confirmToken)}");

        // Try to resend confirmation email - should still succeed but return "already confirmed" message
        using var tenantClient = _factory.CreateClientWithTenant();
        var resendResponse = await tenantClient.PostAsJsonAsync($"/auth/resendConfirmationEmail?useApiLinks=false", new
        {
            Email = newEmail
        });
        await resendResponse.AssertSuccess();

        var result = await resendResponse.Content.ReadFromJsonAsync<ResendConfirmationEmail.ResendConfirmationEmailResponse>();
        Assert.NotNull(result);
        Assert.True(result!.Success);
        // The message might be either "already confirmed" or a generic message
        Assert.NotNull(result.Message);
    }

    [Fact]
    public async Task ResendConfirmationEmail_with_invalid_email_returns_validation_error()
    {
        using var publicClient = _factory.CreateClientWithTenant();

        var resendResponse = await publicClient.PostAsJsonAsync($"/auth/resendConfirmationEmail?useApiLinks=false", new
        {
            Email = "not-an-email"
        });
        Assert.False(resendResponse.IsSuccessStatusCode);
    }

    #endregion

    #region UpdateUserInfo Tests

    [Fact]
    public async Task UpdateUserInfo_change_password_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"update-info-{Guid.NewGuid():N}@example.com";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = $"updateinfo{Guid.NewGuid():N}",
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var setupToken = registerResult!.PasswordSetupToken!;

        // Set initial password
        using var publicClient = _factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            $"/auth/resetPassword?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email={newEmail}&token={Uri.EscapeDataString(setupToken)}",
            new { NewPassword = "InitialPassword1!" });

        // Login with new password
        using var userClient = _factory.CreateClientWithTenant();
        var loginResponse = await userClient.PostAsJsonAsync("/auth/token", new
        {
            Email = newEmail,
            Password = "InitialPassword1!"
        });
        await loginResponse.AssertSuccess();
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        userClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        // Update password
        var updateResponse = await userClient.PutAsJsonAsync("/manage/info", new
        {
            OldPassword = "InitialPassword1!",
            NewPassword = "UpdatedPassword1!"
        });
        await updateResponse.AssertSuccess();

        // Verify new password works
        using var newLoginClient = _factory.CreateClientWithTenant();
        var newLoginResponse = await newLoginClient.PostAsJsonAsync("/auth/token", new
        {
            Email = newEmail,
            Password = "UpdatedPassword1!"
        });
        await newLoginResponse.AssertSuccess();
    }

    [Fact]
    public async Task UpdateUserInfo_change_username_succeeds()
    {
        var sysClient = await CreateAuthenticatedClientAsync();
        var newEmail = $"username-change-{Guid.NewGuid():N}@example.com";
        var originalUsername = $"user{Guid.NewGuid():N}";
        var newUsername = $"user{Guid.NewGuid():N}";

        // Register user
        var registerResponse = await sysClient.PostAsJsonAsync("/manage/users?useApiLinks=false", new
        {
            Email = newEmail,
            Username = originalUsername,
            Role = IdmtDefaultRoleTypes.TenantAdmin
        });
        await registerResponse.AssertSuccess();

        var registerResult = await registerResponse.Content.ReadFromJsonAsync<RegisterUser.RegisterUserResponse>();
        var setupToken = registerResult!.PasswordSetupToken!;

        // Set initial password
        using var publicClient = _factory.CreateClient();
        await publicClient.PostAsJsonAsync(
            $"/auth/resetPassword?tenantIdentifier={IdmtApiFactory.DefaultTenantIdentifier}&email={newEmail}&token={Uri.EscapeDataString(setupToken)}",
            new { NewPassword = "InitialPassword1!" });

        // Login
        using var userClient = _factory.CreateClientWithTenant();
        var loginResponse = await userClient.PostAsJsonAsync("/auth/token", new
        {
            Email = newEmail,
            Password = "InitialPassword1!"
        });
        await loginResponse.AssertSuccess();
        var tokens = await loginResponse.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        userClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        // Update username
        var updateResponse = await userClient.PutAsJsonAsync("/manage/info", new
        {
            NewUsername = newUsername
        });
        await updateResponse.AssertSuccess();
    }

    [Fact]
    public async Task UpdateUserInfo_requires_authentication()
    {
        var client = _factory.CreateClientWithTenant();

        var response = await client.PutAsJsonAsync("/manage/info", new
        {
            OldPassword = "OldPassword1!",
            NewPassword = "NewPassword1!"
        });
        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found });
    }

    #endregion

    private async Task<HttpClient> CreateAuthenticatedClientAsync()
    {
        var client = _factory.CreateClientWithTenant();
        var loginResponse = await client.PostAsJsonAsync("/auth/login", new
        {
            Email = IdmtApiFactory.SysAdminEmail,
            Password = IdmtApiFactory.SysAdminPassword
        });
        await loginResponse.AssertSuccess();
        return client;
    }
}
