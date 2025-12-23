using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Finbuckle.MultiTenant.Abstractions;
using Idmt.Plugin.Features.Auth;
using Idmt.Plugin.Features.Sys;
using Idmt.Plugin.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Idmt.BasicSample.Tests;

public class IdmtIsolationTests : IClassFixture<IdmtApiFactory>
{
    private readonly IdmtApiFactory _factory;
    private const string TenantA = "tenant-a";
    private const string TenantB = "tenant-b";

    public IdmtIsolationTests(IdmtApiFactory factory)
    {
        _factory = factory;
    }

    private async Task EnsureTenantsExistAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<CreateTenant.ICreateTenantHandler>();

        var result = await handler.HandleAsync(new CreateTenant.CreateTenantRequest(TenantA, TenantA, "Tenant A"));
        result = await handler.HandleAsync(new CreateTenant.CreateTenantRequest(TenantB, TenantB, "Tenant B"));
    }

    private async Task CreateUserInTenantAsync(string tenantIdentifier, string email, string password, string role = IdmtDefaultRoleTypes.TenantAdmin)
    {
        Assert.NotEmpty(role);

        using var scope = _factory.Services.CreateScope();
        var provider = scope.ServiceProvider;

        // Set context so UserManager/DbContext works correctly with MultiTenant filters
        var store = provider.GetRequiredService<IMultiTenantStore<IdmtTenantInfo>>();
        var tenant = await store.GetByIdentifierAsync(tenantIdentifier);
        Assert.NotNull(tenant);

        var setter = provider.GetRequiredService<IMultiTenantContextSetter>();
        setter.MultiTenantContext = new MultiTenantContext<IdmtTenantInfo>(tenant);
        var userManager = provider.GetRequiredService<UserManager<IdmtUser>>();
        var user = new IdmtUser { UserName = email, Email = email, TenantId = tenant.Id, EmailConfirmed = true };
        await userManager.CreateAsync(user, password);
        await userManager.AddToRoleAsync(user, role);
    }

    [Fact]
    public async Task User_in_tenant_A_cannot_login_to_tenant_B()
    {
        await EnsureTenantsExistAsync();

        // 1. Create user in Tenant A
        var email = $"user-{Guid.NewGuid():N}@example.com";
        var password = "UserPassword1!";

        await CreateUserInTenantAsync(TenantA, email, password);

        // 2. Try login to Tenant A (Success)
        var clientA = _factory.CreateClientWithTenant(TenantA);
        var loginA = await clientA.PostAsJsonAsync("/auth/login", new { Email = email, Password = password });
        await loginA.AssertSuccess();

        // 3. Try login to Tenant B (Fail)
        var clientB = _factory.CreateClientWithTenant(TenantB);
        var loginB = await clientB.PostAsJsonAsync("/auth/login", new { Email = email, Password = password });

        Assert.Equal(HttpStatusCode.Unauthorized, loginB.StatusCode);
    }

    [Fact]
    public async Task Token_from_tenant_A_cannot_access_tenant_B()
    {
        await EnsureTenantsExistAsync();

        // 1. Create user in Tenant A
        var email = $"user-{Guid.NewGuid():N}@example.com";
        var password = "UserPassword1!";

        await CreateUserInTenantAsync(TenantA, email, password);

        // 2. Login to Tenant A to get token
        var clientA = _factory.CreateClientWithTenant(TenantA);
        var loginA = await clientA.PostAsJsonAsync("/auth/token", new { Email = email, Password = password });
        var tokens = await loginA.Content.ReadFromJsonAsync<Login.AccessTokenResponse>();
        Assert.NotNull(tokens);

        // 3. Access Tenant A protected resource (Success)
        clientA.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);
        var infoA = await clientA.GetAsync("/manage/info");
        await infoA.AssertSuccess();

        // 4. Access Tenant B protected resource with Tenant A token (Fail)
        var clientB = _factory.CreateClientWithTenant(TenantB);
        clientB.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var infoB = await clientB.GetAsync("/manage/info");

        Assert.Contains(infoB.StatusCode, new[] { HttpStatusCode.NotFound, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }
}
