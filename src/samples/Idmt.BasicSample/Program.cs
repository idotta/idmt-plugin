using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddIdmt(builder.Configuration, db => db.UseSqlite("Data Source=Idmt.BasicSample.db"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().ExcludeFromMultiTenantResolution();
}

// Enable static files and default files
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseIdmt();

var options = app.Services.GetRequiredService<IOptions<IdmtOptions>>().Value;

if (options.MultiTenant.Strategies.Contains(IdmtMultiTenantStrategy.Route))
{
    app.MapGroup("/{__tenant__}").MapIdmtEndpoints();
}
else
{
    app.MapGroup("").MapIdmtEndpoints();
}

await app.EnsureIdmtDatabaseAsync();

var seedAction = app.Services.GetService<SeedDataAsync>();
await app.SeedIdmtDataAsync(seedAction);

// Seed test user in development
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    await Idmt.BasicSample.SeedTestUser.SeedAsync(scope.ServiceProvider);
}

app.Run();

public partial class Program;
