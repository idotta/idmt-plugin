using Finbuckle.MultiTenant.AspNetCore.Extensions;
using Idmt.Plugin.Configuration;
using Idmt.Plugin.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Check if running in test mode
var isTest = builder.Configuration.GetValue<bool>("IsTest");

if (!isTest)
{
    builder.Services.AddIdmt(builder.Configuration,
        options => options.UseInMemoryDatabase("IdmtDatabase"));
}
else
{
    // In test mode, DbContext is configured by the test factory
    builder.Services.AddIdmt(builder.Configuration);
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().ExcludeFromMultiTenantResolution();
}

app.UseIdmt();

var options = app.Services.GetRequiredService<IOptions<IdmtOptions>>().Value;

if (options.MultiTenant.Strategies.Contains(IdmtMultiTenantStrategy.Route))
{
    app.MapGroup("/{__tenant__}")
        .MapIdmtEndpoints();
}
else
{
    app.MapIdmtEndpoints();
}

await app.EnsureIdmtDatabaseAsync();

var seedAction = app.Services.GetService<SeedDataAsync>();
await app.SeedIdmtDataAsync(seedAction);

app.Run();

public partial class Program;
