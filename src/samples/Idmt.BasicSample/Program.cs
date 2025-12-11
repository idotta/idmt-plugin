using Idmt.Plugin.Extensions;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddIdmt(builder.Configuration,
    options => options.UseInMemoryDatabase("IdmtDatabase"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseIdmt();

app.MapIdmtEndpoints();

await app.EnsureIdmtDatabaseAsync();

await app.SeedIdmtDataAsync();

app.Run();