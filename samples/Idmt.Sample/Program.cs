using Idmt.Plugin.Extensions;
using Idmt.Sample.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// Add IDMT services
builder.Services.AddIdmt(builder.Configuration);

// Add authorization services
builder.Services.AddAuthorization();

// Add API Explorer for Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Use IDMT middleware (includes multi-tenant, authentication, authorization)
app.UseIdmt();

// Ensure database is created and seeded
app.EnsureIdmtDatabase();
app.SeedIdmtData();

app.UseRouting();

// Map minimal API endpoints
app.MapAuthEndpoints();
app.MapUserEndpoints();
app.MapHealthEndpoints();

app.MapGet("/", () => "IDMT Sample API - Identity MultiTenant Plugin Demo");

app.Run();
