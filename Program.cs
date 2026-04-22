using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Logging;
using Antivirus.Middleware;
using Antivirus.Startup;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.IdentityModel.Tokens;

var isWindowsService = WindowsServiceHelpers.IsWindowsService();

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = isWindowsService
        ? Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory
        : default,
    EnvironmentName = isWindowsService ? "Service" : null
});

builder.Services.Configure<AntivirusPlatformOptions>(
    builder.Configuration.GetSection(AntivirusPlatformOptions.SectionName));
builder.Logging.AddProvider(new RollingFileLoggerProvider(builder.Configuration));

if (isWindowsService)
{
    builder.Host.UseWindowsService(options =>
    {
        options.ServiceName = "SentinelShieldService";
    });

    builder.WebHost.UseUrls("http://127.0.0.1:5100");

    builder.Logging.AddEventLog(settings =>
    {
        settings.SourceName = "Sentinel Shield Antivirus";
        settings.LogName = "Application";
    });
}

builder.Services.AddCors(options =>
{
    options.AddPolicy("frontend", policy =>
    {
        policy
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials()
            .WithOrigins("http://localhost:5173", "https://localhost:5173");
    });
});

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
builder.Services.AddEndpointsApiExplorer();

var platformOptions = builder.Configuration
    .GetSection(AntivirusPlatformOptions.SectionName)
    .Get<AntivirusPlatformOptions>() ?? new AntivirusPlatformOptions();

var jwtKey = platformOptions.JwtSigningKey
    ?? "SentinelShield-Dev-JWT-Key-2026-CHANGE-IN-PRODUCTION!";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "SentinelShield",
            ValidateAudience = true,
            ValidAudience = "SentinelShield",
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromMinutes(5)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

builder.Services
    .AddPlatformFoundation()
    .AddPersistence()
    .AddSecurityPipeline()
    .AddApplicationServices()
    .AddBackgroundProcessing();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var bootstrapper = scope.ServiceProvider.GetRequiredService<IDatabaseBootstrapper>();
    await bootstrapper.InitializeAsync();

    var authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
    await authService.EnsureDefaultAdminAsync();
}

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<RequestLoggingMiddleware>();
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseMiddleware<TenantResolutionMiddleware>();
app.UseMiddleware<LocalTrustMiddleware>();

if (!isWindowsService)
{
    app.UseHttpsRedirection();
}
app.UseCors("frontend");
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapFallbackToFile("index.html");

app.Run();
