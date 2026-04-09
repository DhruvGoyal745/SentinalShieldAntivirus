using System.Diagnostics;
using Antivirus.Application.Contracts;
using Antivirus.Application.Services;
using Antivirus.Configuration;
using Antivirus.Domain;
using Antivirus.Infrastructure.Persistence;
using Antivirus.Infrastructure.Security;
using Antivirus.Infrastructure.Security.StaticAnalysis;
using Antivirus.Infrastructure.Security.Rules;
using Antivirus.Middleware;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting.WindowsServices;

var isWindowsService = WindowsServiceHelpers.IsWindowsService();

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = isWindowsService
        ? Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory
        : default,
    EnvironmentName = isWindowsService ? "Service" : null
});

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

builder.Services.Configure<AntivirusPlatformOptions>(
    builder.Configuration.GetSection(AntivirusPlatformOptions.SectionName));

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

builder.Services.AddSingleton<ISqlConnectionFactory, SqlConnectionFactory>();
builder.Services.AddSingleton<ITenantContextAccessor, TenantContextAccessor>();
builder.Services.AddSingleton<ITenantRegistry, SqlTenantRegistry>();
builder.Services.AddSingleton<IDatabaseBootstrapper, DatabaseBootstrapper>();
builder.Services.AddSingleton<ISecurityRepository, SqlSecurityRepository>();
builder.Services.AddSingleton<IControlPlaneRepository, SqlControlPlaneRepository>();
builder.Services.AddSingleton<IPowerShellRunner, PowerShellRunner>();
builder.Services.AddSingleton<IProcessCommandRunner, ProcessCommandRunner>();
builder.Services.AddSingleton<IWindowsDefenderClient, WindowsDefenderClient>();
builder.Services.AddSingleton<IScanBackgroundQueue, ScanBackgroundQueue>();
builder.Services.AddSingleton<IScanCancellationRegistry, ScanCancellationRegistry>();
builder.Services.AddSingleton<IScanFileDecisionRegistry, ScanFileDecisionRegistry>();
builder.Services.AddSingleton<IFileEventBackgroundQueue, FileEventBackgroundQueue>();
builder.Services.AddSingleton<IHeuristicRule, SuspiciousExtensionRule>();
builder.Services.AddSingleton<IHeuristicRule, DoubleExtensionRule>();
builder.Services.AddSingleton<IHeuristicRule, StartupScriptRule>();
builder.Services.AddSingleton<IHeuristicAnalyzer, HeuristicAnalyzer>();
builder.Services.AddSingleton<IOpenSourceScannerEngine, PatternRuleScannerEngine>();
builder.Services.AddSingleton<IOpenSourceScannerEngine, SignatureHashScannerEngine>();
builder.Services.AddSingleton<IStaticArtifactEnricher, ContentHeuristicEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, DocumentMetadataEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, PortableExecutableMetadataEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, ElfMetadataEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, ArchiveMetadataEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, AuthenticodeVerificationEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, SuspiciousStringExtractionEnricher>();
builder.Services.AddSingleton<IStaticRuleEvaluator, StaticRuleEvaluator>();
builder.Services.AddSingleton<IStaticFileScanner, ProprietaryStaticFileScanner>();
builder.Services.AddSingleton<IBehaviorMonitor, BehaviorMonitor>();
builder.Services.AddSingleton<IReputationClient, ReputationClient>();
builder.Services.AddSingleton<IRemediationCoordinator, RemediationCoordinator>();
builder.Services.AddSingleton<ISandboxSubmissionClient, SandboxSubmissionClient>();
builder.Services.AddSingleton<ISignaturePackCompiler, SignaturePackCompiler>();
builder.Services.AddSingleton<ISignaturePackProvider, SignaturePackProvider>();
builder.Services.AddSingleton<ManagedEngineDaemonClient>();
builder.Services.AddSingleton<IEngineDaemonClient, NativePreferredEngineDaemonClient>();
builder.Services.AddSingleton<IProprietaryProtectionEngine, ProprietaryProtectionEngine>();
builder.Services.AddSingleton<SentinelShieldControlService>();
builder.Services.AddSingleton<ISentinelShieldControlApi>(sp => sp.GetRequiredService<SentinelShieldControlService>());
builder.Services.AddScoped<ISecurityOrchestrator, SecurityOrchestrator>();
builder.Services.AddScoped<IDashboardService, DashboardService>();
builder.Services.AddScoped<IAgentControlPlaneService, AgentControlPlaneService>();
builder.Services.AddScoped<IEnterpriseDashboardService, EnterpriseDashboardService>();
builder.Services.AddScoped<IComplianceService, ComplianceService>();
builder.Services.AddScoped<IScanReportService, ScanReportService>();
builder.Services.AddScoped<IRealtimeProtectionService, RealtimeProtectionService>();
builder.Services.AddHostedService<ScanProcessingHostedService>();
builder.Services.AddHostedService<FileWatcherHostedService>();
builder.Services.AddHostedService<FileEventProcessingHostedService>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var bootstrapper = scope.ServiceProvider.GetRequiredService<IDatabaseBootstrapper>();
    await bootstrapper.InitializeAsync();
}

app.UseMiddleware<RequestLoggingMiddleware>();
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseMiddleware<TenantResolutionMiddleware>();

app.UseHttpsRedirection();
app.UseCors("frontend");
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapControllers();
app.MapFallbackToFile("index.html");

if (!isWindowsService)
{
    var contextScanTarget = ParseContextMenuScanTarget(args);
    if (contextScanTarget is not null)
    {
        app.Lifetime.ApplicationStarted.Register(async () =>
        {
            try
            {
                using var scope = app.Services.CreateScope();
                var orchestrator = scope.ServiceProvider.GetRequiredService<ISecurityOrchestrator>();
                var scan = await orchestrator.QueueScanAsync(new ScanRequest
                {
                    Mode = ScanMode.Custom,
                    TargetPath = contextScanTarget,
                    RequestedBy = "explorer-context-menu"
                });

                var url = $"{app.Urls.FirstOrDefault() ?? "https://localhost:5001"}";
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch
            {
                // Silently ignore if scan or browser launch fails.
            }
        });
    }
    else
    {
        app.Lifetime.ApplicationStarted.Register(() =>
        {
            var url = app.Urls.FirstOrDefault() ?? "https://localhost:5001";
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch
            {
                // Silently ignore if no browser is available.
            }
        });
    }
}

app.Run();

static string? ParseContextMenuScanTarget(string[] args)
{
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i].Equals("--target", StringComparison.OrdinalIgnoreCase))
        {
            var target = args[i + 1];
            if (Path.IsPathRooted(target) && (File.Exists(target) || Directory.Exists(target)))
            {
                return target;
            }
        }
    }

    return null;
}
