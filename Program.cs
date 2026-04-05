using Antivirus.Application.Contracts;
using Antivirus.Application.Services;
using Antivirus.Configuration;
using Antivirus.Infrastructure.Persistence;
using Antivirus.Infrastructure.Security;
using Antivirus.Infrastructure.Security.StaticAnalysis;
using Antivirus.Infrastructure.Security.Rules;
using Antivirus.Middleware;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

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
builder.Services.AddSingleton<IFileEventBackgroundQueue, FileEventBackgroundQueue>();
builder.Services.AddSingleton<IHeuristicRule, SuspiciousExtensionRule>();
builder.Services.AddSingleton<IHeuristicRule, DoubleExtensionRule>();
builder.Services.AddSingleton<IHeuristicRule, StartupScriptRule>();
builder.Services.AddSingleton<IHeuristicAnalyzer, HeuristicAnalyzer>();
builder.Services.AddSingleton<IOpenSourceScannerEngine, YaraScannerEngine>();
builder.Services.AddSingleton<IOpenSourceScannerEngine, ClamAvScannerEngine>();
builder.Services.AddSingleton<IStaticArtifactEnricher, ContentHeuristicEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, DocumentMetadataEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, PortableExecutableMetadataEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, ElfMetadataEnricher>();
builder.Services.AddSingleton<IStaticArtifactEnricher, ArchiveMetadataEnricher>();
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

app.Run();
