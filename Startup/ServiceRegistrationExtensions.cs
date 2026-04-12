using Antivirus.Application.Contracts;
using Antivirus.Application.Services;
using Antivirus.Infrastructure.Persistence;
using Antivirus.Infrastructure.Security;
using Antivirus.Infrastructure.Security.Rules;
using Antivirus.Infrastructure.Security.StaticAnalysis;

namespace Antivirus.Startup;

public static class PersistenceServiceExtensions
{
    public static IServiceCollection AddPersistence(this IServiceCollection services)
    {
        services.AddSingleton<ISqlConnectionFactory, SqlConnectionFactory>();
        services.AddSingleton<ITenantContextAccessor, TenantContextAccessor>();
        services.AddSingleton<ITenantRegistry, SqlTenantRegistry>();
        services.AddSingleton<IDatabaseBootstrapper, DatabaseBootstrapper>();
        services.AddSingleton<ISecurityRepository, SqlSecurityRepository>();
        services.AddSingleton<IControlPlaneRepository, SqlControlPlaneRepository>();

        return services;
    }
}

public static class SecurityPipelineServiceExtensions
{
    public static IServiceCollection AddSecurityPipeline(this IServiceCollection services)
    {
        services.AddSingleton<IHeuristicRule, SuspiciousExtensionRule>();
        services.AddSingleton<IHeuristicRule, DoubleExtensionRule>();
        services.AddSingleton<IHeuristicRule, StartupScriptRule>();
        services.AddSingleton<IHeuristicAnalyzer, HeuristicAnalyzer>();
        services.AddSingleton<IOpenSourceScannerEngine, PatternRuleScannerEngine>();
        services.AddSingleton<IOpenSourceScannerEngine, SignatureHashScannerEngine>();

        services.AddSingleton<IStaticArtifactEnricher, ContentHeuristicEnricher>();
        services.AddSingleton<IStaticArtifactEnricher, DocumentMetadataEnricher>();
        services.AddSingleton<IStaticArtifactEnricher, PortableExecutableMetadataEnricher>();
        services.AddSingleton<IStaticArtifactEnricher, ElfMetadataEnricher>();
        services.AddSingleton<IStaticArtifactEnricher, ArchiveMetadataEnricher>();
        services.AddSingleton<IStaticArtifactEnricher, AuthenticodeVerificationEnricher>();
        services.AddSingleton<IStaticArtifactEnricher, SuspiciousStringExtractionEnricher>();
        services.AddSingleton<IStaticRuleEvaluator, StaticRuleEvaluator>();
        services.AddSingleton<IStaticFileScanner, ProprietaryStaticFileScanner>();
        services.AddSingleton<IBehaviorMonitor, BehaviorMonitor>();
        services.AddSingleton<IReputationClient, ReputationClient>();
        services.AddSingleton<IRemediationCoordinator, RemediationCoordinator>();
        services.AddSingleton<ISandboxSubmissionClient, SandboxSubmissionClient>();
        services.AddSingleton<ISignaturePackCompiler, SignaturePackCompiler>();
        services.AddSingleton<ISignaturePackProvider, SignaturePackProvider>();
        services.AddSingleton<ManagedEngineDaemonClient>();
        services.AddSingleton<IEngineDaemonClient, NativePreferredEngineDaemonClient>();
        services.AddSingleton<IProprietaryProtectionEngine, ProprietaryProtectionEngine>();

        return services;
    }
}

public static class ApplicationServiceExtensions
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        services.AddSingleton<IPowerShellRunner, PowerShellRunner>();
        services.AddSingleton<IProcessCommandRunner, ProcessCommandRunner>();
        services.AddSingleton<IWindowsDefenderClient, WindowsDefenderClient>();
        services.AddSingleton<SentinelShieldControlService>();
        services.AddSingleton<ISentinelShieldControlApi>(sp => sp.GetRequiredService<SentinelShieldControlService>());

        services.AddScoped<ISecurityOrchestrator, SecurityOrchestrator>();
        services.AddScoped<IDashboardService, DashboardService>();
        services.AddScoped<IAgentControlPlaneService, AgentControlPlaneService>();
        services.AddScoped<IEnterpriseDashboardService, EnterpriseDashboardService>();
        services.AddScoped<IComplianceService, ComplianceService>();
        services.AddScoped<IScanReportService, ScanReportService>();
        services.AddScoped<IRealtimeProtectionService, RealtimeProtectionService>();

        return services;
    }
}

public static class BackgroundServiceExtensions
{
    public static IServiceCollection AddBackgroundProcessing(this IServiceCollection services)
    {
        services.AddSingleton<IScanBackgroundQueue, ScanBackgroundQueue>();
        services.AddSingleton<IScanCancellationRegistry, ScanCancellationRegistry>();
        services.AddSingleton<IScanFileDecisionRegistry, ScanFileDecisionRegistry>();
        services.AddSingleton<IFileEventBackgroundQueue, FileEventBackgroundQueue>();

        services.AddHostedService<ScanProcessingHostedService>();
        services.AddHostedService<FileWatcherHostedService>();
        services.AddHostedService<FileEventProcessingHostedService>();

        return services;
    }
}
