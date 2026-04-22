using Antivirus.Application.Contracts;
using Antivirus.Application.Services;
using Antivirus.Infrastructure.Persistence;
using Antivirus.Infrastructure.Platform;
using Antivirus.Infrastructure.Platform.Secrets;
using Antivirus.Infrastructure.Security;
using Antivirus.Infrastructure.Security.Reputation;
using Antivirus.Infrastructure.Security.Reputation.Ingestion;
using Antivirus.Infrastructure.Security.Rules;
using Antivirus.Infrastructure.Security.StaticAnalysis;

namespace Antivirus.Startup;

public static class PlatformServiceExtensions
{
    public static IServiceCollection AddPlatformFoundation(this IServiceCollection services)
    {
        services.AddSingleton<SentinelMetrics>();
        services.AddSingleton<IFeatureFlagService, FeatureFlagService>();
        services.AddSingleton<IManifestSignatureValidator, ManifestSignatureValidator>();
        services.AddSingleton<ILocalTrustBoundary, LocalTrustBoundary>();
        services.AddScoped<ICorrelationContext, CorrelationContext>();

        return services;
    }
}

public static class PersistenceServiceExtensions
{
    public static IServiceCollection AddPersistence(this IServiceCollection services)
    {
        services.AddSingleton<ISqlConnectionFactory, SqlConnectionFactory>();
        services.AddSingleton<ITenantContextAccessor, TenantContextAccessor>();
        services.AddSingleton<ITenantRegistry, SqlTenantRegistry>();
        services.AddSingleton<IDatabaseBootstrapper, DatabaseBootstrapper>();

        // Register concrete implementations
        services.AddSingleton<SqlSecurityRepository>();
        services.AddSingleton<SqlControlPlaneRepository>();

        // Register segregated interfaces (ISP) — each consumer depends only on what it needs
        services.AddSingleton<IScanRepository>(sp => sp.GetRequiredService<SqlSecurityRepository>());
        services.AddSingleton<IThreatRepository>(sp => sp.GetRequiredService<SqlSecurityRepository>());
        services.AddSingleton<IFileEventRepository>(sp => sp.GetRequiredService<SqlSecurityRepository>());
        services.AddSingleton<IHealthSnapshotRepository>(sp => sp.GetRequiredService<SqlSecurityRepository>());
        services.AddSingleton<IReportExportRepository>(sp => sp.GetRequiredService<SqlSecurityRepository>());
        services.AddSingleton<ISecurityStatsRepository>(sp => sp.GetRequiredService<SqlSecurityRepository>());
        services.AddSingleton<ISecurityRepository>(sp => sp.GetRequiredService<SqlSecurityRepository>());

        services.AddSingleton<IDeviceRepository>(sp => sp.GetRequiredService<SqlControlPlaneRepository>());
        services.AddSingleton<IPolicyRepository>(sp => sp.GetRequiredService<SqlControlPlaneRepository>());
        services.AddSingleton<IIncidentRepository>(sp => sp.GetRequiredService<SqlControlPlaneRepository>());
        services.AddSingleton<IComplianceRepository>(sp => sp.GetRequiredService<SqlControlPlaneRepository>());
        services.AddSingleton<IGovernanceRepository>(sp => sp.GetRequiredService<SqlControlPlaneRepository>());
        services.AddSingleton<IControlPlaneRepository>(sp => sp.GetRequiredService<SqlControlPlaneRepository>());

        services.AddSingleton<IUserRepository, SqlUserRepository>();
        services.AddSingleton<IQuarantineRepository, SqlQuarantineRepository>();

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
        services.AddSingleton<IHeuristicRule, MacroDocumentRule>();
        services.AddSingleton<IHeuristicRule, HtaFileRule>();
        services.AddSingleton<IHeuristicRule, DllSideloadingRule>();
        services.AddSingleton<IHeuristicRule, EncodedCommandRule>();
        services.AddSingleton<IHeuristicRule, SuspiciousImportsRule>();
        services.AddSingleton<IHeuristicRule, HighEntropySectionRule>();
        services.AddSingleton<IHeuristicAnalyzer, HeuristicAnalyzer>();

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
        services.AddSingleton<IProcessTreeTracker, ProcessTreeTracker>();
        services.AddSingleton<IVerdictScoringEngine, VerdictScoringEngine>();

        // Phase 3: Cloud reputation orchestration + threat intel.
        if (OperatingSystem.IsWindows())
        {
            services.AddSingleton<ISecretEncryptor, DpapiSecretEncryptor>();
        }
        else
        {
            services.AddSingleton<ISecretEncryptor, AesSecretEncryptor>();
        }
        services.AddSingleton<ISecretsVault, SqlSecretsVault>();
        services.AddSingleton<IThreatIntelSettingsRepository, SqlThreatIntelSettingsRepository>();
        services.AddSingleton<IReputationCache, SqlReputationCache>();
        services.AddSingleton<IProviderHealthRepository, SqlProviderHealthRepository>();
        services.AddSingleton<IReputationLookupAuditRepository, SqlReputationLookupAuditRepository>();
        services.AddSingleton<IIocRepository, SqlIocRepository>();
        services.AddSingleton<IIocMatcher, LocalIocMatcher>();
        services.AddSingleton<IReputationProvider, MockReputationProvider>();
        services.AddHttpClient<VirusTotalReputationProvider>();
        services.AddSingleton<IReputationProvider>(sp => sp.GetRequiredService<VirusTotalReputationProvider>());
        services.AddHttpClient<HybridAnalysisReputationProvider>();
        services.AddSingleton<IReputationProvider>(sp => sp.GetRequiredService<HybridAnalysisReputationProvider>());
        services.AddHttpClient<MispReputationProvider>();
        services.AddSingleton<IReputationProvider>(sp => sp.GetRequiredService<MispReputationProvider>());
        services.AddHttpClient<OtxReputationProvider>();
        services.AddSingleton<IReputationProvider>(sp => sp.GetRequiredService<OtxReputationProvider>());
        services.AddSingleton<IReputationOrchestrator, CloudReputationOrchestrator>();

        // Phase 3C: IOC feed ingestion.
        services.AddSingleton<IIocFeedSyncStore, SqlIocFeedSyncStore>();
        services.AddHttpClient<OtxIocFeedSource>();
        services.AddSingleton<IIocFeedSource>(sp => sp.GetRequiredService<OtxIocFeedSource>());
        services.AddSingleton<IIocIngestionService, IocIngestionService>();
        services.AddHostedService<IocFeedSyncHostedService>();

        services.AddSingleton<IRemediationCoordinator, RemediationCoordinator>();
        services.AddSingleton<ISandboxSubmissionClient, SandboxSubmissionClient>();
        services.AddSingleton<ISignaturePackCompiler, SignaturePackCompiler>();
        services.AddSingleton<ISignaturePackProvider, SignaturePackProvider>();
        services.AddSingleton<IEngineDaemonClient, ManagedEngineDaemonClient>();
        services.AddSingleton<IProprietaryProtectionEngine, ProprietaryProtectionEngine>();
        services.AddSingleton<IQuarantineVault, QuarantineVault>();
        services.AddSingleton<IRansomwareShield, RansomwareShield>();
        services.AddSingleton<IProcessRemediator, ProcessRemediator>();

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

        services.AddScoped<IAuthService, AuthService>();
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
