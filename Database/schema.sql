IF OBJECT_ID('dbo.ScanJobs', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ScanJobs
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        Mode NVARCHAR(32) NOT NULL,
        TargetPath NVARCHAR(1024) NULL,
        RequestedBy NVARCHAR(200) NOT NULL,
        Status NVARCHAR(32) NOT NULL,
        Stage NVARCHAR(32) NOT NULL CONSTRAINT DF_ScanJobs_Stage DEFAULT N'Queued',
        PercentComplete INT NOT NULL CONSTRAINT DF_ScanJobs_PercentComplete DEFAULT 0,
        FilesScanned INT NOT NULL CONSTRAINT DF_ScanJobs_FilesScanned DEFAULT 0,
        TotalFiles INT NULL,
        CurrentTarget NVARCHAR(2048) NULL,
        ThreatCount INT NOT NULL CONSTRAINT DF_ScanJobs_ThreatCount DEFAULT 0,
        Notes NVARCHAR(MAX) NULL,
        CreatedAt DATETIMEOFFSET NOT NULL,
        StartedAt DATETIMEOFFSET NULL,
        CompletedAt DATETIMEOFFSET NULL
    );
END;

IF COL_LENGTH('dbo.ScanJobs', 'Stage') IS NULL
BEGIN
    ALTER TABLE dbo.ScanJobs ADD Stage NVARCHAR(32) NOT NULL CONSTRAINT DF_ScanJobs_Stage_Migrate DEFAULT N'Queued';
END;

IF COL_LENGTH('dbo.ScanJobs', 'PercentComplete') IS NULL
BEGIN
    ALTER TABLE dbo.ScanJobs ADD PercentComplete INT NOT NULL CONSTRAINT DF_ScanJobs_PercentComplete_Migrate DEFAULT 0;
END;

IF COL_LENGTH('dbo.ScanJobs', 'FilesScanned') IS NULL
BEGIN
    ALTER TABLE dbo.ScanJobs ADD FilesScanned INT NOT NULL CONSTRAINT DF_ScanJobs_FilesScanned_Migrate DEFAULT 0;
END;

IF COL_LENGTH('dbo.ScanJobs', 'TotalFiles') IS NULL
BEGIN
    ALTER TABLE dbo.ScanJobs ADD TotalFiles INT NULL;
END;

IF COL_LENGTH('dbo.ScanJobs', 'CurrentTarget') IS NULL
BEGIN
    ALTER TABLE dbo.ScanJobs ADD CurrentTarget NVARCHAR(2048) NULL;
END;

IF OBJECT_ID('dbo.ScanProgressEvents', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ScanProgressEvents
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        ScanJobId INT NOT NULL,
        Stage NVARCHAR(32) NOT NULL,
        PercentComplete INT NOT NULL,
        CurrentPath NVARCHAR(2048) NULL,
        FilesScanned INT NOT NULL,
        TotalFiles INT NULL,
        FindingsCount INT NOT NULL,
        IsSkipped BIT NOT NULL CONSTRAINT DF_ScanProgressEvents_IsSkipped DEFAULT 0,
        DetailMessage NVARCHAR(1024) NULL,
        StartedAt DATETIMEOFFSET NOT NULL,
        CompletedAt DATETIMEOFFSET NULL,
        RecordedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_ScanProgressEvents_RecordedAt DEFAULT SYSUTCDATETIME(),
        CONSTRAINT FK_ScanProgressEvents_ScanJobs FOREIGN KEY (ScanJobId) REFERENCES dbo.ScanJobs(Id)
    );
END;

IF COL_LENGTH('dbo.ScanProgressEvents', 'IsSkipped') IS NULL
BEGIN
    ALTER TABLE dbo.ScanProgressEvents ADD IsSkipped BIT NOT NULL CONSTRAINT DF_ScanProgressEvents_IsSkipped_Migrate DEFAULT 0;
END;

IF COL_LENGTH('dbo.ScanProgressEvents', 'DetailMessage') IS NULL
BEGIN
    ALTER TABLE dbo.ScanProgressEvents ADD DetailMessage NVARCHAR(1024) NULL;
END;

IF OBJECT_ID('dbo.ThreatDetections', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ThreatDetections
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        ScanJobId INT NULL,
        Name NVARCHAR(300) NOT NULL,
        Category NVARCHAR(128) NOT NULL,
        Severity NVARCHAR(32) NOT NULL,
        Source NVARCHAR(32) NOT NULL,
        Resource NVARCHAR(2048) NULL,
        Description NVARCHAR(MAX) NULL,
        EngineName NVARCHAR(128) NULL,
        IsQuarantined BIT NOT NULL CONSTRAINT DF_ThreatDetections_IsQuarantined DEFAULT 0,
        QuarantinePath NVARCHAR(2048) NULL,
        EvidenceJson NVARCHAR(MAX) NULL,
        DetectedAt DATETIMEOFFSET NOT NULL,
        CONSTRAINT FK_ThreatDetections_ScanJobs FOREIGN KEY (ScanJobId) REFERENCES dbo.ScanJobs(Id)
    );
END;

IF OBJECT_ID('dbo.DeviceHealthSnapshots', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.DeviceHealthSnapshots
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        CapturedAt DATETIMEOFFSET NOT NULL,
        AntivirusEnabled BIT NOT NULL,
        RealTimeProtectionEnabled BIT NOT NULL,
        IoavProtectionEnabled BIT NOT NULL,
        NetworkInspectionEnabled BIT NOT NULL,
        EngineServiceEnabled BIT NOT NULL,
        SignaturesOutOfDate BIT NOT NULL,
        AntivirusSignatureVersion NVARCHAR(100) NULL,
        AntivirusSignatureLastUpdated DATETIMEOFFSET NULL,
        QuickScanAgeDays INT NULL,
        FullScanAgeDays INT NULL
    );
END;

IF OBJECT_ID('dbo.SignatureRules', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.SignatureRules
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        RuleName NVARCHAR(200) NOT NULL,
        Pattern NVARCHAR(4000) NOT NULL,
        Severity NVARCHAR(32) NOT NULL,
        IsEnabled BIT NOT NULL CONSTRAINT DF_SignatureRules_IsEnabled DEFAULT 1,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_SignatureRules_CreatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF OBJECT_ID('dbo.FileSecurityEvents', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.FileSecurityEvents
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        FilePath NVARCHAR(2048) NOT NULL,
        PreviousPath NVARCHAR(2048) NULL,
        EventType NVARCHAR(32) NOT NULL,
        Status NVARCHAR(32) NOT NULL,
        HashSha256 NVARCHAR(64) NULL,
        FileSizeBytes BIGINT NULL,
        ThreatCount INT NOT NULL CONSTRAINT DF_FileSecurityEvents_ThreatCount DEFAULT 0,
        Notes NVARCHAR(MAX) NULL,
        ObservedAt DATETIMEOFFSET NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_FileSecurityEvents_CreatedAt DEFAULT SYSUTCDATETIME(),
        ProcessedAt DATETIMEOFFSET NULL
    );
END;

IF OBJECT_ID('dbo.FileEngineResults', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.FileEngineResults
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        FileSecurityEventId INT NOT NULL,
        EngineName NVARCHAR(128) NOT NULL,
        Source NVARCHAR(32) NOT NULL,
        Status NVARCHAR(32) NOT NULL,
        IsMatch BIT NOT NULL,
        SignatureName NVARCHAR(256) NULL,
        Details NVARCHAR(MAX) NULL,
        RawOutput NVARCHAR(MAX) NULL,
        ScannedAt DATETIMEOFFSET NOT NULL,
        CONSTRAINT FK_FileEngineResults_FileSecurityEvents FOREIGN KEY (FileSecurityEventId) REFERENCES dbo.FileSecurityEvents(Id)
    );
END;

IF OBJECT_ID('dbo.Devices', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.Devices
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        DeviceId NVARCHAR(200) NOT NULL,
        DeviceName NVARCHAR(200) NOT NULL,
        OperatingSystem NVARCHAR(32) NOT NULL,
        AgentVersion NVARCHAR(64) NOT NULL,
        EngineVersion NVARCHAR(64) NOT NULL,
        SignaturePackVersion NVARCHAR(64) NOT NULL,
        PolicyVersion NVARCHAR(64) NOT NULL,
        RolloutRing NVARCHAR(32) NOT NULL,
        EnrollmentStatus NVARCHAR(32) NOT NULL,
        BaselineScanCompleted BIT NOT NULL CONSTRAINT DF_Devices_BaselineScanCompleted DEFAULT 0,
        LegacyShadowModeEnabled BIT NOT NULL CONSTRAINT DF_Devices_LegacyShadowModeEnabled DEFAULT 1,
        SelfProtectionJson NVARCHAR(MAX) NOT NULL CONSTRAINT DF_Devices_SelfProtectionJson DEFAULT N'{}',
        CapabilitiesJson NVARCHAR(MAX) NOT NULL CONSTRAINT DF_Devices_CapabilitiesJson DEFAULT N'[]',
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_Devices_CreatedAt DEFAULT SYSUTCDATETIME(),
        LastSeenAt DATETIMEOFFSET NULL
    );
END;

IF OBJECT_ID('dbo.AgentHeartbeats', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.AgentHeartbeats
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        DeviceId NVARCHAR(200) NOT NULL,
        AgentVersion NVARCHAR(64) NOT NULL,
        EngineVersion NVARCHAR(64) NOT NULL,
        SignaturePackVersion NVARCHAR(64) NOT NULL,
        PolicyVersion NVARCHAR(64) NOT NULL,
        BaselineScanCompleted BIT NOT NULL,
        LegacyShadowModeEnabled BIT NOT NULL,
        SelfProtectionJson NVARCHAR(MAX) NOT NULL,
        ReceivedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_AgentHeartbeats_ReceivedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF OBJECT_ID('dbo.PolicyBundles', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.PolicyBundles
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        PolicyName NVARCHAR(200) NOT NULL,
        Version NVARCHAR(64) NOT NULL,
        RolloutRing NVARCHAR(32) NOT NULL,
        QuarantineOnMalicious BIT NOT NULL CONSTRAINT DF_PolicyBundles_QuarantineOnMalicious DEFAULT 1,
        BlockHighConfidenceDetections BIT NOT NULL CONSTRAINT DF_PolicyBundles_BlockHighConfidence DEFAULT 1,
        AllowSampleUpload BIT NOT NULL CONSTRAINT DF_PolicyBundles_AllowSampleUpload DEFAULT 0,
        EnableLegacyShadowMode BIT NOT NULL CONSTRAINT DF_PolicyBundles_EnableLegacyShadowMode DEFAULT 1,
        PolicyJson NVARCHAR(MAX) NOT NULL,
        IsActive BIT NOT NULL CONSTRAINT DF_PolicyBundles_IsActive DEFAULT 1,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_PolicyBundles_CreatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF OBJECT_ID('dbo.SecurityIncidents', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.SecurityIncidents
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        DeviceId NVARCHAR(200) NOT NULL,
        Title NVARCHAR(300) NOT NULL,
        Severity NVARCHAR(32) NOT NULL,
        Status NVARCHAR(32) NOT NULL,
        Source NVARCHAR(64) NOT NULL,
        PrimaryArtifact NVARCHAR(2048) NOT NULL,
        RuleId NVARCHAR(200) NOT NULL,
        Confidence DECIMAL(5,2) NOT NULL,
        Summary NVARCHAR(MAX) NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_SecurityIncidents_CreatedAt DEFAULT SYSUTCDATETIME(),
        UpdatedAt DATETIMEOFFSET NULL
    );
END;

IF OBJECT_ID('dbo.RemediationActions', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.RemediationActions
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        DeviceId NVARCHAR(200) NOT NULL,
        ThreatDetectionId INT NULL,
        IncidentId INT NULL,
        ActionKind NVARCHAR(32) NOT NULL,
        Status NVARCHAR(32) NOT NULL,
        RequestedBy NVARCHAR(200) NOT NULL,
        Notes NVARCHAR(MAX) NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_RemediationActions_CreatedAt DEFAULT SYSUTCDATETIME(),
        CompletedAt DATETIMEOFFSET NULL
    );
END;

IF OBJECT_ID('dbo.FalsePositiveReviews', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.FalsePositiveReviews
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        ThreatDetectionId INT NULL,
        ArtifactHash NVARCHAR(128) NOT NULL,
        RuleId NVARCHAR(200) NOT NULL,
        Scope NVARCHAR(32) NOT NULL,
        Status NVARCHAR(32) NOT NULL,
        Analyst NVARCHAR(200) NOT NULL,
        Notes NVARCHAR(MAX) NOT NULL,
        SubmittedAt DATETIMEOFFSET NOT NULL,
        DecisionedAt DATETIMEOFFSET NULL
    );
END;

IF OBJECT_ID('dbo.SandboxSubmissions', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.SandboxSubmissions
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        DeviceId NVARCHAR(200) NOT NULL,
        ArtifactHash NVARCHAR(128) NOT NULL,
        FileName NVARCHAR(260) NOT NULL,
        Status NVARCHAR(32) NOT NULL,
        CorrelationId NVARCHAR(200) NOT NULL,
        Verdict NVARCHAR(32) NOT NULL,
        BehaviorSummary NVARCHAR(MAX) NOT NULL,
        IndicatorsJson NVARCHAR(MAX) NOT NULL,
        FamilyName NVARCHAR(200) NOT NULL,
        TagsJson NVARCHAR(MAX) NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL,
        UpdatedAt DATETIMEOFFSET NULL
    );
END;

IF OBJECT_ID('dbo.ComplianceReports', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ComplianceReports
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        ReportType NVARCHAR(32) NOT NULL,
        ReportDate DATETIMEOFFSET NOT NULL,
        AgentCoveragePercent DECIMAL(5,2) NOT NULL,
        SignatureCurrencyPercent DECIMAL(5,2) NOT NULL,
        PolicyCompliancePercent DECIMAL(5,2) NOT NULL,
        BaselineScanCompletionPercent DECIMAL(5,2) NOT NULL,
        OpenCriticalIncidentCount INT NOT NULL,
        QuarantinedThreatCount INT NOT NULL,
        SelfProtectionCoveragePercent DECIMAL(5,2) NOT NULL,
        AuditFindingCount INT NOT NULL,
        ExportJson NVARCHAR(MAX) NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_ComplianceReports_CreatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF OBJECT_ID('dbo.AuditTrail', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.AuditTrail
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        Category NVARCHAR(64) NOT NULL,
        Subject NVARCHAR(200) NOT NULL,
        PerformedBy NVARCHAR(200) NOT NULL,
        Details NVARCHAR(MAX) NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_AuditTrail_CreatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF OBJECT_ID('dbo.Exclusions', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.Exclusions
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        Scope NVARCHAR(32) NOT NULL,
        MatchValue NVARCHAR(512) NOT NULL,
        Reason NVARCHAR(MAX) NOT NULL,
        CreatedBy NVARCHAR(200) NOT NULL,
        ApprovedBy NVARCHAR(200) NULL,
        ExpiresAt DATETIMEOFFSET NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_Exclusions_CreatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF OBJECT_ID('dbo.ScanReportExports', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ScanReportExports
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        ScanJobId INT NULL,
        FileName NVARCHAR(260) NOT NULL,
        Format NVARCHAR(16) NOT NULL,
        ExportedBy NVARCHAR(200) NOT NULL,
        VulnerabilityCount INT NOT NULL CONSTRAINT DF_ScanReportExports_VulnerabilityCount DEFAULT 0,
        ExportedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_ScanReportExports_ExportedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ThreatDetections_DetectedAt' AND object_id = OBJECT_ID('dbo.ThreatDetections'))
BEGIN
    CREATE INDEX IX_ThreatDetections_DetectedAt ON dbo.ThreatDetections(DetectedAt DESC);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScanJobs_CreatedAt' AND object_id = OBJECT_ID('dbo.ScanJobs'))
BEGIN
    CREATE INDEX IX_ScanJobs_CreatedAt ON dbo.ScanJobs(CreatedAt DESC);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FileSecurityEvents_ObservedAt' AND object_id = OBJECT_ID('dbo.FileSecurityEvents'))
BEGIN
    CREATE INDEX IX_FileSecurityEvents_ObservedAt ON dbo.FileSecurityEvents(ObservedAt DESC, Id DESC);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_FileEngineResults_FileSecurityEventId' AND object_id = OBJECT_ID('dbo.FileEngineResults'))
BEGIN
    CREATE INDEX IX_FileEngineResults_FileSecurityEventId ON dbo.FileEngineResults(FileSecurityEventId);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Devices_DeviceId' AND object_id = OBJECT_ID('dbo.Devices'))
BEGIN
    CREATE UNIQUE INDEX IX_Devices_DeviceId ON dbo.Devices(DeviceId);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SecurityIncidents_CreatedAt' AND object_id = OBJECT_ID('dbo.SecurityIncidents'))
BEGIN
    CREATE INDEX IX_SecurityIncidents_CreatedAt ON dbo.SecurityIncidents(CreatedAt DESC);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SandboxSubmissions_CreatedAt' AND object_id = OBJECT_ID('dbo.SandboxSubmissions'))
BEGIN
    CREATE INDEX IX_SandboxSubmissions_CreatedAt ON dbo.SandboxSubmissions(CreatedAt DESC);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScanReportExports_ExportedAt' AND object_id = OBJECT_ID('dbo.ScanReportExports'))
BEGIN
    CREATE INDEX IX_ScanReportExports_ExportedAt ON dbo.ScanReportExports(ExportedAt DESC);
END;

-- ── Phase 2: Quarantine Vault ───────────────────────────────────

IF OBJECT_ID('dbo.QuarantineItems', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.QuarantineItems
    (
        Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        OriginalPath NVARCHAR(512) NOT NULL,
        OriginalFileName NVARCHAR(260) NOT NULL,
        VaultPath NVARCHAR(512) NOT NULL,
        HashSha256 NVARCHAR(128) NOT NULL,
        FileSizeBytes BIGINT NOT NULL,
        EncryptionKeyId NVARCHAR(64) NOT NULL,
        EncryptionIV VARBINARY(16) NOT NULL,
        ThreatName NVARCHAR(200) NULL,
        ThreatSeverity NVARCHAR(32) NOT NULL CONSTRAINT DF_QuarantineItems_ThreatSeverity DEFAULT 'Medium',
        ThreatSource NVARCHAR(64) NULL,
        DetectionContextJson NVARCHAR(MAX) NULL,
        PurgeState NVARCHAR(32) NOT NULL CONSTRAINT DF_QuarantineItems_PurgeState DEFAULT 'Active',
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_QuarantineItems_CreatedAt DEFAULT SYSUTCDATETIME(),
        RetentionExpiresAt DATETIMEOFFSET NOT NULL,
        RestoredAt DATETIMEOFFSET NULL,
        PurgedAt DATETIMEOFFSET NULL,
        RestoredBy NVARCHAR(200) NULL
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_QuarantineItems_PurgeState' AND object_id = OBJECT_ID('dbo.QuarantineItems'))
BEGIN
    CREATE INDEX IX_QuarantineItems_PurgeState ON dbo.QuarantineItems(PurgeState, CreatedAt DESC);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_QuarantineItems_RetentionExpiresAt' AND object_id = OBJECT_ID('dbo.QuarantineItems'))
BEGIN
    CREATE INDEX IX_QuarantineItems_RetentionExpiresAt ON dbo.QuarantineItems(RetentionExpiresAt) WHERE PurgeState = 'Active';
END;

-- ── Phase 2: Ransomware Shield ──────────────────────────────────

IF OBJECT_ID('dbo.RansomwareSignals', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.RansomwareSignals
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        ProcessId INT NOT NULL,
        ProcessPath NVARCHAR(512) NOT NULL,
        AffectedFileCount INT NOT NULL,
        MaxEntropyScore FLOAT NOT NULL,
        ExtensionChangeCount INT NOT NULL,
        RecommendedAction NVARCHAR(32) NOT NULL,
        Summary NVARCHAR(MAX) NOT NULL,
        DetectedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_RansomwareSignals_DetectedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_RansomwareSignals_DetectedAt' AND object_id = OBJECT_ID('dbo.RansomwareSignals'))
BEGIN
    CREATE INDEX IX_RansomwareSignals_DetectedAt ON dbo.RansomwareSignals(DetectedAt DESC);
END;

IF COL_LENGTH('dbo.SecurityIncidents', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.SecurityIncidents ADD ScanJobId INT NULL;
END;

IF COL_LENGTH('dbo.FileSecurityEvents', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.FileSecurityEvents ADD ScanJobId INT NULL;
END;

IF COL_LENGTH('dbo.SandboxSubmissions', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.SandboxSubmissions ADD ScanJobId INT NULL;
END;

IF COL_LENGTH('dbo.FalsePositiveReviews', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.FalsePositiveReviews ADD ScanJobId INT NULL;
END;


-- ── Phase 3: Cloud Reputation & Threat Intelligence ───────────

IF OBJECT_ID('dbo.ThreatIntelSettings', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ThreatIntelSettings
    (
        TenantKey NVARCHAR(100) NOT NULL PRIMARY KEY,
        SettingsJson NVARCHAR(MAX) NOT NULL,
        UpdatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_ThreatIntelSettings_UpdatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF OBJECT_ID('dbo.ReputationCache', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ReputationCache
    (
        Id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        TenantKey NVARCHAR(100) NOT NULL,
        Provider NVARCHAR(64) NOT NULL,
        LookupType NVARCHAR(32) NOT NULL,
        NormalizedValue NVARCHAR(512) NOT NULL,
        VerdictJson NVARCHAR(MAX) NOT NULL,
        Verdict NVARCHAR(32) NOT NULL,
        Confidence DECIMAL(5,4) NOT NULL,
        ExpiresAt DATETIMEOFFSET NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_ReputationCache_CreatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ReputationCache_Key' AND object_id = OBJECT_ID('dbo.ReputationCache'))
BEGIN
    CREATE UNIQUE INDEX UX_ReputationCache_Key ON dbo.ReputationCache(TenantKey, Provider, LookupType, NormalizedValue);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ReputationCache_ExpiresAt' AND object_id = OBJECT_ID('dbo.ReputationCache'))
BEGIN
    CREATE INDEX IX_ReputationCache_ExpiresAt ON dbo.ReputationCache(ExpiresAt);
END;

IF OBJECT_ID('dbo.ReputationLookupAudit', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ReputationLookupAudit
    (
        Id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        TenantKey NVARCHAR(100) NOT NULL,
        CallerUser NVARCHAR(200) NULL,
        LookupType NVARCHAR(32) NOT NULL,
        RedactedValue NVARCHAR(256) NOT NULL,
        ProvidersAttempted NVARCHAR(512) NOT NULL,
        CacheHit BIT NOT NULL,
        LocalIocHit BIT NOT NULL,
        LatencyMs INT NOT NULL,
        FinalVerdict NVARCHAR(32) NOT NULL,
        FailureReason NVARCHAR(512) NULL,
        CorrelationId NVARCHAR(100) NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_ReputationLookupAudit_CreatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ReputationLookupAudit_CreatedAt' AND object_id = OBJECT_ID('dbo.ReputationLookupAudit'))
BEGIN
    CREATE INDEX IX_ReputationLookupAudit_CreatedAt ON dbo.ReputationLookupAudit(TenantKey, CreatedAt DESC);
END;

IF OBJECT_ID('dbo.EncryptedSecrets', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.EncryptedSecrets
    (
        Id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        TenantKey NVARCHAR(100) NOT NULL,
        Provider NVARCHAR(64) NOT NULL,
        SecretKey NVARCHAR(64) NOT NULL,
        CipherText VARBINARY(MAX) NOT NULL,
        Algorithm NVARCHAR(32) NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_EncryptedSecrets_CreatedAt DEFAULT SYSUTCDATETIME(),
        UpdatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_EncryptedSecrets_UpdatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_EncryptedSecrets_Key' AND object_id = OBJECT_ID('dbo.EncryptedSecrets'))
BEGIN
    CREATE UNIQUE INDEX UX_EncryptedSecrets_Key ON dbo.EncryptedSecrets(TenantKey, Provider, SecretKey);
END;

IF OBJECT_ID('dbo.IocIndicators', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.IocIndicators
    (
        Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        TenantKey NVARCHAR(100) NOT NULL,
        IocType NVARCHAR(32) NOT NULL,
        NormalizedValue NVARCHAR(512) NOT NULL,
        DisplayValue NVARCHAR(512) NOT NULL,
        Source NVARCHAR(64) NOT NULL,
        Severity NVARCHAR(32) NOT NULL CONSTRAINT DF_IocIndicators_Severity DEFAULT 'Medium',
        Confidence DECIMAL(5,4) NOT NULL CONSTRAINT DF_IocIndicators_Confidence DEFAULT 0.5,
        TagsJson NVARCHAR(1024) NULL,
        Description NVARCHAR(MAX) NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_IocIndicators_CreatedAt DEFAULT SYSUTCDATETIME(),
        ExpiresAt DATETIMEOFFSET NULL,
        IsActive BIT NOT NULL CONSTRAINT DF_IocIndicators_IsActive DEFAULT 1
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_IocIndicators_Dedupe' AND object_id = OBJECT_ID('dbo.IocIndicators'))
BEGIN
    CREATE UNIQUE INDEX UX_IocIndicators_Dedupe ON dbo.IocIndicators(TenantKey, IocType, NormalizedValue, Source);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IocIndicators_Lookup' AND object_id = OBJECT_ID('dbo.IocIndicators'))
BEGIN
    CREATE INDEX IX_IocIndicators_Lookup ON dbo.IocIndicators(TenantKey, IocType, NormalizedValue) WHERE IsActive = 1;
END;

IF OBJECT_ID('dbo.IocSources', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.IocSources
    (
        Id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        TenantKey NVARCHAR(100) NOT NULL,
        Provider NVARCHAR(64) NOT NULL,
        LastSyncAt DATETIMEOFFSET NULL,
        LastCursor NVARCHAR(512) NULL,
        Enabled BIT NOT NULL CONSTRAINT DF_IocSources_Enabled DEFAULT 1
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_IocSources_TenantProvider' AND object_id = OBJECT_ID('dbo.IocSources'))
BEGIN
    CREATE UNIQUE INDEX UX_IocSources_TenantProvider ON dbo.IocSources(TenantKey, Provider);
END;

IF OBJECT_ID('dbo.IocFeedSyncRuns', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.IocFeedSyncRuns
    (
        Id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        TenantKey NVARCHAR(100) NOT NULL,
        Provider NVARCHAR(64) NOT NULL,
        StartedAt DATETIMEOFFSET NOT NULL,
        CompletedAt DATETIMEOFFSET NULL,
        IndicatorsImported INT NOT NULL CONSTRAINT DF_IocFeedSyncRuns_Imported DEFAULT 0,
        IndicatorsSkipped INT NOT NULL CONSTRAINT DF_IocFeedSyncRuns_Skipped DEFAULT 0,
        Success BIT NOT NULL CONSTRAINT DF_IocFeedSyncRuns_Success DEFAULT 0,
        FailureReason NVARCHAR(512) NULL,
        CursorAfter NVARCHAR(512) NULL
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_IocFeedSyncRuns_StartedAt' AND object_id = OBJECT_ID('dbo.IocFeedSyncRuns'))
BEGIN
    CREATE INDEX IX_IocFeedSyncRuns_StartedAt ON dbo.IocFeedSyncRuns(TenantKey, Provider, StartedAt DESC);
END;

IF OBJECT_ID('dbo.ProviderHealthSnapshots', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.ProviderHealthSnapshots
    (
        Id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        TenantKey NVARCHAR(100) NOT NULL,
        Provider NVARCHAR(64) NOT NULL,
        Enabled BIT NOT NULL,
        LastSuccessAt DATETIMEOFFSET NULL,
        LastFailureAt DATETIMEOFFSET NULL,
        LastFailureReason NVARCHAR(512) NULL,
        CircuitState NVARCHAR(16) NOT NULL CONSTRAINT DF_ProviderHealthSnapshots_CircuitState DEFAULT 'Closed',
        RateLimitTokensRemaining INT NOT NULL CONSTRAINT DF_ProviderHealthSnapshots_RateLimit DEFAULT 0,
        LastSyncDurationMs INT NOT NULL CONSTRAINT DF_ProviderHealthSnapshots_SyncDuration DEFAULT 0,
        LastSyncCount INT NOT NULL CONSTRAINT DF_ProviderHealthSnapshots_SyncCount DEFAULT 0,
        LastSyncAt DATETIMEOFFSET NULL,
        UpdatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_ProviderHealthSnapshots_UpdatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ProviderHealthSnapshots_TenantProvider' AND object_id = OBJECT_ID('dbo.ProviderHealthSnapshots'))
BEGIN
    CREATE UNIQUE INDEX UX_ProviderHealthSnapshots_TenantProvider ON dbo.ProviderHealthSnapshots(TenantKey, Provider);
END;