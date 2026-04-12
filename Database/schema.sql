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

IF OBJECT_ID('dbo.LegacyParitySnapshots', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.LegacyParitySnapshots
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        DeviceId NVARCHAR(200) NOT NULL,
        OperatingSystem NVARCHAR(32) NOT NULL,
        MalwareFamily NVARCHAR(128) NOT NULL,
        DetectionRecallPercent DECIMAL(5,2) NOT NULL,
        FalsePositiveRatePercent DECIMAL(5,2) NOT NULL,
        VerdictLatencyMilliseconds DECIMAL(12,2) NOT NULL,
        RemediationSuccessPercent DECIMAL(5,2) NOT NULL,
        CrashTamperRatePercent DECIMAL(5,2) NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL
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
    CREATE INDEX IX_FileSecurityEvents_ObservedAt ON dbo.FileSecurityEvents(ObservedAt DESC);
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

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_LegacyParitySnapshots_CreatedAt' AND object_id = OBJECT_ID('dbo.LegacyParitySnapshots'))
BEGIN
    CREATE INDEX IX_LegacyParitySnapshots_CreatedAt ON dbo.LegacyParitySnapshots(CreatedAt DESC);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SandboxSubmissions_CreatedAt' AND object_id = OBJECT_ID('dbo.SandboxSubmissions'))
BEGIN
    CREATE INDEX IX_SandboxSubmissions_CreatedAt ON dbo.SandboxSubmissions(CreatedAt DESC);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ScanReportExports_ExportedAt' AND object_id = OBJECT_ID('dbo.ScanReportExports'))
BEGIN
    CREATE INDEX IX_ScanReportExports_ExportedAt ON dbo.ScanReportExports(ExportedAt DESC);
END;

IF COL_LENGTH('dbo.SecurityIncidents', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.SecurityIncidents ADD ScanJobId INT NULL;
END;

IF COL_LENGTH('dbo.FileSecurityEvents', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.FileSecurityEvents ADD ScanJobId INT NULL;
END;

IF COL_LENGTH('dbo.LegacyParitySnapshots', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.LegacyParitySnapshots ADD ScanJobId INT NULL;
END;

IF COL_LENGTH('dbo.SandboxSubmissions', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.SandboxSubmissions ADD ScanJobId INT NULL;
END;

IF COL_LENGTH('dbo.FalsePositiveReviews', 'ScanJobId') IS NULL
BEGIN
    ALTER TABLE dbo.FalsePositiveReviews ADD ScanJobId INT NULL;
END;
