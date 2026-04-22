using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlControlPlaneRepository : IControlPlaneRepository
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly ITenantRegistry _tenantRegistry;
    private readonly AntivirusPlatformOptions _options;

    public SqlControlPlaneRepository(ITenantRegistry tenantRegistry, IOptions<AntivirusPlatformOptions> options)
    {
        _tenantRegistry = tenantRegistry;
        _options = options.Value;
    }

    public async Task<DeviceProfile> UpsertDeviceAsync(AgentRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        const string existsSql = "SELECT TOP (1) Id FROM dbo.Devices WHERE DeviceId = @DeviceId;";
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);

        int? existingId;
        await using (var existsCommand = new SqlCommand(existsSql, connection))
        {
            existsCommand.Parameters.AddWithValue("@DeviceId", request.DeviceId);
            var scalar = await existsCommand.ExecuteScalarAsync(cancellationToken);
            existingId = scalar is null ? null : Convert.ToInt32(scalar);
        }

        var selfProtectionJson = JsonSerializer.Serialize(DefaultSelfProtection(), JsonOptions);
        var capabilitiesJson = JsonSerializer.Serialize(request.Capabilities, JsonOptions);

        if (existingId is null)
        {
            const string insertSql = """
                INSERT INTO dbo.Devices
                (
                    DeviceId, DeviceName, OperatingSystem, AgentVersion, EngineVersion, SignaturePackVersion, PolicyVersion,
                    RolloutRing, EnrollmentStatus, BaselineScanCompleted, LegacyShadowModeEnabled, SelfProtectionJson,
                    CapabilitiesJson, LastSeenAt
                )
                VALUES
                (
                    @DeviceId, @DeviceName, @OperatingSystem, @AgentVersion, @EngineVersion, @SignaturePackVersion, @PolicyVersion,
                    @RolloutRing, @EnrollmentStatus, 0, @LegacyShadowModeEnabled, @SelfProtectionJson, @CapabilitiesJson, SYSUTCDATETIME()
                );
                """;

            await using var insertCommand = new SqlCommand(insertSql, connection);
            insertCommand.Parameters.AddWithValue("@DeviceId", request.DeviceId);
            insertCommand.Parameters.AddWithValue("@DeviceName", request.DeviceName);
            insertCommand.Parameters.AddWithValue("@OperatingSystem", request.OperatingSystem.ToString());
            insertCommand.Parameters.AddWithValue("@AgentVersion", request.AgentVersion);
            insertCommand.Parameters.AddWithValue("@EngineVersion", request.EngineVersion);
            insertCommand.Parameters.AddWithValue("@SignaturePackVersion", _options.CurrentSignaturePackVersion);
            insertCommand.Parameters.AddWithValue("@PolicyVersion", _options.CurrentPolicyVersion);
            insertCommand.Parameters.AddWithValue("@RolloutRing", request.RolloutRing.ToString());
            insertCommand.Parameters.AddWithValue("@EnrollmentStatus", DeviceEnrollmentStatus.Active.ToString());
            insertCommand.Parameters.AddWithValue("@LegacyShadowModeEnabled", _options.UseLegacyShadowMode);
            insertCommand.Parameters.AddWithValue("@SelfProtectionJson", selfProtectionJson);
            insertCommand.Parameters.AddWithValue("@CapabilitiesJson", capabilitiesJson);
            await insertCommand.ExecuteNonQueryAsync(cancellationToken);
        }
        else
        {
            const string updateSql = """
                UPDATE dbo.Devices
                SET DeviceName = @DeviceName,
                    OperatingSystem = @OperatingSystem,
                    AgentVersion = @AgentVersion,
                    EngineVersion = @EngineVersion,
                    RolloutRing = @RolloutRing,
                    CapabilitiesJson = @CapabilitiesJson,
                    LastSeenAt = SYSUTCDATETIME()
                WHERE DeviceId = @DeviceId;
                """;

            await using var updateCommand = new SqlCommand(updateSql, connection);
            updateCommand.Parameters.AddWithValue("@DeviceId", request.DeviceId);
            updateCommand.Parameters.AddWithValue("@DeviceName", request.DeviceName);
            updateCommand.Parameters.AddWithValue("@OperatingSystem", request.OperatingSystem.ToString());
            updateCommand.Parameters.AddWithValue("@AgentVersion", request.AgentVersion);
            updateCommand.Parameters.AddWithValue("@EngineVersion", request.EngineVersion);
            updateCommand.Parameters.AddWithValue("@RolloutRing", request.RolloutRing.ToString());
            updateCommand.Parameters.AddWithValue("@CapabilitiesJson", capabilitiesJson);
            await updateCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        return await GetDeviceAsync(request.DeviceId, cancellationToken)
            ?? throw new InvalidOperationException($"Device {request.DeviceId} could not be loaded after registration.");
    }

    public async Task<DeviceProfile?> GetDeviceAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (1) Id, DeviceId, DeviceName, OperatingSystem, AgentVersion, EngineVersion, SignaturePackVersion, PolicyVersion,
            RolloutRing, EnrollmentStatus, BaselineScanCompleted, LegacyShadowModeEnabled, SelfProtectionJson, CapabilitiesJson, CreatedAt, LastSeenAt
            FROM dbo.Devices
            WHERE DeviceId = @DeviceId;
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@DeviceId", deviceId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? MapDevice(reader) : null;
    }

    public async Task<IReadOnlyCollection<DeviceProfile>> GetDevicesAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, DeviceId, DeviceName, OperatingSystem, AgentVersion, EngineVersion, SignaturePackVersion, PolicyVersion,
            RolloutRing, EnrollmentStatus, BaselineScanCompleted, LegacyShadowModeEnabled, SelfProtectionJson, CapabilitiesJson, CreatedAt, LastSeenAt
            FROM dbo.Devices
            ORDER BY LastSeenAt DESC, CreatedAt DESC;
            """;

        var devices = new List<DeviceProfile>();
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        while (await reader.ReadAsync(cancellationToken))
        {
            devices.Add(MapDevice(reader));
        }

        return devices;
    }

    public async Task SaveHeartbeatAsync(AgentHeartbeatRequest request, CancellationToken cancellationToken = default)
    {
        const string updateSql = """
            UPDATE dbo.Devices
            SET AgentVersion = @AgentVersion,
                EngineVersion = @EngineVersion,
                SignaturePackVersion = @SignaturePackVersion,
                PolicyVersion = @PolicyVersion,
                BaselineScanCompleted = @BaselineScanCompleted,
                LegacyShadowModeEnabled = @LegacyShadowModeEnabled,
                SelfProtectionJson = @SelfProtectionJson,
                LastSeenAt = SYSUTCDATETIME()
            WHERE DeviceId = @DeviceId;
            """;

        const string insertSql = """
            INSERT INTO dbo.AgentHeartbeats
            (DeviceId, AgentVersion, EngineVersion, SignaturePackVersion, PolicyVersion, BaselineScanCompleted, LegacyShadowModeEnabled, SelfProtectionJson)
            VALUES
            (@DeviceId, @AgentVersion, @EngineVersion, @SignaturePackVersion, @PolicyVersion, @BaselineScanCompleted, @LegacyShadowModeEnabled, @SelfProtectionJson);
            """;

        var selfProtectionJson = JsonSerializer.Serialize(request.SelfProtection, JsonOptions);
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();

        try
        {
            await using (var updateCommand = new SqlCommand(updateSql, connection, transaction))
            {
                updateCommand.Parameters.AddWithValue("@DeviceId", request.DeviceId);
                updateCommand.Parameters.AddWithValue("@AgentVersion", request.AgentVersion);
                updateCommand.Parameters.AddWithValue("@EngineVersion", request.EngineVersion);
                updateCommand.Parameters.AddWithValue("@SignaturePackVersion", request.SignaturePackVersion);
                updateCommand.Parameters.AddWithValue("@PolicyVersion", request.PolicyVersion);
                updateCommand.Parameters.AddWithValue("@BaselineScanCompleted", request.BaselineScanCompleted);
                updateCommand.Parameters.AddWithValue("@LegacyShadowModeEnabled", request.LegacyShadowModeEnabled);
                updateCommand.Parameters.AddWithValue("@SelfProtectionJson", selfProtectionJson);
                await updateCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            await using (var insertCommand = new SqlCommand(insertSql, connection, transaction))
            {
                insertCommand.Parameters.AddWithValue("@DeviceId", request.DeviceId);
                insertCommand.Parameters.AddWithValue("@AgentVersion", request.AgentVersion);
                insertCommand.Parameters.AddWithValue("@EngineVersion", request.EngineVersion);
                insertCommand.Parameters.AddWithValue("@SignaturePackVersion", request.SignaturePackVersion);
                insertCommand.Parameters.AddWithValue("@PolicyVersion", request.PolicyVersion);
                insertCommand.Parameters.AddWithValue("@BaselineScanCompleted", request.BaselineScanCompleted);
                insertCommand.Parameters.AddWithValue("@LegacyShadowModeEnabled", request.LegacyShadowModeEnabled);
                insertCommand.Parameters.AddWithValue("@SelfProtectionJson", selfProtectionJson);
                await insertCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public async Task<DevicePolicyBundle> GetActivePolicyAsync(CancellationToken cancellationToken = default)
    {
        const string ensureSql = """
            IF NOT EXISTS (SELECT 1 FROM dbo.PolicyBundles WHERE IsActive = 1)
            BEGIN
                INSERT INTO dbo.PolicyBundles
                (PolicyName, Version, RolloutRing, QuarantineOnMalicious, BlockHighConfidenceDetections, AllowSampleUpload, EnableLegacyShadowMode, PolicyJson, IsActive)
                VALUES
                (N'Enterprise default policy', @Version, N'Canary', 1, 1, @AllowSampleUpload, @EnableLegacyShadowMode, @PolicyJson, 1);
            END;
            """;

        const string sql = """
            SELECT TOP (1) Id, PolicyName, Version, RolloutRing, QuarantineOnMalicious, BlockHighConfidenceDetections, AllowSampleUpload, EnableLegacyShadowMode, PolicyJson, CreatedAt
            FROM dbo.PolicyBundles
            WHERE IsActive = 1
            ORDER BY CreatedAt DESC;
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using (var ensureCommand = new SqlCommand(ensureSql, connection))
        {
            ensureCommand.Parameters.AddWithValue("@Version", _options.CurrentPolicyVersion);
            ensureCommand.Parameters.AddWithValue("@AllowSampleUpload", _options.AllowSampleUpload);
            ensureCommand.Parameters.AddWithValue("@EnableLegacyShadowMode", _options.UseLegacyShadowMode);
            ensureCommand.Parameters.AddWithValue("@PolicyJson", BuildDefaultPolicyJson());
            await ensureCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);

        return new DevicePolicyBundle
        {
            Id = reader.GetInt32(0),
            PolicyName = reader.GetString(1),
            Version = reader.GetString(2),
            RolloutRing = Enum.Parse<PackRolloutRing>(reader.GetString(3)),
            QuarantineOnMalicious = reader.GetBoolean(4),
            BlockHighConfidenceDetections = reader.GetBoolean(5),
            AllowSampleUpload = reader.GetBoolean(6),
            EnableLegacyShadowMode = reader.GetBoolean(7),
            PolicyJson = reader.GetString(8),
            CreatedAt = reader.GetDateTimeOffset(9)
        };
    }

    public async Task<SignaturePackManifest> GetCurrentSignaturePackAsync(CancellationToken cancellationToken = default)
    {
        const string ensureSql = """
            IF NOT EXISTS (SELECT 1 FROM dbo.GlobalSignaturePackManifests WHERE Status = 'Released')
            BEGIN
                INSERT INTO dbo.GlobalSignaturePackManifests
                (Version, RolloutRing, Channel, IsDelta, Sha256, DownloadUrl, SignatureCount, MinAgentVersion, Status, ReleasedAt, Notes)
                VALUES
                (@Version, N'Canary', @Channel, 0, @Sha256, @DownloadUrl, 12, N'1.0.0', N'Released', SYSUTCDATETIME(), N'Seeded pack for enterprise control-plane rollout.');
            END;
            """;

        const string sql = """
            SELECT TOP (1) Id, Version, RolloutRing, Channel, IsDelta, Sha256, DownloadUrl, SignatureCount, MinAgentVersion, Status, CreatedAt, ReleasedAt
            FROM dbo.GlobalSignaturePackManifests
            WHERE Status = 'Released'
            ORDER BY ReleasedAt DESC, CreatedAt DESC;
            """;

        await using var connection = await _tenantRegistry.OpenPlatformConnectionAsync(cancellationToken);
        await using (var ensureCommand = new SqlCommand(ensureSql, connection))
        {
            ensureCommand.Parameters.AddWithValue("@Version", _options.CurrentSignaturePackVersion);
            ensureCommand.Parameters.AddWithValue("@Channel", _options.SignaturePackChannel);
            ensureCommand.Parameters.AddWithValue("@Sha256", "seeded-pack-sha256");
            ensureCommand.Parameters.AddWithValue("@DownloadUrl", _options.SignaturePackDownloadUrl);
            await ensureCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return MapPack(reader);
    }

    public async Task<IReadOnlyCollection<SignaturePackManifest>> GetSignaturePacksAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, Version, RolloutRing, Channel, IsDelta, Sha256, DownloadUrl, SignatureCount, MinAgentVersion, Status, CreatedAt, ReleasedAt
            FROM dbo.GlobalSignaturePackManifests
            ORDER BY CreatedAt DESC;
            """;

        var packs = new List<SignaturePackManifest>();
        await using var connection = await _tenantRegistry.OpenPlatformConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            packs.Add(MapPack(reader));
        }

        if (packs.Count == 0)
        {
            packs.Add(await GetCurrentSignaturePackAsync(cancellationToken));
        }

        return packs;
    }

    public async Task<IReadOnlyCollection<SignatureRuleDefinition>> GetEnabledSignatureRulesAsync(CancellationToken cancellationToken = default)
    {
        const string seedSql = """
            IF NOT EXISTS (SELECT 1 FROM dbo.SignatureRules)
            BEGIN
                INSERT INTO dbo.SignatureRules (RuleName, Pattern, Severity, IsEnabled)
                VALUES
                (N'Encoded PowerShell payload', N'content:EncodedCommand', N'High', 1),
                (N'Mimikatz marker', N'content:mimikatz', N'Critical', 1),
                (N'Suspicious double extension', N'name:.pdf.exe', N'High', 1),
                (N'Ransomware extension burst', N'path:.locked', N'Critical', 1),
                (N'Packed PE section', N'pe:section=UPX', N'Medium', 1),
                (N'Archive script payload', N'archive:member=.js', N'Medium', 1),
                (N'Office macro project', N'doc:hasMacros=true', N'High', 1),
                (N'External document relationship', N'doc:hasExternalRelationships=true', N'High', 1),
                (N'PDF active action', N'doc:hasOpenAction=true', N'High', 1);
            END;
            """;

        const string sql = """
            SELECT Id, RuleName, Pattern, Severity
            FROM dbo.SignatureRules
            WHERE IsEnabled = 1
            ORDER BY RuleName;
            """;

        var rules = new List<SignatureRuleDefinition>();
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using (var seedCommand = new SqlCommand(seedSql, connection))
        {
            await seedCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rules.Add(new SignatureRuleDefinition
            {
                Id = reader.GetInt32(0),
                RuleName = reader.GetString(1),
                Pattern = reader.GetString(2),
                Severity = Enum.Parse<ThreatSeverity>(reader.GetString(3))
            });
        }

        return rules;
    }

    public async Task<SecurityIncident> CreateIncidentAsync(SecurityIncident incident, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO dbo.SecurityIncidents
            (ScanJobId, DeviceId, Title, Severity, Status, Source, PrimaryArtifact, RuleId, Confidence, Summary, UpdatedAt)
            OUTPUT INSERTED.Id, INSERTED.ScanJobId, INSERTED.DeviceId, INSERTED.Title, INSERTED.Severity, INSERTED.Status, INSERTED.Source, INSERTED.PrimaryArtifact, INSERTED.RuleId, INSERTED.Confidence, INSERTED.Summary, INSERTED.CreatedAt, INSERTED.UpdatedAt
            VALUES
            (@ScanJobId, @DeviceId, @Title, @Severity, @Status, @Source, @PrimaryArtifact, @RuleId, @Confidence, @Summary, @UpdatedAt);
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ScanJobId", incident.ScanJobId.HasValue ? incident.ScanJobId.Value : DBNull.Value);
        command.Parameters.AddWithValue("@DeviceId", incident.DeviceId);
        command.Parameters.AddWithValue("@Title", incident.Title);
        command.Parameters.AddWithValue("@Severity", incident.Severity.ToString());
        command.Parameters.AddWithValue("@Status", incident.Status.ToString());
        command.Parameters.AddWithValue("@Source", incident.Source);
        command.Parameters.AddWithValue("@PrimaryArtifact", incident.PrimaryArtifact);
        command.Parameters.AddWithValue("@RuleId", incident.RuleId);
        command.Parameters.AddWithValue("@Confidence", incident.Confidence);
        command.Parameters.AddWithValue("@Summary", incident.Summary);
        command.Parameters.AddWithValue("@UpdatedAt", incident.UpdatedAt.HasValue ? incident.UpdatedAt.Value : DBNull.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);

        return new SecurityIncident
        {
            Id = reader.GetInt32(0),
            ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
            DeviceId = reader.GetString(2),
            Title = reader.GetString(3),
            Severity = Enum.Parse<ThreatSeverity>(reader.GetString(4)),
            Status = Enum.Parse<IncidentStatus>(reader.GetString(5)),
            Source = reader.GetString(6),
            PrimaryArtifact = reader.GetString(7),
            RuleId = reader.GetString(8),
            Confidence = reader.GetDecimal(9),
            Summary = reader.GetString(10),
            CreatedAt = reader.GetDateTimeOffset(11),
            UpdatedAt = reader.IsDBNull(12) ? null : reader.GetFieldValue<DateTimeOffset>(12)
        };
    }

    public async Task<bool> ResolveIncidentAsync(int incidentId, string resolvedBy, CancellationToken cancellationToken = default)
    {
        const string updateSql = """
            UPDATE dbo.SecurityIncidents
            SET Status = @Status,
                UpdatedAt = SYSUTCDATETIME(),
                Summary = CONCAT(Summary, CHAR(10), 'Resolved by ', @ResolvedBy, ' at ', CONVERT(nvarchar(40), SYSUTCDATETIME(), 127))
            WHERE Id = @Id;
            """;

        const string auditSql = """
            INSERT INTO dbo.AuditTrail (Category, Subject, PerformedBy, Details)
            VALUES (N'Incident', @Subject, @PerformedBy, @Details);
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var updateCommand = new SqlCommand(updateSql, connection);
        updateCommand.Parameters.AddWithValue("@Id", incidentId);
        updateCommand.Parameters.AddWithValue("@Status", IncidentStatus.Resolved.ToString());
        updateCommand.Parameters.AddWithValue("@ResolvedBy", resolvedBy);
        var updated = await updateCommand.ExecuteNonQueryAsync(cancellationToken);

        if (updated > 0)
        {
            await using var auditCommand = new SqlCommand(auditSql, connection);
            auditCommand.Parameters.AddWithValue("@Subject", $"Incident #{incidentId}");
            auditCommand.Parameters.AddWithValue("@PerformedBy", resolvedBy);
            auditCommand.Parameters.AddWithValue("@Details", "Incident resolved from the enterprise dashboard.");
            await auditCommand.ExecuteNonQueryAsync(cancellationToken);
        }

        return updated > 0;
    }

    public async Task<IReadOnlyCollection<SecurityIncident>> GetIncidentsAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, ScanJobId, DeviceId, Title, Severity, Status, Source, PrimaryArtifact, RuleId, Confidence, Summary, CreatedAt, UpdatedAt
            FROM dbo.SecurityIncidents
            ORDER BY CreatedAt DESC;
            """;

        var incidents = new List<SecurityIncident>();
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            incidents.Add(new SecurityIncident
            {
                Id = reader.GetInt32(0),
                ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
                DeviceId = reader.GetString(2),
                Title = reader.GetString(3),
                Severity = Enum.Parse<ThreatSeverity>(reader.GetString(4)),
                Status = Enum.Parse<IncidentStatus>(reader.GetString(5)),
                Source = reader.GetString(6),
                PrimaryArtifact = reader.GetString(7),
                RuleId = reader.GetString(8),
                Confidence = reader.GetDecimal(9),
                Summary = reader.GetString(10),
                CreatedAt = reader.GetDateTimeOffset(11),
                UpdatedAt = reader.IsDBNull(12) ? null : reader.GetFieldValue<DateTimeOffset>(12)
            });
        }

        return incidents;
    }

    public async Task SaveRemediationActionAsync(RemediationActionRecord action, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO dbo.RemediationActions
            (DeviceId, ThreatDetectionId, IncidentId, ActionKind, Status, RequestedBy, Notes, CompletedAt)
            VALUES
            (@DeviceId, @ThreatDetectionId, @IncidentId, @ActionKind, @Status, @RequestedBy, @Notes, @CompletedAt);
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@DeviceId", action.DeviceId);
        command.Parameters.AddWithValue("@ThreatDetectionId", action.ThreatDetectionId.HasValue ? action.ThreatDetectionId.Value : DBNull.Value);
        command.Parameters.AddWithValue("@IncidentId", action.IncidentId.HasValue ? action.IncidentId.Value : DBNull.Value);
        command.Parameters.AddWithValue("@ActionKind", action.ActionKind.ToString());
        command.Parameters.AddWithValue("@Status", action.Status.ToString());
        command.Parameters.AddWithValue("@RequestedBy", action.RequestedBy);
        command.Parameters.AddWithValue("@Notes", action.Notes);
        command.Parameters.AddWithValue("@CompletedAt", action.CompletedAt.HasValue ? action.CompletedAt.Value : DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyCollection<ComplianceReport>> GetComplianceReportsAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, ReportType, ReportDate, AgentCoveragePercent, SignatureCurrencyPercent, PolicyCompliancePercent, BaselineScanCompletionPercent, OpenCriticalIncidentCount, QuarantinedThreatCount, SelfProtectionCoveragePercent, AuditFindingCount, ExportJson, CreatedAt
            FROM dbo.ComplianceReports
            ORDER BY ReportDate DESC, CreatedAt DESC;
            """;

        var reports = new List<ComplianceReport>();
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            reports.Add(new ComplianceReport
            {
                Id = reader.GetInt32(0),
                ReportType = Enum.Parse<ComplianceReportType>(reader.GetString(1)),
                ReportDate = reader.GetDateTimeOffset(2),
                AgentCoveragePercent = reader.GetDecimal(3),
                SignatureCurrencyPercent = reader.GetDecimal(4),
                PolicyCompliancePercent = reader.GetDecimal(5),
                BaselineScanCompletionPercent = reader.GetDecimal(6),
                OpenCriticalIncidentCount = reader.GetInt32(7),
                QuarantinedThreatCount = reader.GetInt32(8),
                SelfProtectionCoveragePercent = reader.GetDecimal(9),
                AuditFindingCount = reader.GetInt32(10),
                ExportJson = reader.GetString(11),
                CreatedAt = reader.GetDateTimeOffset(12)
            });
        }

        return reports;
    }

    public async Task<ComplianceReport> SaveComplianceReportAsync(ComplianceReport report, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO dbo.ComplianceReports
            (ReportType, ReportDate, AgentCoveragePercent, SignatureCurrencyPercent, PolicyCompliancePercent, BaselineScanCompletionPercent, OpenCriticalIncidentCount, QuarantinedThreatCount, SelfProtectionCoveragePercent, AuditFindingCount, ExportJson)
            OUTPUT INSERTED.Id, INSERTED.ReportType, INSERTED.ReportDate, INSERTED.AgentCoveragePercent, INSERTED.SignatureCurrencyPercent, INSERTED.PolicyCompliancePercent, INSERTED.BaselineScanCompletionPercent, INSERTED.OpenCriticalIncidentCount, INSERTED.QuarantinedThreatCount, INSERTED.SelfProtectionCoveragePercent, INSERTED.AuditFindingCount, INSERTED.ExportJson, INSERTED.CreatedAt
            VALUES
            (@ReportType, @ReportDate, @AgentCoveragePercent, @SignatureCurrencyPercent, @PolicyCompliancePercent, @BaselineScanCompletionPercent, @OpenCriticalIncidentCount, @QuarantinedThreatCount, @SelfProtectionCoveragePercent, @AuditFindingCount, @ExportJson);
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ReportType", report.ReportType.ToString());
        command.Parameters.AddWithValue("@ReportDate", report.ReportDate);
        command.Parameters.AddWithValue("@AgentCoveragePercent", report.AgentCoveragePercent);
        command.Parameters.AddWithValue("@SignatureCurrencyPercent", report.SignatureCurrencyPercent);
        command.Parameters.AddWithValue("@PolicyCompliancePercent", report.PolicyCompliancePercent);
        command.Parameters.AddWithValue("@BaselineScanCompletionPercent", report.BaselineScanCompletionPercent);
        command.Parameters.AddWithValue("@OpenCriticalIncidentCount", report.OpenCriticalIncidentCount);
        command.Parameters.AddWithValue("@QuarantinedThreatCount", report.QuarantinedThreatCount);
        command.Parameters.AddWithValue("@SelfProtectionCoveragePercent", report.SelfProtectionCoveragePercent);
        command.Parameters.AddWithValue("@AuditFindingCount", report.AuditFindingCount);
        command.Parameters.AddWithValue("@ExportJson", report.ExportJson);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);

        return new ComplianceReport
        {
            Id = reader.GetInt32(0),
            ReportType = Enum.Parse<ComplianceReportType>(reader.GetString(1)),
            ReportDate = reader.GetDateTimeOffset(2),
            AgentCoveragePercent = reader.GetDecimal(3),
            SignatureCurrencyPercent = reader.GetDecimal(4),
            PolicyCompliancePercent = reader.GetDecimal(5),
            BaselineScanCompletionPercent = reader.GetDecimal(6),
            OpenCriticalIncidentCount = reader.GetInt32(7),
            QuarantinedThreatCount = reader.GetInt32(8),
            SelfProtectionCoveragePercent = reader.GetDecimal(9),
            AuditFindingCount = reader.GetInt32(10),
            ExportJson = reader.GetString(11),
            CreatedAt = reader.GetDateTimeOffset(12)
        };
    }

    public async Task<FalsePositiveReview> CreateFalsePositiveReviewAsync(FalsePositiveReview review, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO dbo.FalsePositiveReviews
            (ScanJobId, ThreatDetectionId, ArtifactHash, RuleId, Scope, Status, Analyst, Notes, SubmittedAt, DecisionedAt)
            OUTPUT INSERTED.Id, INSERTED.ScanJobId, INSERTED.ThreatDetectionId, INSERTED.ArtifactHash, INSERTED.RuleId, INSERTED.Scope, INSERTED.Status, INSERTED.Analyst, INSERTED.Notes, INSERTED.SubmittedAt, INSERTED.DecisionedAt
            VALUES
            (@ScanJobId, @ThreatDetectionId, @ArtifactHash, @RuleId, @Scope, @Status, @Analyst, @Notes, @SubmittedAt, @DecisionedAt);
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ScanJobId", review.ScanJobId.HasValue ? review.ScanJobId.Value : DBNull.Value);
        command.Parameters.AddWithValue("@ThreatDetectionId", review.ThreatDetectionId.HasValue ? review.ThreatDetectionId.Value : DBNull.Value);
        command.Parameters.AddWithValue("@ArtifactHash", review.ArtifactHash);
        command.Parameters.AddWithValue("@RuleId", review.RuleId);
        command.Parameters.AddWithValue("@Scope", review.Scope.ToString());
        command.Parameters.AddWithValue("@Status", review.Status.ToString());
        command.Parameters.AddWithValue("@Analyst", review.Analyst);
        command.Parameters.AddWithValue("@Notes", review.Notes);
        command.Parameters.AddWithValue("@SubmittedAt", review.SubmittedAt);
        command.Parameters.AddWithValue("@DecisionedAt", review.DecisionedAt.HasValue ? review.DecisionedAt.Value : DBNull.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);

        return new FalsePositiveReview
        {
            Id = reader.GetInt32(0),
            ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
            ThreatDetectionId = reader.IsDBNull(2) ? null : reader.GetInt32(2),
            ArtifactHash = reader.GetString(3),
            RuleId = reader.GetString(4),
            Scope = Enum.Parse<FalsePositiveScope>(reader.GetString(5)),
            Status = Enum.Parse<FalsePositiveReviewStatus>(reader.GetString(6)),
            Analyst = reader.GetString(7),
            Notes = reader.GetString(8),
            SubmittedAt = reader.GetDateTimeOffset(9),
            DecisionedAt = reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10)
        };
    }

    public async Task<IReadOnlyCollection<FalsePositiveReview>> GetFalsePositiveReviewsAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, ScanJobId, ThreatDetectionId, ArtifactHash, RuleId, Scope, Status, Analyst, Notes, SubmittedAt, DecisionedAt
            FROM dbo.FalsePositiveReviews
            ORDER BY SubmittedAt DESC;
            """;

        var reviews = new List<FalsePositiveReview>();
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            reviews.Add(new FalsePositiveReview
            {
                Id = reader.GetInt32(0),
                ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
                ThreatDetectionId = reader.IsDBNull(2) ? null : reader.GetInt32(2),
                ArtifactHash = reader.GetString(3),
                RuleId = reader.GetString(4),
                Scope = Enum.Parse<FalsePositiveScope>(reader.GetString(5)),
                Status = Enum.Parse<FalsePositiveReviewStatus>(reader.GetString(6)),
                Analyst = reader.GetString(7),
                Notes = reader.GetString(8),
                SubmittedAt = reader.GetDateTimeOffset(9),
                DecisionedAt = reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10)
            });
        }

        return reviews;
    }

    public async Task<FalsePositiveReview?> DecideFalsePositiveReviewAsync(
        int reviewId,
        FalsePositiveReviewStatus status,
        string analyst,
        string? notes,
        CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE dbo.FalsePositiveReviews
            SET Status = @Status,
                Analyst = @Analyst,
                Notes = @Notes,
                DecisionedAt = @DecisionedAt
            OUTPUT INSERTED.Id, INSERTED.ThreatDetectionId, INSERTED.ArtifactHash, INSERTED.RuleId, INSERTED.Scope, INSERTED.Status, INSERTED.Analyst, INSERTED.Notes, INSERTED.SubmittedAt, INSERTED.DecisionedAt
            WHERE Id = @Id;
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Id", reviewId);
        command.Parameters.AddWithValue("@Status", status.ToString());
        command.Parameters.AddWithValue("@Analyst", analyst);
        command.Parameters.AddWithValue("@Notes", notes ?? string.Empty);
        command.Parameters.AddWithValue("@DecisionedAt", DateTimeOffset.UtcNow);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new FalsePositiveReview
        {
            Id = reader.GetInt32(0),
            ThreatDetectionId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
            ArtifactHash = reader.GetString(2),
            RuleId = reader.GetString(3),
            Scope = Enum.Parse<FalsePositiveScope>(reader.GetString(4)),
            Status = Enum.Parse<FalsePositiveReviewStatus>(reader.GetString(5)),
            Analyst = reader.GetString(6),
            Notes = reader.GetString(7),
            SubmittedAt = reader.GetDateTimeOffset(8),
            DecisionedAt = reader.IsDBNull(9) ? null : reader.GetFieldValue<DateTimeOffset>(9)
        };
    }

    public async Task<SandboxSubmission> CreateSandboxSubmissionAsync(SandboxSubmission submission, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO dbo.SandboxSubmissions
            (ScanJobId, DeviceId, ArtifactHash, FileName, Status, CorrelationId, Verdict, BehaviorSummary, IndicatorsJson, FamilyName, TagsJson, CreatedAt, UpdatedAt)
            OUTPUT INSERTED.Id, INSERTED.ScanJobId, INSERTED.DeviceId, INSERTED.ArtifactHash, INSERTED.FileName, INSERTED.Status, INSERTED.CorrelationId, INSERTED.Verdict, INSERTED.BehaviorSummary, INSERTED.IndicatorsJson, INSERTED.FamilyName, INSERTED.TagsJson, INSERTED.CreatedAt, INSERTED.UpdatedAt
            VALUES
            (@ScanJobId, @DeviceId, @ArtifactHash, @FileName, @Status, @CorrelationId, @Verdict, @BehaviorSummary, @IndicatorsJson, @FamilyName, @TagsJson, @CreatedAt, @UpdatedAt);
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ScanJobId", submission.ScanJobId.HasValue ? submission.ScanJobId.Value : DBNull.Value);
        command.Parameters.AddWithValue("@DeviceId", submission.DeviceId);
        command.Parameters.AddWithValue("@ArtifactHash", submission.ArtifactHash);
        command.Parameters.AddWithValue("@FileName", submission.FileName);
        command.Parameters.AddWithValue("@Status", submission.Status.ToString());
        command.Parameters.AddWithValue("@CorrelationId", submission.CorrelationId);
        command.Parameters.AddWithValue("@Verdict", submission.Verdict.ToString());
        command.Parameters.AddWithValue("@BehaviorSummary", submission.BehaviorSummary);
        command.Parameters.AddWithValue("@IndicatorsJson", submission.IndicatorsJson);
        command.Parameters.AddWithValue("@FamilyName", submission.FamilyName);
        command.Parameters.AddWithValue("@TagsJson", submission.TagsJson);
        command.Parameters.AddWithValue("@CreatedAt", submission.CreatedAt);
        command.Parameters.AddWithValue("@UpdatedAt", submission.UpdatedAt.HasValue ? submission.UpdatedAt.Value : DBNull.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);

        return new SandboxSubmission
        {
            Id = reader.GetInt32(0),
            ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
            DeviceId = reader.GetString(2),
            ArtifactHash = reader.GetString(3),
            FileName = reader.GetString(4),
            Status = Enum.Parse<SandboxSubmissionStatus>(reader.GetString(5)),
            CorrelationId = reader.GetString(6),
            Verdict = Enum.Parse<SandboxVerdict>(reader.GetString(7)),
            BehaviorSummary = reader.GetString(8),
            IndicatorsJson = reader.GetString(9),
            FamilyName = reader.GetString(10),
            TagsJson = reader.GetString(11),
            CreatedAt = reader.GetDateTimeOffset(12),
            UpdatedAt = reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13)
        };
    }

    public async Task<IReadOnlyCollection<SandboxSubmission>> GetSandboxSubmissionsAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, ScanJobId, DeviceId, ArtifactHash, FileName, Status, CorrelationId, Verdict, BehaviorSummary, IndicatorsJson, FamilyName, TagsJson, CreatedAt, UpdatedAt
            FROM dbo.SandboxSubmissions
            ORDER BY CreatedAt DESC;
            """;

        var submissions = new List<SandboxSubmission>();
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            submissions.Add(new SandboxSubmission
            {
                Id = reader.GetInt32(0),
                ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
                DeviceId = reader.GetString(2),
                ArtifactHash = reader.GetString(3),
                FileName = reader.GetString(4),
                Status = Enum.Parse<SandboxSubmissionStatus>(reader.GetString(5)),
                CorrelationId = reader.GetString(6),
                Verdict = Enum.Parse<SandboxVerdict>(reader.GetString(7)),
                BehaviorSummary = reader.GetString(8),
                IndicatorsJson = reader.GetString(9),
                FamilyName = reader.GetString(10),
                TagsJson = reader.GetString(11),
                CreatedAt = reader.GetDateTimeOffset(12),
                UpdatedAt = reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13)
            });
        }

        return submissions;
    }

    public async Task SaveLegacyParitySnapshotAsync(LegacyParitySnapshot snapshot, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO dbo.LegacyParitySnapshots
            (ScanJobId, DeviceId, OperatingSystem, MalwareFamily, DetectionRecallPercent, FalsePositiveRatePercent, VerdictLatencyMilliseconds, RemediationSuccessPercent, CrashTamperRatePercent, CreatedAt)
            VALUES
            (@ScanJobId, @DeviceId, @OperatingSystem, @MalwareFamily, @DetectionRecallPercent, @FalsePositiveRatePercent, @VerdictLatencyMilliseconds, @RemediationSuccessPercent, @CrashTamperRatePercent, @CreatedAt);
            """;

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ScanJobId", snapshot.ScanJobId.HasValue ? snapshot.ScanJobId.Value : DBNull.Value);
        command.Parameters.AddWithValue("@DeviceId", snapshot.DeviceId);
        command.Parameters.AddWithValue("@OperatingSystem", snapshot.OperatingSystem.ToString());
        command.Parameters.AddWithValue("@MalwareFamily", snapshot.MalwareFamily);
        command.Parameters.AddWithValue("@DetectionRecallPercent", snapshot.DetectionRecallPercent);
        command.Parameters.AddWithValue("@FalsePositiveRatePercent", snapshot.FalsePositiveRatePercent);
        command.Parameters.AddWithValue("@VerdictLatencyMilliseconds", snapshot.VerdictLatencyMilliseconds);
        command.Parameters.AddWithValue("@RemediationSuccessPercent", snapshot.RemediationSuccessPercent);
        command.Parameters.AddWithValue("@CrashTamperRatePercent", snapshot.CrashTamperRatePercent);
        command.Parameters.AddWithValue("@CreatedAt", snapshot.CreatedAt);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyCollection<LegacyParitySnapshot>> GetLegacyParitySnapshotsAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, ScanJobId, DeviceId, OperatingSystem, MalwareFamily, DetectionRecallPercent, FalsePositiveRatePercent, VerdictLatencyMilliseconds, RemediationSuccessPercent, CrashTamperRatePercent, CreatedAt
            FROM dbo.LegacyParitySnapshots
            ORDER BY CreatedAt DESC;
            """;

        var snapshots = new List<LegacyParitySnapshot>();
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            snapshots.Add(new LegacyParitySnapshot
            {
                Id = reader.GetInt32(0),
                ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
                DeviceId = reader.GetString(2),
                OperatingSystem = Enum.Parse<OperatingSystemPlatform>(reader.GetString(3)),
                MalwareFamily = reader.GetString(4),
                DetectionRecallPercent = reader.GetDecimal(5),
                FalsePositiveRatePercent = reader.GetDecimal(6),
                VerdictLatencyMilliseconds = reader.GetDecimal(7),
                RemediationSuccessPercent = reader.GetDecimal(8),
                CrashTamperRatePercent = reader.GetDecimal(9),
                CreatedAt = reader.GetDateTimeOffset(10)
            });
        }

        return snapshots;
    }

    private static DeviceProfile MapDevice(SqlDataReader reader)
    {
        return new DeviceProfile
        {
            Id = reader.GetInt32(0),
            DeviceId = reader.GetString(1),
            DeviceName = reader.GetString(2),
            OperatingSystem = Enum.Parse<OperatingSystemPlatform>(reader.GetString(3)),
            AgentVersion = reader.GetString(4),
            EngineVersion = reader.GetString(5),
            SignaturePackVersion = reader.GetString(6),
            PolicyVersion = reader.GetString(7),
            RolloutRing = Enum.Parse<PackRolloutRing>(reader.GetString(8)),
            EnrollmentStatus = Enum.Parse<DeviceEnrollmentStatus>(reader.GetString(9)),
            BaselineScanCompleted = reader.GetBoolean(10),
            LegacyShadowModeEnabled = reader.GetBoolean(11),
            SelfProtection = JsonSerializer.Deserialize<AgentSelfProtectionStatus>(reader.GetString(12), JsonOptions) ?? new AgentSelfProtectionStatus(),
            Capabilities = JsonSerializer.Deserialize<string[]>(reader.GetString(13), JsonOptions) ?? Array.Empty<string>(),
            CreatedAt = reader.GetDateTimeOffset(14),
            LastSeenAt = reader.IsDBNull(15) ? null : reader.GetFieldValue<DateTimeOffset>(15)
        };
    }

    private static SignaturePackManifest MapPack(SqlDataReader reader)
    {
        return new SignaturePackManifest
        {
            Id = reader.GetInt32(0),
            Version = reader.GetString(1),
            RolloutRing = Enum.Parse<PackRolloutRing>(reader.GetString(2)),
            Channel = reader.GetString(3),
            IsDelta = reader.GetBoolean(4),
            Sha256 = reader.GetString(5),
            DownloadUrl = reader.GetString(6),
            SignatureCount = reader.GetInt32(7),
            MinAgentVersion = reader.GetString(8),
            Status = Enum.Parse<SignaturePackStatus>(reader.GetString(9)),
            CreatedAt = reader.GetDateTimeOffset(10),
            ReleasedAt = reader.IsDBNull(11) ? null : reader.GetFieldValue<DateTimeOffset>(11)
        };
    }

    private static AgentSelfProtectionStatus DefaultSelfProtection() =>
        new()
        {
            ProcessProtectionEnabled = true,
            FileProtectionEnabled = true,
            ServiceProtectionEnabled = true,
            DriverProtectionEnabled = false,
            WatchdogHealthy = true,
            SignedUpdatesOnly = true
        };

    private string BuildDefaultPolicyJson()
    {
        var policy = new
        {
            quarantineOnMalicious = true,
            blockHighConfidenceDetections = true,
            allowSampleUpload = _options.AllowSampleUpload,
            enableLegacyShadowMode = _options.UseLegacyShadowMode,
            baselineScanMode = "Full",
            realtime = new
            {
                watchRoots = _options.WatchRoots,
                maxFileScanBytes = _options.MaxFileScanBytes
            }
        };

        return JsonSerializer.Serialize(policy, JsonOptions);
    }
}
