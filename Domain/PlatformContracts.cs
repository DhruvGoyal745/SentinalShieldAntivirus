using System.Text.Json;
using System.Text.Json.Serialization;

namespace Antivirus.Domain;

/// <summary>
/// Versioned wire-format contracts for agent-to-cloud communication.
/// These are the stable schemas that enrolled agents depend on — changing a field
/// name or removing a property is a breaking change that requires a new version.
/// </summary>

// ── Envelope ────────────────────────────────────────────────────────────────

/// <summary>
/// Standard wrapper for all telemetry and command payloads.
/// The Version field determines which deserializer the receiver uses.
/// </summary>
public sealed class EventEnvelope
{
    [JsonPropertyName("v")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("schemaVersion")]
    public string SchemaVersion { get; init; } = "1.0.0";

    [JsonPropertyName("id")]
    public string EventId { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("correlationId")]
    public string? CorrelationId { get; init; }

    [JsonPropertyName("deviceId")]
    public string DeviceId { get; init; } = string.Empty;

    [JsonPropertyName("tenantKey")]
    public string? TenantKey { get; init; }

    [JsonPropertyName("type")]
    public string EventType { get; init; } = string.Empty;

    [JsonPropertyName("ts")]
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("payload")]
    public JsonElement? Payload { get; init; }
}

// ── Verdict ─────────────────────────────────────────────────────────────────

/// <summary>
/// Standardized scan verdict that the agent reports to the cloud and the cloud stores.
/// </summary>
public sealed class VerdictEnvelope
{
    [JsonPropertyName("v")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("correlationId")]
    public string? CorrelationId { get; init; }

    [JsonPropertyName("deviceId")]
    public string DeviceId { get; init; } = string.Empty;

    [JsonPropertyName("filePath")]
    public string? FilePath { get; init; }

    [JsonPropertyName("hashSha256")]
    public string? HashSha256 { get; init; }

    [JsonPropertyName("verdict")]
    public PipelineVerdict Verdict { get; init; }

    [JsonPropertyName("score")]
    public decimal Score { get; init; }

    [JsonPropertyName("engines")]
    public IReadOnlyCollection<EngineContribution> Engines { get; init; } = [];

    [JsonPropertyName("ts")]
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class EngineContribution
{
    [JsonPropertyName("name")]
    public string EngineName { get; init; } = string.Empty;

    [JsonPropertyName("ruleId")]
    public string? RuleId { get; init; }

    [JsonPropertyName("severity")]
    public ThreatSeverity Severity { get; init; }

    [JsonPropertyName("confidence")]
    public decimal Confidence { get; init; }
}

// ── Remote Actions ──────────────────────────────────────────────────────────

/// <summary>
/// Commands sent from the cloud/admin console to an agent, delivered via heartbeat response.
/// </summary>
public sealed class RemoteAction
{
    [JsonPropertyName("v")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("actionId")]
    public string ActionId { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("type")]
    public RemoteActionType ActionType { get; init; }

    [JsonPropertyName("parameters")]
    public JsonElement? Parameters { get; init; }

    [JsonPropertyName("issuedAt")]
    public DateTimeOffset IssuedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; init; }
}

public enum RemoteActionType
{
    RunScan,
    UpdateSignatures,
    IsolateNetwork,
    RestoreNetwork,
    CollectDiagnostics,
    ForceRestart,
    SetFeatureFlag
}

// ── Quarantine Item ─────────────────────────────────────────────────────────

public sealed class QuarantineItem
{
    [JsonPropertyName("v")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("itemId")]
    public string ItemId { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("originalPath")]
    public string OriginalPath { get; init; } = string.Empty;

    [JsonPropertyName("quarantinePath")]
    public string? QuarantinePath { get; init; }

    [JsonPropertyName("hashSha256")]
    public string? HashSha256 { get; init; }

    [JsonPropertyName("fileSizeBytes")]
    public long FileSizeBytes { get; init; }

    [JsonPropertyName("threatName")]
    public string? ThreatName { get; init; }

    [JsonPropertyName("quarantinedAt")]
    public DateTimeOffset QuarantinedAt { get; init; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("isRestored")]
    public bool IsRestored { get; init; }
}

// ── Investigation Case ──────────────────────────────────────────────────────

public sealed class InvestigationCase
{
    [JsonPropertyName("v")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("caseId")]
    public string CaseId { get; init; } = Guid.NewGuid().ToString("N");

    [JsonPropertyName("correlationId")]
    public string? CorrelationId { get; init; }

    [JsonPropertyName("deviceId")]
    public string DeviceId { get; init; } = string.Empty;

    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    [JsonPropertyName("severity")]
    public ThreatSeverity Severity { get; init; }

    [JsonPropertyName("status")]
    public IncidentStatus Status { get; init; }

    [JsonPropertyName("relatedIncidentIds")]
    public IReadOnlyCollection<int> RelatedIncidentIds { get; init; } = [];

    [JsonPropertyName("relatedThreatIds")]
    public IReadOnlyCollection<int> RelatedThreatIds { get; init; } = [];

    [JsonPropertyName("timelineJson")]
    public string? TimelineJson { get; init; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

// ── Agent Policy (versioned contract) ───────────────────────────────────────

/// <summary>
/// The policy contract that agents receive on heartbeat. Includes feature flags,
/// scan schedule, exclusion rules, and all engine toggle states.
/// </summary>
public sealed class AgentPolicyContract
{
    [JsonPropertyName("v")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("schemaVersion")]
    public string SchemaVersion { get; init; } = "1.0.0";

    [JsonPropertyName("policyId")]
    public string PolicyId { get; init; } = string.Empty;

    [JsonPropertyName("policyVersion")]
    public string PolicyVersion { get; init; } = string.Empty;

    [JsonPropertyName("featureFlags")]
    public IReadOnlyDictionary<string, bool> FeatureFlags { get; init; } = new Dictionary<string, bool>();

    [JsonPropertyName("scanScheduleCron")]
    public string? ScanScheduleCron { get; init; }

    [JsonPropertyName("exclusionPaths")]
    public IReadOnlyCollection<string> ExclusionPaths { get; init; } = [];

    [JsonPropertyName("exclusionExtensions")]
    public IReadOnlyCollection<string> ExclusionExtensions { get; init; } = [];

    [JsonPropertyName("exclusionProcesses")]
    public IReadOnlyCollection<string> ExclusionProcesses { get; init; } = [];

    [JsonPropertyName("quarantineOnMalicious")]
    public bool QuarantineOnMalicious { get; init; } = true;

    [JsonPropertyName("allowSampleUpload")]
    public bool AllowSampleUpload { get; init; }

    [JsonPropertyName("rolloutRing")]
    public PackRolloutRing RolloutRing { get; init; }

    [JsonPropertyName("pendingActions")]
    public IReadOnlyCollection<RemoteAction> PendingActions { get; init; } = [];
}
