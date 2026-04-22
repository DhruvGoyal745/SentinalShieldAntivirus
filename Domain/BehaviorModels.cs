namespace Antivirus.Domain;

public enum BehaviorSignalType
{
    ProcessCreation,
    FileOperation,
    RegistryModification,
    NetworkActivity,
    ScriptExecution
}

public sealed record BehaviorSignal
{
    public required BehaviorSignalType SignalType { get; init; }
    public required string ProcessPath { get; init; }
    public string? ParentProcessPath { get; init; }
    public string? CommandLine { get; init; }
    public string? TargetPath { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class BehaviorRuleMatch
{
    public required string RuleId { get; init; }
    public List<BehaviorSignal> Signals { get; init; } = [];
    public required ThreatSeverity Severity { get; init; }
    public required decimal Confidence { get; init; }
    public required string Description { get; init; }
}

public sealed class ProcessLineage
{
    public required int ProcessId { get; init; }
    public required string ProcessPath { get; init; }
    public string? CommandLine { get; init; }
    public int? ParentProcessId { get; init; }
    public string? ParentProcessPath { get; init; }
    public DateTimeOffset CreationTime { get; init; }
    public List<ProcessLineage> Children { get; init; } = [];
}

public sealed record LOLBinPattern
{
    public required string ParentPattern { get; init; }
    public required string ChildPattern { get; init; }
    public required string Description { get; init; }
    public required ThreatSeverity Severity { get; init; }
    public required decimal Confidence { get; init; }
}
