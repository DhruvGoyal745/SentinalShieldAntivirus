using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class BehaviorMonitor : IBehaviorMonitor
{
    public Task<IReadOnlyCollection<DetectionEventRecord>> AnalyzeAsync(FileWatchNotification notification, FileInfo file, CancellationToken cancellationToken = default)
    {
        var detections = new List<DetectionEventRecord>();
        var fullPath = file.FullName;

        if (fullPath.Contains("startup", StringComparison.OrdinalIgnoreCase)
            || fullPath.Contains("runonce", StringComparison.OrdinalIgnoreCase))
        {
            detections.Add(Create("beh-startup", ThreatSeverity.High, 0.91m, "Persistence-style startup path activity detected."));
        }

        if (notification.EventType == FileEventType.Renamed
            && file.Extension.Contains("locked", StringComparison.OrdinalIgnoreCase))
        {
            detections.Add(Create("beh-ransom", ThreatSeverity.Critical, 0.95m, "Rename pattern resembles ransomware extension activity."));
        }

        if (notification.EventType == FileEventType.Created
            && (file.Extension.Equals(".ps1", StringComparison.OrdinalIgnoreCase)
                || file.Extension.Equals(".vbs", StringComparison.OrdinalIgnoreCase)
                || file.Extension.Equals(".js", StringComparison.OrdinalIgnoreCase)))
        {
            detections.Add(Create("beh-scriptdrop", ThreatSeverity.Medium, 0.66m, "Script dropper behavior observed in realtime monitor."));
        }

        return Task.FromResult<IReadOnlyCollection<DetectionEventRecord>>(detections);
    }

    private static DetectionEventRecord Create(string ruleId, ThreatSeverity severity, decimal confidence, string summary) =>
        new()
        {
            RuleId = ruleId,
            EngineName = "Sentinel Behavior Engine",
            Source = ThreatSource.Behavior,
            Severity = severity,
            Confidence = confidence,
            Summary = summary
        };
}
