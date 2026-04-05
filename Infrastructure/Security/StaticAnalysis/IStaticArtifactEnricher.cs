using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public interface IStaticArtifactEnricher
{
    Task<IReadOnlyCollection<DetectionEventRecord>> EnrichAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken = default);
}
