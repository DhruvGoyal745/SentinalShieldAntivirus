using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation.Ingestion;

/// <summary>
/// Pull-style threat-intel feed source. Implementations are stateless; the
/// caller passes the previous cursor and receives the new cursor + a batch
/// of indicators ready for upsert.
/// </summary>
public interface IIocFeedSource
{
    /// <summary>Provider key (matches <see cref="IReputationProvider.Name"/>).</summary>
    string Provider { get; }

    /// <summary>Fetch one page/window of indicators.</summary>
    Task<IocFeedFetchResult> FetchAsync(string tenantKey, string? cursor, int maxItems, CancellationToken cancellationToken);
}

public sealed class IocFeedFetchResult
{
    public IReadOnlyList<IocIndicator> Indicators { get; init; } = Array.Empty<IocIndicator>();
    public string? NextCursor { get; init; }
    public string? FailureReason { get; init; }
    public bool Success => FailureReason is null;
}
