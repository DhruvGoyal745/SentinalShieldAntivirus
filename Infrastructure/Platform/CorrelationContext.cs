using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Antivirus.Infrastructure.Platform;

/// <summary>
/// Assigns a unique correlation ID to every request/operation and propagates it through
/// the entire processing pipeline (scan → engine → quarantine → incident).
/// Enables end-to-end tracing across structured log entries.
/// </summary>
public interface ICorrelationContext
{
    string CorrelationId { get; }

    string? ParentOperationId { get; }

    IDisposable BeginOperation(string operationName);
}

public sealed class CorrelationContext : ICorrelationContext
{
    private static readonly AsyncLocal<string?> Current = new();
    private static readonly AsyncLocal<string?> ParentId = new();

    public string CorrelationId => Current.Value ?? Guid.NewGuid().ToString("N");

    public string? ParentOperationId => ParentId.Value;

    public IDisposable BeginOperation(string operationName)
    {
        var previous = Current.Value;
        var previousParent = ParentId.Value;
        ParentId.Value = previous;
        Current.Value = Guid.NewGuid().ToString("N");
        return new OperationScope(previous, previousParent);
    }

    public static void SetCorrelationId(string correlationId)
    {
        Current.Value = correlationId;
    }

    private sealed class OperationScope : IDisposable
    {
        private readonly string? _previousCorrelationId;
        private readonly string? _previousParentId;

        public OperationScope(string? previousCorrelationId, string? previousParentId)
        {
            _previousCorrelationId = previousCorrelationId;
            _previousParentId = previousParentId;
        }

        public void Dispose()
        {
            Current.Value = _previousCorrelationId;
            ParentId.Value = _previousParentId;
        }
    }
}
