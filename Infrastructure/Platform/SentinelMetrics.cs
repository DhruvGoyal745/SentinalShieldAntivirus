using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Antivirus.Infrastructure.Platform;

/// <summary>
/// Exposes key operational metrics using System.Diagnostics.Metrics so they can be scraped by
/// Prometheus, OpenTelemetry, or any compatible collector. Provides the performance baseline
/// that all later phases depend on for regression detection.
/// </summary>
public sealed class SentinelMetrics
{
    public static readonly string MeterName = "SentinelShield";

    private readonly Meter _meter;

    private readonly Counter<long> _filesScanned;
    private readonly Counter<long> _threatsDetected;
    private readonly Counter<long> _filesQuarantined;
    private readonly Counter<long> _incidentsCreated;
    private readonly Counter<long> _signaturePackLoads;
    private readonly Counter<long> _scanJobsCompleted;
    private readonly Counter<long> _realtimeEventsProcessed;
    private readonly Counter<long> _apiRequestsTotal;
    private readonly Counter<long> _apiRequestErrors;

    private readonly Histogram<double> _scanLatencyMs;
    private readonly Histogram<double> _apiLatencyMs;
    private readonly Histogram<double> _engineLatencyMs;
    private readonly Histogram<double> _scanThroughput;
    private readonly Histogram<double> _memoryWorkingSet;
    private readonly Counter<long> _crashesTotal;

    private long _scanQueueDepth;
    private long _fileEventQueueDepth;
    private double _idleCpuPercent;

    public SentinelMetrics()
    {
        _meter = new Meter(MeterName, "1.0.0");

        _filesScanned = _meter.CreateCounter<long>("sentinel.files.scanned", "files", "Total files scanned");
        _threatsDetected = _meter.CreateCounter<long>("sentinel.threats.detected", "threats", "Total threats detected");
        _filesQuarantined = _meter.CreateCounter<long>("sentinel.files.quarantined", "files", "Total files quarantined");
        _incidentsCreated = _meter.CreateCounter<long>("sentinel.incidents.created", "incidents", "Total incidents created");
        _signaturePackLoads = _meter.CreateCounter<long>("sentinel.sigpack.loads", "loads", "Signature pack reload count");
        _scanJobsCompleted = _meter.CreateCounter<long>("sentinel.scans.completed", "scans", "Total scan jobs completed");
        _realtimeEventsProcessed = _meter.CreateCounter<long>("sentinel.realtime.events", "events", "Total realtime file events processed");
        _apiRequestsTotal = _meter.CreateCounter<long>("sentinel.api.requests", "requests", "Total API requests");
        _apiRequestErrors = _meter.CreateCounter<long>("sentinel.api.errors", "errors", "Total API request errors");

        _scanLatencyMs = _meter.CreateHistogram<double>("sentinel.scan.latency", "ms", "Per-file scan latency");
        _apiLatencyMs = _meter.CreateHistogram<double>("sentinel.api.latency", "ms", "API request latency");
        _engineLatencyMs = _meter.CreateHistogram<double>("sentinel.engine.latency", "ms", "Engine daemon call latency");

        _scanThroughput = _meter.CreateHistogram<double>("sentinel.scan.throughput_files_per_second", "files/s", "Scan throughput in files per second");
        _memoryWorkingSet = _meter.CreateHistogram<double>("sentinel.memory.working_set_bytes", "bytes", "Process working set memory");
        _crashesTotal = _meter.CreateCounter<long>("sentinel.crashes.total", "crashes", "Total unhandled exceptions / crashes");

        _meter.CreateObservableGauge("sentinel.queue.scan.depth", () => Interlocked.Read(ref _scanQueueDepth), "items", "Scan job queue depth");
        _meter.CreateObservableGauge("sentinel.queue.fileevent.depth", () => Interlocked.Read(ref _fileEventQueueDepth), "items", "File event queue depth");
        _meter.CreateObservableGauge("sentinel.cpu.idle_percent", () => _idleCpuPercent, "%", "Idle CPU percentage");
    }

    public void RecordFileScanned() => _filesScanned.Add(1);
    public void RecordThreatDetected(int count = 1) => _threatsDetected.Add(count);
    public void RecordFileQuarantined() => _filesQuarantined.Add(1);
    public void RecordIncidentCreated() => _incidentsCreated.Add(1);
    public void RecordSignaturePackLoad() => _signaturePackLoads.Add(1);
    public void RecordScanCompleted() => _scanJobsCompleted.Add(1);
    public void RecordRealtimeEvent() => _realtimeEventsProcessed.Add(1);
    public void RecordApiRequest() => _apiRequestsTotal.Add(1);
    public void RecordApiError() => _apiRequestErrors.Add(1);

    public void RecordScanLatency(double milliseconds) => _scanLatencyMs.Record(milliseconds);
    public void RecordApiLatency(double milliseconds) => _apiLatencyMs.Record(milliseconds);
    public void RecordEngineLatency(double milliseconds) => _engineLatencyMs.Record(milliseconds);

    public void SetScanQueueDepth(long depth) => Interlocked.Exchange(ref _scanQueueDepth, depth);
    public void SetFileEventQueueDepth(long depth) => Interlocked.Exchange(ref _fileEventQueueDepth, depth);

    public void RecordScanThroughput(double filesPerSecond) => _scanThroughput.Record(filesPerSecond);
    public void RecordMemoryWorkingSet(double bytes) => _memoryWorkingSet.Record(bytes);
    public void SetIdleCpuPercent(double percent) => _idleCpuPercent = percent;
    public void RecordCrash() => _crashesTotal.Add(1);
}
