using System.Security;
using System.Text;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Application.Services;

public sealed class ScanReportService : IScanReportService
{
    private readonly IScanRepository _scanRepository;
    private readonly IThreatRepository _threatRepository;
    private readonly IReportExportRepository _reportExportRepository;

    public ScanReportService(
        IScanRepository scanRepository,
        IThreatRepository threatRepository,
        IReportExportRepository reportExportRepository)
    {
        _scanRepository = scanRepository;
        _threatRepository = threatRepository;
        _reportExportRepository = reportExportRepository;
    }

    public Task<IReadOnlyCollection<ScanReportExport>> GetExportsAsync(CancellationToken cancellationToken = default) =>
        _reportExportRepository.GetScanReportExportsAsync(50, cancellationToken);

    public async Task<(byte[] Content, string FileName, string ContentType)> ExportAllScansAsync(string requestedBy, CancellationToken cancellationToken = default)
    {
        var scans = await _scanRepository.GetRecentScansAsync(500, cancellationToken);
        var threats = await _threatRepository.GetThreatsAsync(activeOnly: false, cancellationToken);
        return await BuildExportAsync(null, scans, threats, requestedBy, cancellationToken);
    }

    public async Task<(byte[] Content, string FileName, string ContentType)> ExportScanAsync(int scanId, string requestedBy, CancellationToken cancellationToken = default)
    {
        var scan = await _scanRepository.GetScanByIdAsync(scanId, cancellationToken)
            ?? throw new InvalidOperationException($"Scan {scanId} was not found.");
        var threats = (await _threatRepository.GetThreatsAsync(activeOnly: false, cancellationToken))
            .Where(threat => threat.ScanJobId == scanId)
            .ToArray();
        return await BuildExportAsync(scanId, new[] { scan }, threats, requestedBy, cancellationToken);
    }

    private async Task<(byte[] Content, string FileName, string ContentType)> BuildExportAsync(
        int? scanId,
        IReadOnlyCollection<ScanJob> scans,
        IReadOnlyCollection<ThreatDetection> threats,
        string requestedBy,
        CancellationToken cancellationToken)
    {
        var fileName = scanId.HasValue
            ? $"scan-report-{scanId.Value}-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}.xls"
            : $"scan-report-all-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}.xls";
        var content = Encoding.UTF8.GetBytes(BuildSpreadsheetXml(scans, threats));

        await _reportExportRepository.CreateScanReportExportAsync(
            new ScanReportExport
            {
                ScanJobId = scanId,
                FileName = fileName,
                Format = "xls",
                ExportedBy = string.IsNullOrWhiteSpace(requestedBy) ? "enterprise-operator" : requestedBy,
                VulnerabilityCount = threats.Count,
                ExportedAt = DateTimeOffset.UtcNow
            },
            cancellationToken);

        return (content, fileName, "application/vnd.ms-excel");
    }

    private static string BuildSpreadsheetXml(IReadOnlyCollection<ScanJob> scans, IReadOnlyCollection<ThreatDetection> threats)
    {
        var builder = new StringBuilder();
        builder.AppendLine("<?xml version=\"1.0\"?>");
        builder.AppendLine("<?mso-application progid=\"Excel.Sheet\"?>");
        builder.AppendLine("<Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\"");
        builder.AppendLine(" xmlns:o=\"urn:schemas-microsoft-com:office:office\"");
        builder.AppendLine(" xmlns:x=\"urn:schemas-microsoft-com:office:excel\"");
        builder.AppendLine(" xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\">");
        builder.AppendLine("<Worksheet ss:Name=\"Scans\"><Table>");
        AppendRow(builder, "Scan ID", "Mode", "Status", "Threat Count", "Requested By", "Target Path", "Created At", "Started At", "Completed At", "Notes");
        foreach (var scan in scans.OrderByDescending(item => item.CreatedAt))
        {
            AppendRow(
                builder,
                scan.Id.ToString(),
                scan.Mode.ToString(),
                scan.Status.ToString(),
                scan.ThreatCount.ToString(),
                scan.RequestedBy,
                scan.TargetPath ?? "System default",
                scan.CreatedAt.ToString("u"),
                scan.StartedAt?.ToString("u") ?? string.Empty,
                scan.CompletedAt?.ToString("u") ?? string.Empty,
                scan.Notes ?? string.Empty);
        }

        builder.AppendLine("</Table></Worksheet>");
        builder.AppendLine("<Worksheet ss:Name=\"Vulnerabilities\"><Table>");
        AppendRow(builder, "Scan ID", "Detection ID", "Threat", "Category", "Severity", "Source", "Resource", "Description", "Quarantined", "Detected At");
        foreach (var threat in threats.OrderByDescending(item => item.DetectedAt))
        {
            AppendRow(
                builder,
                threat.ScanJobId?.ToString() ?? "Realtime",
                threat.Id.ToString(),
                threat.Name,
                threat.Category,
                threat.Severity.ToString(),
                threat.Source.ToString(),
                threat.Resource ?? string.Empty,
                threat.Description ?? string.Empty,
                threat.IsQuarantined ? "Yes" : "No",
                threat.DetectedAt.ToString("u"));
        }

        builder.AppendLine("</Table></Worksheet>");
        builder.AppendLine("</Workbook>");
        return builder.ToString();
    }

    private static void AppendRow(StringBuilder builder, params string[] values)
    {
        builder.AppendLine("<Row>");
        foreach (var value in values)
        {
            builder.Append("<Cell><Data ss:Type=\"String\">");
            builder.Append(SecurityElement.Escape(value));
            builder.AppendLine("</Data></Cell>");
        }

        builder.AppendLine("</Row>");
    }
}
