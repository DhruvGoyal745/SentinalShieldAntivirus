using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/reports")]
public sealed class ReportsController : ControllerBase
{
    private readonly IScanReportService _scanReportService;

    public ReportsController(IScanReportService scanReportService)
    {
        _scanReportService = scanReportService;
    }

    [HttpGet("scans/exports")]
    public async Task<ActionResult<IReadOnlyCollection<ScanReportExport>>> GetExports(CancellationToken cancellationToken)
    {
        return Ok(await _scanReportService.GetExportsAsync(cancellationToken));
    }

    [HttpGet("scans/export")]
    public async Task<IActionResult> ExportAll([FromQuery] string? requestedBy, CancellationToken cancellationToken)
    {
        var report = await _scanReportService.ExportAllScansAsync(requestedBy ?? "enterprise-operator", cancellationToken);
        return File(report.Content, report.ContentType, report.FileName);
    }

    [HttpGet("scans/{scanId:int}/export")]
    public async Task<IActionResult> ExportScan(int scanId, [FromQuery] string? requestedBy, CancellationToken cancellationToken)
    {
        var report = await _scanReportService.ExportScanAsync(scanId, requestedBy ?? "enterprise-operator", cancellationToken);
        return File(report.Content, report.ContentType, report.FileName);
    }
}
