using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public sealed class RansomwareController : ControllerBase
{
    private readonly IRansomwareShield _ransomwareShield;
    private readonly AntivirusPlatformOptions _options;

    public RansomwareController(IRansomwareShield ransomwareShield, IOptions<AntivirusPlatformOptions> options)
    {
        _ransomwareShield = ransomwareShield;
        _options = options.Value;
    }

    [HttpGet("signals")]
    public IActionResult GetSignals([FromQuery] int maxCount = 20)
    {
        var signals = _ransomwareShield.GetRecentSignals(Math.Clamp(maxCount, 1, 100));
        return Ok(signals);
    }

    [HttpGet("protected-folders")]
    public IActionResult GetProtectedFolders()
    {
        var configured = _options.ProtectedFolders;
        var folders = configured.Length > 0
            ? configured
            : new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
            };

        return Ok(folders.Where(f => !string.IsNullOrEmpty(f)));
    }
}
