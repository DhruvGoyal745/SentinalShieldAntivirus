using System.Security.Cryptography.X509Certificates;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class AuthenticodeVerificationEnricher : IStaticArtifactEnricher
{
    private static readonly HashSet<string> SignableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".msi", ".msix", ".appx", ".ocx", ".drv"
    };

    public Task<IReadOnlyCollection<DetectionEventRecord>> EnrichAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken = default)
    {
        if (!SignableExtensions.Contains(artifact.File.Extension))
        {
            return Task.FromResult<IReadOnlyCollection<DetectionEventRecord>>(Array.Empty<DetectionEventRecord>());
        }

        if (!artifact.File.Exists || artifact.File.Length < 512)
        {
            return Task.FromResult<IReadOnlyCollection<DetectionEventRecord>>(Array.Empty<DetectionEventRecord>());
        }

        var detections = new List<DetectionEventRecord>();

        try
        {
            var certificate = X509Certificate2.CreateFromSignedFile(artifact.File.FullName);
            using var cert2 = new X509Certificate2(certificate);

            artifact.SetProperty("sig.signed", "true");
            artifact.SetProperty("sig.subject", cert2.Subject);
            artifact.SetProperty("sig.issuer", cert2.Issuer);
            artifact.SetProperty("sig.notAfter", cert2.NotAfter.ToString("O"));

            if (cert2.NotAfter < DateTimeOffset.UtcNow)
            {
                artifact.SetProperty("sig.expired", "true");
                detections.Add(new DetectionEventRecord
                {
                    RuleId = "heur-sig-expired-certificate",
                    EngineName = "Sentinel Authenticode Inspector",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.Medium,
                    Confidence = 0.60m,
                    Summary = $"Executable is signed but the certificate expired on {cert2.NotAfter:yyyy-MM-dd}."
                });
            }

            if (IsSelfSignedCertificate(cert2))
            {
                artifact.SetProperty("sig.selfSigned", "true");
                detections.Add(new DetectionEventRecord
                {
                    RuleId = "heur-sig-self-signed",
                    EngineName = "Sentinel Authenticode Inspector",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.Medium,
                    Confidence = 0.65m,
                    Summary = "Executable is signed with a self-signed certificate, which provides no trust chain verification."
                });
            }
        }
        catch
        {
            artifact.SetProperty("sig.signed", "false");

            if (IsInSuspiciousLocation(artifact.File))
            {
                detections.Add(new DetectionEventRecord
                {
                    RuleId = "heur-sig-unsigned-suspicious-location",
                    EngineName = "Sentinel Authenticode Inspector",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.High,
                    Confidence = 0.78m,
                    Summary = "Unsigned executable found in a user-writable location commonly abused for malware staging."
                });
            }
            else
            {
                detections.Add(new DetectionEventRecord
                {
                    RuleId = "heur-sig-unsigned-executable",
                    EngineName = "Sentinel Authenticode Inspector",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.Low,
                    Confidence = 0.40m,
                    Summary = "Executable does not carry a digital signature."
                });
            }
        }

        return Task.FromResult<IReadOnlyCollection<DetectionEventRecord>>(detections);
    }

    private static bool IsSelfSignedCertificate(X509Certificate2 certificate)
    {
        return string.Equals(certificate.Subject, certificate.Issuer, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInSuspiciousLocation(FileInfo file)
    {
        var path = file.FullName;
        return path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\tmp\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\AppData\Local\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\AppData\Roaming\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase);
    }
}
