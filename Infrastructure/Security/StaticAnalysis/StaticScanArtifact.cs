using System.Collections.ObjectModel;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class StaticScanArtifact
{
    private readonly Dictionary<string, string> _properties = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _archiveEntries = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _sections = new(StringComparer.OrdinalIgnoreCase);

    public StaticScanArtifact(FileInfo file, string? hashSha256)
    {
        File = file;
        HashSha256 = hashSha256;
        Classification = InferClassification(file);
    }

    public FileInfo File { get; }

    public string? HashSha256 { get; }

    public string Classification { get; set; }

    public string? TextContent { get; set; }

    public long? ArchiveEntryCount { get; set; }

    public long? ArchiveExpandedBytes { get; set; }

    public long? ArchiveCompressedBytes { get; set; }

    public IReadOnlyDictionary<string, string> Properties => new ReadOnlyDictionary<string, string>(_properties);

    public IReadOnlyCollection<string> ArchiveEntries => _archiveEntries;

    public IReadOnlyCollection<string> Sections => _sections;

    public void SetProperty(string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        _properties[key] = value;
    }

    public void AddArchiveEntry(string? entry)
    {
        if (!string.IsNullOrWhiteSpace(entry))
        {
            _archiveEntries.Add(entry);
        }
    }

    public void AddSection(string? section)
    {
        if (!string.IsNullOrWhiteSpace(section))
        {
            _sections.Add(section);
        }
    }

    private static string InferClassification(FileInfo file)
    {
        var extension = file.Extension.ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(extension))
        {
            return "GENERIC";
        }

        return extension switch
        {
            ".exe" or ".dll" or ".sys" => "PE",
            ".so" or ".elf" or ".bin" => "ELF",
            ".ps1" or ".vbs" or ".js" or ".cmd" or ".bat" or ".sh" or ".py" or ".rb" => "SCRIPT",
            ".zip" or ".rar" or ".7z" or ".tar" or ".gz" => "ARCHIVE",
            ".doc" or ".docx" or ".docm" or ".xls" or ".xlsx" or ".xlsm" or ".ppt" or ".pptx" or ".pptm" or ".pdf" => "DOCUMENT",
            _ => "GENERIC"
        };
    }
}
