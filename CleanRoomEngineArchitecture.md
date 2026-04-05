# Clean-Room Engine Architecture

This antivirus now follows a clean-room implementation strategy inspired by open-source antivirus product boundaries, without reusing ClamAV code.

## Runtime boundaries

- `Antivirus.Domain`
  Holds the shared domain models and enums used by the rest of the product.
- `Antivirus.Application`
  Holds contracts and orchestration services.
- `Antivirus.Infrastructure`
  Holds SQL persistence, background services, realtime watchers, and the clean-room engine implementation.
- `Antivirus`
  Hosts the ASP.NET API, middleware, and the React frontend.

## Clean-room static engine

The primary proprietary static path lives under `Infrastructure/Security/StaticAnalysis`.

- `StaticScanArtifact`
  Shared artifact model that carries file metadata, content snippets, archive members, and parsed properties.
- `ContentHeuristicEnricher`
  Reads a bounded content window and extracts script and macro heuristics.
- `PortableExecutableMetadataEnricher`
  Parses PE headers and section names without external engines.
- `ElfMetadataEnricher`
  Parses ELF headers and basic machine/class metadata.
- `ArchiveMetadataEnricher`
  Inspects ZIP archives, captures member names, and flags expansion anomalies.
- `StaticRuleEvaluator`
  Applies compiled proprietary rules against the enriched artifact.

## Rule format

The signature compiler supports these rule prefixes:

- `sha256:...`
- `name:...`
- `path:...`
- `content:...`
- `pe:...`
- `elf:...`
- `archive:...`

Examples:

- `content:EncodedCommand`
- `name:.pdf.exe`
- `pe:section=UPX`
- `archive:member=.js`

## Current scope

This is a clean-room user-mode engine foundation. It includes:

- proprietary signature pack compilation
- bounded content inspection
- PE and ELF header analysis
- ZIP archive inspection
- manual scan progress integration
- realtime scan orchestration

It does not yet include:

- kernel blocking
- full archive support for RAR and 7z
- sandbox detonation implementation
- native engine daemon IPC replacing the managed fallback
