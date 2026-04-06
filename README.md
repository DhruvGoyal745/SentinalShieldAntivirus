# Sentinel Shield Antivirus

A full-stack endpoint security platform built with **.NET 10** and **React**. Sentinel Shield combines a proprietary multi-stage scan engine, real-time file monitoring, heuristic analysis, open-source scanner integration, and an enterprise control plane — all shipped as a single self-contained executable.

---

## Features

### Scan Engine
- **Multi-stage pipeline** — Observe → Normalize → Static Analysis → Heuristic Analysis → Reputation Lookup → Response → Telemetry
- **Quick, Full, and Custom scan modes** with parallel file processing
- **Proprietary signature pack compiler** with versioned rule packs
- **Static artifact enrichment** — PE metadata, ELF headers, document properties, archive inspection, and content heuristics
- **Heuristic rules** — suspicious extensions, double extensions, startup script detection
- **SHA-256 hash computation** and reputation evaluation
- **Sandbox submission broker** for detonation-based analysis
- **Automatic quarantine** of malicious artifacts with remediation tracking

### Real-Time Protection
- **File system watcher** monitoring Downloads, Desktop, Documents, Temp, and Startup folders
- **Background event queue** with debounced processing
- **Skipped file detection** — locked/in-use files are flagged with a user prompt to retry or skip

### Open-Source Scanner Integration
- **YARA** rule engine support
- **ClamAV** command-line and daemon mode support
- Legacy shadow mode for parity comparison between proprietary and open-source engines

### Enterprise Control Plane
- **Multi-tenant architecture** with per-tenant databases
- **Fleet posture dashboard** — device count, agent coverage, policy compliance, self-protection status
- **Security incident management** — auto-created from high-confidence detections
- **Compliance reporting** with snapshot capture
- **Agent registration and heartbeat** protocol
- **Signature pack rollout** with ring-based deployment (Canary → GA)
- **Governance workflows** — legacy parity snapshots, sandbox queue, false-positive reviews

### Dashboard & UI
- **React SPA** with seven dedicated pages:
  - **Home** — live scan progress bar, scan controls, fleet summary
  - **Incidents** — open/resolved security incidents
  - **Detections** — threat signals with quarantine and false-positive actions
  - **Telemetry** — real-time file events and scan history
  - **Fleet** — device posture, signature pack versions, agent health
  - **Governance** — legacy parity, sandbox submissions, review workflows
  - **Reports** — Excel export of scan results and compliance snapshots
- **Scan selector dropdown** for filtering data by scan across all pages
- **Skipped file modal** — popup prompt when a file cannot be accessed during scanning
- **Attention modal** — post-scan vulnerability summary

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   React Frontend                     │
│  (Vite + React, served as static files from wwwroot) │
└──────────────────────┬──────────────────────────────┘
                       │ REST API
┌──────────────────────▼──────────────────────────────┐
│               ASP.NET Core Host                      │
│  Controllers · Middleware · Razor Pages               │
├──────────────────────────────────────────────────────┤
│            Application Services Layer                │
│  SecurityOrchestrator · DashboardService             │
│  RealtimeProtectionService · ScanReportService       │
│  AgentControlPlaneService · ComplianceService        │
├──────────────────────────────────────────────────────┤
│            Infrastructure Layer                      │
│  ┌─────────────────┐  ┌────────────────────────────┐ │
│  │   Persistence    │  │     Security Engine         │ │
│  │  SQL Server      │  │  StaticFileScanner          │ │
│  │  Multi-tenant    │  │  BehaviorMonitor            │ │
│  │  Schema bootstrap│  │  ReputationClient           │ │
│  └─────────────────┘  │  HeuristicAnalyzer          │ │
│                        │  YARA · ClamAV engines      │ │
│                        │  SandboxSubmissionClient     │ │
│                        │  RemediationCoordinator      │ │
│                        │  SignaturePackCompiler       │ │
│                        │  NativeEngineDaemonClient    │ │
│                        └────────────────────────────┘ │
├──────────────────────────────────────────────────────┤
│                  Domain Layer                        │
│  ScanJob · ThreatDetection · FileSecurityEvent       │
│  DeviceHealthSnapshot · SecurityIncident             │
└──────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | .NET 10, C# 14 |
| Frontend | React, Vite |
| Database | SQL Server / SQL Server Express |
| Scan Engines | Proprietary static + heuristic, YARA, ClamAV |
| Native Engine | C++ daemon with named-pipe/Unix-socket transport |
| Publish | Self-contained single-file executable (win-x64) |

---

## Getting Started

### Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [Node.js](https://nodejs.org/) (LTS) — for building the React frontend
- [SQL Server Express](https://www.microsoft.com/en-us/sql-server/sql-server-downloads) (free) — or SQL Server LocalDB for development

### Clone

```bash
git clone https://github.com/DhruvGoyal745/SentinalShieldAntivirus.git
cd SentinalShieldAntivirus
```

### Run in Development

```bash
cd ClientApp
npm install
npm run build
cd ..
dotnet run
```

The app starts on `https://localhost:5001` and opens in your default browser automatically.

### Configuration

Edit `appsettings.json` to point to your SQL Server instance:

```json
{
  "ConnectionStrings": {
    "PlatformDb": "Server=.\\SQLEXPRESS;Integrated Security=true;TrustServerCertificate=true;Initial Catalog=SentinelShieldDb"
  }
}
```

For development with LocalDB, the override in `appsettings.Development.json` is used automatically:

```json
{
  "ConnectionStrings": {
    "PlatformDb": "Server=(localdb)\\MSSQLLocalDB;Integrated Security=true;TrustServerCertificate=true;Initial Catalog=SentinelShieldDb"
  }
}
```

The database and schema are **created automatically** on first run.

---

## Publish as Standalone Executable

Build a single self-contained `.exe` that requires no .NET runtime on the target machine:

```bash
dotnet publish -c Release -r win-x64 --self-contained
```

Output: `bin\publish\win-x64\SentinelShieldAntivirus.exe` (~51 MB)

The exe is also **auto-generated on every build** — no separate publish step needed.

### What's in the Publish Folder

| File | Purpose |
|------|---------|
| `SentinelShieldAntivirus.exe` | Self-contained executable |
| `appsettings.json` | Runtime configuration |
| `Database\*.sql` | Schema files (auto-applied on startup) |
| `Rules\Yara\*.yar` | YARA signature rules |
| `wwwroot\` | React frontend (bundled by Vite) |

### Running on Another Machine

1. Copy the entire `win-x64` folder to the target machine
2. Install **SQL Server Express** (free)
3. Edit `appsettings.json` if the SQL instance name differs
4. Double-click `SentinelShieldAntivirus.exe` — the browser opens automatically
5. Run as **Administrator** for real-time file watcher access to protected directories

---

## Project Structure

```
Antivirus/
├── Application/
│   ├── Contracts/          # Interfaces (ISecurityRepository, ISecurityOrchestrator, ...)
│   └── Services/           # SecurityOrchestrator, DashboardService, ...
├── ClientApp/
│   └── src/
│       ├── components/     # Ribbon, SkippedFileModal, AttentionModal, ...
│       ├── pages/          # HomePage, DetectionsPage, TelemetryPage, ...
│       ├── ui/             # Constants, presentation helpers
│       ├── App.jsx
│       └── api.js          # REST API client
├── Configuration/          # AntivirusPlatformOptions
├── Controllers/            # REST API endpoints
├── Database/               # SQL schema scripts
├── Domain/                 # Enums, models (ScanJob, ThreatDetection, ...)
├── Infrastructure/
│   ├── Persistence/        # SqlSecurityRepository, DatabaseBootstrapper, ...
│   └── Security/
│       ├── Rules/          # Heuristic rules (double extension, startup script, ...)
│       ├── StaticAnalysis/ # PE, ELF, document, archive enrichers
│       └── ...             # Engine daemon, YARA, ClamAV, behavior monitor, ...
├── Middleware/              # Tenant resolution, exception handling, logging
├── NativeEngine/           # C++ engine daemon source
├── Pages/                  # Razor Pages (Error, Privacy, Index)
├── Rules/Yara/             # YARA rule files
├── Tools/                  # YARA and ClamAV binaries
├── Program.cs              # Application entry point
└── Antivirus.csproj        # Project file with publish configuration
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard` | Dashboard summary |
| GET | `/api/scans` | Recent scan history |
| POST | `/api/scans` | Start a new scan |
| POST | `/api/scans/{id}/stop` | Stop a running scan |
| GET | `/api/scans/{id}/progress` | Scan progress events |
| GET | `/api/threats` | Threat detections |
| POST | `/api/threats/{id}/quarantine` | Quarantine a threat |
| GET | `/api/fileevents` | Real-time file events |
| GET | `/api/health/status` | Device health snapshot |
| GET | `/api/controlplane/summary` | Enterprise control plane summary |
| GET | `/api/controlplane/tenants` | Tenant list |
| GET | `/api/controlplane/compliance` | Compliance reports |
| POST | `/api/controlplane/compliance/capture` | Capture compliance snapshot |
| POST | `/api/controlplane/incidents/{id}/resolve` | Resolve an incident |
| GET | `/api/governance/parity` | Legacy parity snapshots |
| GET | `/api/governance/sandbox` | Sandbox submissions |
| GET | `/api/governance/reviews` | False-positive reviews |
| POST | `/api/governance/reviews` | Submit a review |
| POST | `/api/agent/register` | Register an agent |
| POST | `/api/agent/heartbeat` | Agent heartbeat |
| GET | `/api/agent/policy` | Agent policy bundle |
| GET | `/api/agent/pack` | Signature pack manifest |
| GET | `/api/reports/scans/exports` | Scan export history |
| GET | `/api/reports/scans/export` | Export all scans to Excel |
| GET | `/api/reports/scans/{id}/export` | Export a single scan to Excel |

---

## License

This project is provided as-is for educational and portfolio purposes.
