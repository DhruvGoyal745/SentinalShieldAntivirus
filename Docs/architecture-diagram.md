# Sentinel Shield Antivirus — Complete Architecture

## High-Level System Overview

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           SENTINEL SHIELD PLATFORM                               │
│                                                                                  │
│  ┌─────────────────────┐  ┌──────────────────────┐  ┌────────────────────────┐  │
│  │  SentinelShield.Tray │  │ SentinelShield.Desktop│  │  React SPA (Browser)  │  │
│  │  (System Tray App)   │  │ (WPF Dashboard)       │  │  (ClientApp)          │  │
│  │  .NET 10 WinForms    │  │ .NET 10 WPF           │  │  Vite + React 19      │  │
│  └──────────┬──────────┘  └──────────┬───────────┘  └──────────┬─────────────┘  │
│             │                        │                          │                │
│             │  HTTP localhost:5000    │  Embedded host           │  HTTP /api/*   │
│             ▼                        ▼                          ▼                │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │                    ASP.NET Core 10 Razor Pages Host                      │    │
│  │                    (Antivirus.csproj — Program.cs)                       │    │
│  │  ┌──────────────────────────────────────────────────────────────────┐    │    │
│  │  │                      Middleware Pipeline                         │    │    │
│  │  │  TenantResolution → ExceptionHandling → RequestLogging          │    │    │
│  │  └──────────────────────────────────────────────────────────────────┘    │    │
│  │                              │                                           │    │
│  │  ┌───────────────────────────┴──────────────────────────────────────┐    │    │
│  │  │                       API Controllers                            │    │    │
│  │  │  Scans │ Threats │ FileEvents │ Health │ Dashboard │ Engine      │    │    │
│  │  │  ControlPlane │ Agents │ Governance │ Reports │ ServiceControl   │    │    │
│  │  └───────────────────────────┬──────────────────────────────────────┘    │    │
│  │                              │                                           │    │
│  │  ┌───────────────────────────┴──────────────────────────────────────┐    │    │
│  │  │                    Application Layer                             │    │    │
│  │  │  SecurityOrchestrator │ DashboardService │ ScanReportService     │    │    │
│  │  │  AgentControlPlaneService │ ComplianceService                    │    │    │
│  │  │  EnterpriseDashboardService │ SentinelShieldControlService       │    │    │
│  │  └───────────────────────────┬──────────────────────────────────────┘    │    │
│  │                              │                                           │    │
│  │  ┌───────────────────────────┴──────────────────────────────────────┐    │    │
│  │  │                   Infrastructure Layer                           │    │    │
│  │  │                                                                  │    │    │
│  │  │  SECURITY          │  PERSISTENCE        │  RUNTIME              │    │    │
│  │  │  (Scan Engines,    │  (SQL Server,        │  (File Paths,         │    │    │
│  │  │   File Watchers,   │   Repositories)      │   OS Detection)       │    │    │
│  │  │   Analysis)        │                      │                       │    │    │
│  │  └───────────────────────────┬──────────────────────────────────────┘    │    │
│  │                              │                                           │    │
│  │  ┌───────────────────────────┴──────────────────────────────────────┐    │    │
│  │  │                      Domain Layer                                │    │    │
│  │  │  SecurityModels │ EnterpriseModels │ ValueObjects                │    │    │
│  │  └──────────────────────────────────────────────────────────────────┘    │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
│                              │                                                   │
│                              ▼                                                   │
│                    ┌────────────────────┐                                        │
│                    │   SQL Server DB    │                                        │
│                    │   (Per-Tenant)     │                                        │
│                    └────────────────────┘                                        │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer-by-Layer Breakdown

### 1. Presentation Layer (3 Clients)

```
┌──────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                             │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ System Tray App  │  │ WPF Desktop  │  │  React SPA         │ │
│  │                  │  │              │  │                    │ │
│  │ TrayApplication  │  │ MainWindow   │  │ App.jsx            │ │
│  │ Context.cs       │  │ .xaml.cs     │  │ ├─ pages/          │ │
│  │ ServiceApiClient │  │ Dashboard    │  │ │  HomePage        │ │
│  │ DesktopLauncher  │  │ Client.cs    │  │ │  DetectionsPage  │ │
│  │                  │  │ Embedded     │  │ │  IncidentsPage   │ │
│  │ Features:        │  │ ServiceHost  │  │ │  TelemetryPage   │ │
│  │ • Quick scan     │  │ SingleInst.  │  │ │  FleetPage       │ │
│  │ • Pause/resume   │  │ Coordinator  │  │ │  GovernancePage  │ │
│  │ • Status icon    │  │ NativeMethods│  │ │  ReportsPage     │ │
│  │ • Open dashboard │  │              │  │ ├─ components/     │ │
│  │                  │  │ Features:    │  │ │  PageHeader      │ │
│  │                  │  │ • Embedded   │  │ │  ScanSelector    │ │
│  │                  │  │   ASP.NET    │  │ │  SkippedFileModal│ │
│  │                  │  │   host       │  │ │  AttentionModal  │ │
│  │                  │  │ • WebView2   │  │ │  States          │ │
│  │                  │  │   browser    │  │ ├─ api.js          │ │
│  │                  │  │ • Native     │  │ ├─ state/          │ │
│  │                  │  │   win32      │  │ │  useDashboardStore│
│  │                  │  │   interop    │  │ └─ ui/             │ │
│  │                  │  │              │  │    constants       │ │
│  │                  │  │              │  │    presentation    │ │
│  └──────────────────┘  └──────────────┘  └────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 2. API Layer (Controllers)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         API CONTROLLERS                                  │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ ScansCtrl    │  │ ThreatsCtrl  │  │ FileEventsCtrl│ │ HealthCtrl  │ │
│  │              │  │              │  │              │  │             │ │
│  │ GET  /scans  │  │ GET  /threats│  │ GET /fileevents│ │ GET /status │ │
│  │ POST /scans  │  │ POST /:id/  │  │              │  │             │ │
│  │ POST /:id/   │  │  quarantine │  └──────────────┘  └─────────────┘ │
│  │  stop        │  │ POST /:id/  │                                     │
│  │ POST /:id/   │  │  review     │  ┌──────────────┐  ┌─────────────┐ │
│  │  file-decision│ │              │  │ DashboardCtrl│  │ EngineCtrl  │ │
│  │ GET /:id/    │  └──────────────┘  │              │  │             │ │
│  │  progress    │                     │ GET /dashboard│ │GET /status  │ │
│  └──────────────┘  ┌──────────────┐  └──────────────┘  │POST /reload │ │
│                     │ControlPlane │                     └─────────────┘ │
│  ┌──────────────┐  │              │  ┌──────────────┐  ┌─────────────┐ │
│  │ GovernanceCtrl│ │GET /summary  │  │ ReportsCtrl  │  │ServiceCtrl  │ │
│  │              │  │GET /tenants  │  │              │  │             │ │
│  │GET /parity   │  │GET /fleet    │  │GET /exports  │  │GET /status  │ │
│  │GET /sandbox  │  └──────────────┘  │POST /exports │  │POST /scan   │ │
│  │GET /reviews  │                     └──────────────┘  │POST /pause  │ │
│  │POST /reviews │  ┌──────────────┐                     │POST /resume │ │
│  │POST decision │  │ AgentsCtrl   │                     │POST /update │ │
│  └──────────────┘  │              │                     └─────────────┘ │
│                     │POST /register│                                     │
│                     │POST /heartbeat│                                    │
│                     └──────────────┘                                     │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3. Application Layer (Services & Orchestration)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       APPLICATION LAYER                                  │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                  SecurityOrchestrator                            │    │
│  │  Central coordinator for all scan operations                    │    │
│  │  • QueueScanAsync → enqueue to background queue                 │    │
│  │  • ExecuteQueuedScanAsync → drive engine daemon client          │    │
│  │  • StopScanAsync → cancel via ScanCancellationRegistry          │    │
│  │  • SubmitFileDecisionAsync → skip/retry via decision registry   │    │
│  │  • SyncThreatsAsync → merge engine detections to DB             │    │
│  │  • QuarantineThreatAsync → move file + update DB                │    │
│  │  • CaptureHealthAsync → snapshot device health state            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────┐  ┌───────────────────┐  ┌─────────────────────┐  │
│  │ DashboardService │  │ ScanReportService  │  │ ComplianceService   │  │
│  │                  │  │                   │  │                     │  │
│  │ Aggregates:      │  │ Generates:        │  │ Captures:           │  │
│  │ • Health snapshot│  │ • JSON exports    │  │ • Compliance        │  │
│  │ • Recent scans   │  │ • CSV exports     │  │   posture reports   │  │
│  │ • Active threats │  │ • PDF reports     │  │                     │  │
│  │ • File events    │  │                   │  │                     │  │
│  │ • Unique counts  │  │                   │  │                     │  │
│  └──────────────────┘  └───────────────────┘  └─────────────────────┘  │
│                                                                          │
│  ┌──────────────────────┐  ┌──────────────────────────────────────────┐ │
│  │AgentControlPlaneService│ │SentinelShieldControlService              │ │
│  │                      │  │                                          │ │
│  │ • Register device    │  │ • Pause/resume realtime protection       │ │
│  │ • Process heartbeat  │  │ • Start quick scan from tray/desktop     │ │
│  │ • Return policy      │  │ • Check for signature updates            │ │
│  └──────────────────────┘  └──────────────────────────────────────────┘ │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                  Contracts (Interfaces)                            │  │
│  │  ISecurityRepository │ IControlPlaneRepository │ ITenantRegistry   │  │
│  │  ISecurityOrchestrator │ IDashboardService │ IComplianceService    │  │
│  │  IRealtimeProtectionService │ IEngineDaemonClient                  │  │
│  │  IProprietaryProtectionEngine │ ISignaturePackProvider              │  │
│  │  IStaticFileScanner │ IBehaviorMonitor │ IReputationClient         │  │
│  │  ISandboxSubmissionClient │ IRemediationCoordinator                │  │
│  │  IOpenSourceScannerEngine │ IHeuristicAnalyzer │ IHeuristicRule    │  │
│  │  IScanBackgroundQueue │ IScanCancellationRegistry                  │  │
│  │  IScanFileDecisionRegistry │ IFileEventBackgroundQueue             │  │
│  │  IWindowsDefenderClient │ IPowerShellRunner │ IProcessCommandRunner│  │
│  │  ISentinelShieldControlApi │ ISignaturePackCompiler                │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### 4. Infrastructure Layer

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      INFRASTRUCTURE LAYER                                │
│                                                                          │
│  ═══════════════ SECURITY (Scan Engines & Analysis) ═══════════════     │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │              Scan Engine Daemon Clients                          │    │
│  │  ┌────────────────────────┐  ┌───────────────────────────────┐  │    │
│  │  │ ManagedEngineDaemonClient│ │NativePreferredEngineDaemonClient│ │   │
│  │  │ (Pure .NET engine)     │  │(Delegates to native if avail.)│  │    │
│  │  │ • Drives full scan     │  │• Falls back to managed engine │  │    │
│  │  │   pipeline per file    │  │                               │  │    │
│  │  │ • Parallel scanning    │  └───────────────────────────────┘  │    │
│  │  │ • Skip/retry decisions │                                     │    │
│  │  │ • Progress reporting   │                                     │    │
│  │  └────────────────────────┘                                     │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │           Proprietary Protection Engine (Pipeline)              │    │
│  │                                                                 │    │
│  │  File In → Static Scan → Behavior Analysis → Reputation Check  │    │
│  │         → Sandbox (if needed) → Verdict → Quarantine (if bad)  │    │
│  │                                                                 │    │
│  │  ┌──────────────────┐  ┌────────────────┐  ┌────────────────┐  │    │
│  │  │ProprietaryStatic │  │BehaviorMonitor │  │ReputationClient│  │    │
│  │  │FileScanner       │  │                │  │                │  │    │
│  │  │• SHA-256 hash    │  │• File event    │  │• Hash lookup   │  │    │
│  │  │  matching        │  │  analysis      │  │• Cloud rep.    │  │    │
│  │  │• Signature rules │  │• Suspicious    │  │  check         │  │    │
│  │  │• Static artifact │  │  patterns      │  └────────────────┘  │    │
│  │  │  enrichment      │  └────────────────┘                       │    │
│  │  └──────────────────┘                                           │    │
│  │                                                                 │    │
│  │  ┌──────────────────┐  ┌────────────────┐  ┌────────────────┐  │    │
│  │  │SandboxSubmission │  │Remediation     │  │HeuristicAnalyzer│ │    │
│  │  │Client            │  │Coordinator     │  │                │  │    │
│  │  │• Detonation      │  │• Quarantine    │  │• Pattern rules │  │    │
│  │  │• Behavior capture│  │  file moves    │  │• Double ext.   │  │    │
│  │  │• Verdict merge   │  │• Path mgmt     │  │• Startup script│  │    │
│  │  └──────────────────┘  └────────────────┘  │• Suspicious ext│  │    │
│  │                                             └────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │          Static Analysis Enrichment Pipeline                    │    │
│  │                                                                 │    │
│  │  ┌─────────────────┐ ┌──────────────────┐ ┌──────────────────┐ │    │
│  │  │PortableExecutable│ │AuthenticodeVerif.│ │ContentHeuristic  │ │    │
│  │  │MetadataEnricher  │ │Enricher          │ │Enricher          │ │    │
│  │  └─────────────────┘ └──────────────────┘ └──────────────────┘ │    │
│  │  ┌─────────────────┐ ┌──────────────────┐ ┌──────────────────┐ │    │
│  │  │ArchiveMetadata  │ │DocumentMetadata  │ │ElfMetadata       │ │    │
│  │  │Enricher         │ │Enricher          │ │Enricher          │ │    │
│  │  └─────────────────┘ └──────────────────┘ └──────────────────┘ │    │
│  │  ┌─────────────────┐ ┌──────────────────┐                      │    │
│  │  │SuspiciousString │ │StaticRuleEvaluator│                     │    │
│  │  │Extraction       │ │(orchestrates all) │                     │    │
│  │  └─────────────────┘ └──────────────────┘                      │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │             Open-Source Scanner Engines (Shadow Mode)            │    │
│  │                                                                 │    │
│  │  ┌────────────────┐ ┌───────────────────┐ ┌──────────────────┐ │    │
│  │  │ClamAvScanner   │ │YaraScanner        │ │PatternRuleScanner│ │    │
│  │  │Engine          │ │Engine             │ │Engine            │ │    │
│  │  │• clamscan CLI  │ │• yara CLI         │ │• SignatureHash   │ │    │
│  │  │  integration   │ │  integration      │ │  Scanner         │ │    │
│  │  └────────────────┘ └───────────────────┘ └──────────────────┘ │    │
│  │  Run in shadow mode for legacy parity comparison                │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │           Signature Pack System                                 │    │
│  │  ┌────────────────────┐  ┌──────────────────────────────────┐  │    │
│  │  │SignaturePackProvider│  │SignaturePackCompiler              │  │    │
│  │  │• Fetches manifest  │  │• Compiles rules from definitions │  │    │
│  │  │  + rules from DB   │  │  into ProprietarySignaturePack   │  │    │
│  │  └────────────────────┘  └──────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │          Background Services (Hosted Services)                  │    │
│  │                                                                 │    │
│  │  ┌─────────────────────┐  ┌──────────────────────────────────┐ │    │
│  │  │ScanProcessing       │  │FileEventProcessing               │ │    │
│  │  │HostedService        │  │HostedService                     │ │    │
│  │  │• Dequeue scan jobs  │  │• Dequeue file watch events       │ │    │
│  │  │• Reconcile orphaned │  │• Route to RealtimeProtection     │ │    │
│  │  │  scans on restart   │  │  Service                         │ │    │
│  │  └─────────────────────┘  └──────────────────────────────────┘ │    │
│  │  ┌─────────────────────┐  ┌──────────────────────────────────┐ │    │
│  │  │FileWatcher          │  │RealtimeProtection                │ │    │
│  │  │HostedService        │  │Service                           │ │    │
│  │  │• FileSystemWatcher  │  │• Scan queued file events         │ │    │
│  │  │  on configured roots│  │• Run proprietary + shadow engines│ │    │
│  │  │• Emits FileWatch    │  │• Save legacy parity snapshots    │ │    │
│  │  │  Notifications      │  │• Create threats + incidents      │ │    │
│  │  └─────────────────────┘  └──────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │          Concurrency & State Registries                         │    │
│  │                                                                 │    │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │    │
│  │  │ScanBackground    │  │ScanCancellation  │  │ScanFileDecision│ │    │
│  │  │Queue             │  │Registry          │  │Registry       │  │    │
│  │  │(Channel<T>)      │  │(CancellationToken│  │(TaskCompletion│  │    │
│  │  │                  │  │ per scan)        │  │ Source<T>)    │  │    │
│  │  └──────────────────┘  └──────────────────┘  └──────────────┘  │    │
│  │  ┌──────────────────┐                                           │    │
│  │  │FileEventBackground│                                          │    │
│  │  │Queue              │                                          │    │
│  │  │(Channel<T>)       │                                          │    │
│  │  └──────────────────┘                                           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ═══════════════ PERSISTENCE (Data Access) ═══════════════════════      │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐    │
│  │SqlSecurity       │  │SqlControlPlane   │  │SqlTenantRegistry   │    │
│  │Repository        │  │Repository        │  │                    │    │
│  │                  │  │                  │  │• Multi-tenant DB   │    │
│  │• ScanJobs        │  │• DeviceProfiles  │  │  routing           │    │
│  │• FileSecurityEvts│  │• SecurityIncidents│ │• Connection pool   │    │
│  │• ThreatDetections│  │• ComplianceReports│ │  per tenant        │    │
│  │• ScanProgressEvts│  │• FalsePositive   │  │• Auto-create DB    │    │
│  │• FileEngineResults│ │  Reviews         │  │  + schema          │    │
│  │• DeviceHealth    │  │• SandboxSubmissions│ │                    │    │
│  │  Snapshots       │  │• LegacyParity    │  │                    │    │
│  │• ScanReportExports│ │  Snapshots       │  │                    │    │
│  │                  │  │• SignaturePacks   │  │                    │    │
│  │                  │  │• SignatureRules   │  │                    │    │
│  │                  │  │• Remediations     │  │                    │    │
│  └──────────────────┘  └──────────────────┘  └────────────────────┘    │
│                                                                          │
│  ═══════════════ RUNTIME ═════════════════════════════════════════      │
│                                                                          │
│  ┌──────────────────────────┐  ┌─────────────────────────────────┐     │
│  │SentinelRuntimePaths      │  │WindowsDefenderClient            │     │
│  │• OS-aware path resolution│  │• PowerShell Get-MpComputerStatus│     │
│  │• Watch roots             │  │• Fallback health source         │     │
│  │• Quarantine directory    │  │                                 │     │
│  │• Signature directory     │  │PowerShellRunner                 │     │
│  └──────────────────────────┘  │ProcessCommandRunner             │     │
│                                 └─────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

### 5. Domain Layer

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          DOMAIN LAYER                                    │
│                                                                          │
│  SecurityModels.cs                                                       │
│  ┌────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│  │ ScanJob        │ │ScanRequest   │ │ThreatDetection│ │FileSecurityEvt│ │
│  │ ScanStatusUpdate│ │ScanProgressEvt│ │FileWatchNotif │ │FileEventUpdate│ │
│  │ ScanControlResult│ │ScanHandle   │ │FileScanContext│ │FileEngineResult│ │
│  │ ScanFileDecision│ │PipelineScan │ │EngineDetection│ │DeviceHealth   │ │
│  │ QuarantineResult│ │Result       │ │QuarantineResult│ │Snapshot       │ │
│  │ DashboardSummary│ │ScanReportExport│ │PendingScanFile│ │LoadSignature │ │
│  │                │ │              │ │Prompt         │ │PackResult     │ │
│  └────────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ │
│                                                                          │
│  EnterpriseModels.cs                                                     │
│  ┌────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│  │DeviceProfile   │ │SecurityIncident│ │ComplianceReport│ │FalsePositive │ │
│  │DevicePolicyBundle│ │AgentRegistration│ │SandboxSubmission│ │Review      │ │
│  │FleetSummary    │ │AgentHeartbeat│ │LegacyParity  │ │Remediation   │ │
│  │TenantSummary   │ │SignaturePack │ │Snapshot       │ │ActionRecord  │ │
│  │EnterpriseDash  │ │Manifest      │ │DetectionEvent │ │SignatureRule  │ │
│  │boardSummary    │ │              │ │Record         │ │Definition     │ │
│  └────────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ │
│                                                                          │
│  ValueObjects.cs                                                         │
│  ┌────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│  │ScanMode (enum) │ │ScanStatus    │ │ScanStage     │ │ThreatSeverity│ │
│  │ThreatSource    │ │FileEventType │ │FileEventStatus│ │PipelineVerdict│ │
│  │IncidentStatus  │ │FileEngine    │ │FalsePositive │ │Remediation   │ │
│  │                │ │ResultStatus  │ │ReviewStatus  │ │Status/Kind   │ │
│  └────────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

### 6. Database Schema (Per-Tenant)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    SQL SERVER (Per-Tenant Database)                       │
│                                                                          │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────────┐ │
│  │ ScanJobs        │  │ FileSecurityEvents│  │ ThreatDetections       │ │
│  │─────────────────│  │──────────────────│  │────────────────────────│ │
│  │ Id (PK)         │  │ Id (PK)          │  │ Id (PK)                │ │
│  │ Mode            │◄─│ ScanJobId (FK)   │  │ ScanJobId (FK)         │ │
│  │ TargetPath      │  │ FilePath         │  │ Name                   │ │
│  │ RequestedBy     │  │ EventType        │  │ Category               │ │
│  │ Status          │  │ Status           │  │ Severity               │ │
│  │ Stage           │  │ HashSha256       │  │ Resource               │ │
│  │ PercentComplete │  │ FileSizeBytes    │  │ IsQuarantined          │ │
│  │ FilesScanned    │  │ ThreatCount      │  │ EvidenceJson           │ │
│  │ ThreatCount     │  │ ObservedAt       │  │ DetectedAt             │ │
│  │ CreatedAt       │  │ ProcessedAt      │  └────────────────────────┘ │
│  │ CompletedAt     │  └────────┬─────────┘                             │
│  └────────┬────────┘           │          ┌────────────────────────┐   │
│           │                    │          │ FileEngineResults      │   │
│  ┌────────┴────────┐          └─────────►│────────────────────────│   │
│  │ScanProgressEvents│                     │ FileSecurityEventId(FK)│   │
│  │─────────────────│                     │ EngineName             │   │
│  │ ScanJobId (FK)  │                     │ Source                 │   │
│  │ Stage           │                     │ Status                 │   │
│  │ PercentComplete │                     │ IsMatch                │   │
│  │ FilesScanned    │                     │ SignatureName          │   │
│  │ IsSkipped       │                     └────────────────────────┘   │
│  │ DetailMessage   │                                                   │
│  │ RecordedAt      │  ┌──────────────────┐  ┌────────────────────┐   │
│  └─────────────────┘  │SecurityIncidents │  │DeviceProfiles      │   │
│                        │──────────────────│  │────────────────────│   │
│  ┌─────────────────┐  │ ScanJobId (FK)   │  │ DeviceId (PK)      │   │
│  │ScanReportExports│  │ DeviceId         │  │ MachineName        │   │
│  │─────────────────│  │ Title            │  │ OsPlatform         │   │
│  │ ScanJobId (FK)  │  │ Severity         │  │ AgentVersion       │   │
│  │ FileName        │  │ Status           │  │ PolicyVersion      │   │
│  │ Format          │  │ RuleId           │  │ SignatureVersion    │   │
│  │ VulnerabilityCount│ │ Confidence       │  │ LastHeartbeat      │   │
│  │ ExportedAt      │  └──────────────────┘  └────────────────────┘   │
│  └─────────────────┘                                                   │
│                        ┌──────────────────┐  ┌────────────────────┐   │
│  ┌─────────────────┐  │FalsePositiveReviews│ │SandboxSubmissions  │   │
│  │DeviceHealth     │  │──────────────────│  │────────────────────│   │
│  │Snapshots        │  │ ThreatId         │  │ ScanJobId (FK)     │   │
│  │─────────────────│  │ Status           │  │ FileName           │   │
│  │ AntivirusEnabled│  │ Analyst          │  │ Verdict            │   │
│  │ RealTimeProt.   │  │ Notes            │  │ BehaviorSummary    │   │
│  │ SignatureVersion│  └──────────────────┘  └────────────────────┘   │
│  │ QuickScanAge   │                                                   │
│  │ FullScanAge    │  ┌──────────────────┐  ┌────────────────────┐   │
│  └─────────────────┘  │LegacyParity     │  │ComplianceReports   │   │
│                        │Snapshots        │  │────────────────────│   │
│  ┌─────────────────┐  │──────────────────│  │ DeviceId           │   │
│  │SignaturePackManifests│ │ MalwareFamily  │  │ PolicyCompliance   │   │
│  │─────────────────│  │ DetectionRecall% │  │ Score              │   │
│  │ Version         │  │ FalsePositive%   │  │ CapturedAt         │   │
│  │ RuleCount       │  └──────────────────┘  └────────────────────┘   │
│  │ Channel         │                                                   │
│  └─────────────────┘  ┌──────────────────┐                            │
│                        │RemediationActions│                            │
│  ┌─────────────────┐  │──────────────────│                            │
│  │SignatureRule     │  │ DeviceId         │                            │
│  │Definitions      │  │ ActionKind       │                            │
│  │─────────────────│  │ Status           │                            │
│  │ RuleId          │  │ RequestedBy      │                            │
│  │ Category        │  │ CompletedAt      │                            │
│  │ Severity        │  └──────────────────┘                            │
│  │ HashPattern     │                                                   │
│  │ IsEnabled       │                                                   │
│  └─────────────────┘                                                   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow: Manual Scan (End-to-End)

```
User clicks "Start Scan"
         │
         ▼
[React SPA] POST /api/scans { mode: "Quick" }
         │
         ▼
[ScansController] → SecurityOrchestrator.QueueScanAsync()
         │
         ├─ 1. SqlSecurityRepository.CreateScanAsync() → INSERT ScanJobs (Status=Pending)
         ├─ 2. ScanBackgroundQueue.QueueAsync()         → Channel<QueuedScanWorkItem>
         └─ 3. Return ScanJob { id: 5, status: "Pending" }
                  │
                  ▼ (background)
[ScanProcessingHostedService] dequeues from Channel
         │
         ▼
SecurityOrchestrator.ExecuteQueuedScanAsync()
         │
         ├─ 1. Update status → Running
         ├─ 2. SignaturePackProvider.GetCompiledPackAsync()
         ├─ 3. EngineDaemonClient.LoadSignaturePackAsync()
         └─ 4. EngineDaemonClient.StartManualScanAsync()
                  │
                  ▼
[ManagedEngineDaemonClient] per file:
         │
         ├─ DiscoverTargets() → walk directories
         │
         └─ For each file (parallel):
              ├─ StaticFileScanner.ScanAsync()        → hash + signature match
              ├─ BehaviorMonitor.AnalyzeAsync()       → heuristic patterns
              ├─ ReputationClient.EvaluateAsync()     → cloud hash lookup
              ├─ SandboxSubmissionClient.SubmitIfNeededAsync()
              ├─ ResolveVerdict() → Clean / Suspicious / Malicious
              ├─ RemediationCoordinator.QuarantineAsync() (if malicious)
              ├─ ControlPlaneRepository.CreateIncidentAsync() (if threat)
              └─ Publish progress via SSE → React SPA updates live
                  │
                  ▼ (file inaccessible?)
         [ScanFileDecisionRegistry] → WaitForDecisionAsync()
                  │                     ▲
                  ▼                     │
         [React SPA] shows             │ POST /api/scans/5/file-decision
         "Skip/Retry" modal ───────────┘
```

## Data Flow: Realtime File Monitoring

```
[FileWatcherHostedService]
   FileSystemWatcher on configured roots
         │
         │ File Created/Changed/Renamed/Deleted
         ▼
RealtimeProtectionService.RegisterFileEventAsync()
         │
         ├─ SqlSecurityRepository.CreateFileEventAsync() → INSERT FileSecurityEvents
         └─ FileEventBackgroundQueue.QueueAsync()
                  │
                  ▼ (background)
[FileEventProcessingHostedService] dequeues
         │
         ▼
RealtimeProtectionService.ProcessQueuedFileEventAsync()
         │
         ├─ ProprietaryProtectionEngine.ScanFileAsync()
         │     ├─ StaticFileScanner → BehaviorMonitor → ReputationClient
         │     ├─ Verdict resolution
         │     └─ Quarantine if malicious
         │
         ├─ (Shadow mode) Open-source engines: ClamAV, YARA, PatternRule
         │     └─ LegacyParitySnapshot saved for comparison
         │
         ├─ SqlSecurityRepository.SaveFileEngineResultsAsync()
         ├─ SqlSecurityRepository.UpsertThreatsAsync()
         └─ SqlSecurityRepository.UpdateFileEventAsync()
```

## Technology Stack Summary

| Layer | Technology |
|---|---|
| **Desktop App** | .NET 10 WPF + WebView2 |
| **System Tray** | .NET 10 WinForms |
| **Web Frontend** | React 19 + Vite 8 + Zustand |
| **Web Backend** | ASP.NET Core 10 Razor Pages |
| **API Style** | REST Controllers |
| **Database** | SQL Server (multi-tenant) |
| **Data Access** | Raw ADO.NET (SqlCommand) |
| **Background Jobs** | `BackgroundService` + `Channel<T>` queues |
| **File Monitoring** | `FileSystemWatcher` |
| **Scan Engines** | Proprietary (.NET) + ClamAV + YARA (CLI) |
| **OS Integration** | PowerShell (Windows Defender), Win32 interop |
| **Logging** | Custom `RollingFileLoggerProvider` |
| **Target OS** | Windows (primary), cross-platform runtime paths |
