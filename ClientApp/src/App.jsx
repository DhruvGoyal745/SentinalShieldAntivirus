import { startTransition, useEffect, useEffectEvent, useState } from "react";
import { api, setTenantKey } from "./api";
import Ribbon from "./components/Ribbon";
import SkippedFileModal from "./components/SkippedFileModal";
import AttentionModal from "./components/AttentionModal";
import HomePage from "./pages/HomePage";
import IncidentsPage from "./pages/IncidentsPage";
import DetectionsPage from "./pages/DetectionsPage";
import TelemetryPage from "./pages/TelemetryPage";
import FleetPage from "./pages/FleetPage";
import GovernancePage from "./pages/GovernancePage";
import ReportsPage from "./pages/ReportsPage";
import { liveScanStatuses, pageDefinitions, scanPipelineSteps, scanStageOrder } from "./ui/constants";
import { buildAgentPayload, buildHeartbeatPayload } from "./ui/agentPayloads";
import {
  deriveScanProgress,
  getInitialPage,
  getLatestScanProgress,
  getSkippedEventKey,
  mergeScanWithProgress
} from "./ui/presentation";

export default function App() {
  const [controlPlane, setControlPlane] = useState(null);
  const [tenants, setTenants] = useState([]);
  const [threats, setThreats] = useState([]);
  const [scans, setScans] = useState([]);
  const [scanExports, setScanExports] = useState([]);
  const [fileEvents, setFileEvents] = useState([]);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [stoppingScanId, setStoppingScanId] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [detectionQuery, setDetectionQuery] = useState("");
  const [telemetryQuery, setTelemetryQuery] = useState("");
  const [analysisClock, setAnalysisClock] = useState(() => Date.now());
  const [focusedScanId, setFocusedScanId] = useState(null);
  const [scanProgressEvents, setScanProgressEvents] = useState([]);
  const [handledSkippedEventKeys, setHandledSkippedEventKeys] = useState([]);
  const [handledAttentionScanIds, setHandledAttentionScanIds] = useState([]);
  const [dismissedAttentionScanId, setDismissedAttentionScanId] = useState(null);
  const [skipPrompt, setSkipPrompt] = useState(null);
  const [attentionPrompt, setAttentionPrompt] = useState(null);
  const [retryingSkippedFile, setRetryingSkippedFile] = useState(false);
  const [currentPage, setCurrentPage] = useState(getInitialPage);
  const [selectedTenant, setSelectedTenant] = useState(window.localStorage.getItem("sentinel-tenant-key") ?? "sentinel-demo");
  const [scanRequest, setScanRequest] = useState({
    mode: "Quick",
    targetPath: "",
    requestedBy: "enterprise-operator",
    runHeuristics: true
  });

  async function syncAgentLifecycle(currentControlPlane = null) {
    await api.registerAgent(buildAgentPayload());
    await api.heartbeat(buildHeartbeatPayload(currentControlPlane));
  }

  const loadData = useEffectEvent(async ({ syncLifecycle = false, preserveMessage = false } = {}) => {
    setLoading(true);
    setError("");

    try {
      if (syncLifecycle) {
        await syncAgentLifecycle(controlPlane);
      }

      const [controlPlaneResult, tenantsResult, threatsResult, scansResult, scanExportsResult, fileEventsResult, healthResult] = await Promise.all([
        api.getControlPlaneSummary(),
        api.getTenants(),
        api.getThreats(),
        api.getScans(),
        api.getScanExports(),
        api.getFileEvents(),
        api.getHealth()
      ]);

      startTransition(() => {
        setControlPlane(controlPlaneResult);
        setTenants(tenantsResult);
        setThreats(threatsResult);
        setScans(scansResult);
        setScanExports(scanExportsResult);
        setFileEvents(fileEventsResult);
        setHealth(healthResult);
        if (!preserveMessage) {
          setMessage("");
        }
      });
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  });

  useEffect(() => {
    const onHashChange = () => setCurrentPage(getInitialPage());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    setTenantKey(selectedTenant);
    setFocusedScanId(null);
    setScanProgressEvents([]);
    setHandledSkippedEventKeys([]);
    setHandledAttentionScanIds([]);
    setDismissedAttentionScanId(null);
    setSkipPrompt(null);
    setAttentionPrompt(null);
    loadData({ syncLifecycle: true });
  }, [selectedTenant]);

  const trackedScan = focusedScanId ? scans.find((scan) => scan.id === focusedScanId) ?? null : null;
  const activeScanBase = trackedScan ?? scans.find((scan) => liveScanStatuses.has(scan.status)) ?? scans[0] ?? null;
  const latestScanProgress = getLatestScanProgress(scanProgressEvents);
  const activeScan = mergeScanWithProgress(activeScanBase, latestScanProgress);
  const hasLiveScan = activeScan ? liveScanStatuses.has(activeScan.status) : false;
  const hasRunningScan = activeScan?.status === "Running";
  const analysisProgress = deriveScanProgress(activeScan, analysisClock);
  const effectiveStage = activeScan?.stage === "Cancelled"
    ? latestScanProgress?.stage ?? "Queued"
    : activeScan?.stage ?? "Queued";
  const activeStageIndex = scanStageOrder.get(effectiveStage) ?? 0;

  const analysisSteps = scanPipelineSteps.map((step, index) => {
    if (!activeScan) {
      return { ...step, state: "upcoming" };
    }

    if (activeScan.status === "Completed" || activeScan.stage === "Completed") {
      return { ...step, state: "complete" };
    }

    if (activeScan.status === "Failed" || activeScan.status === "Cancelled") {
      return {
        ...step,
        state: index < activeStageIndex ? "complete" : index === activeStageIndex ? "failed" : "upcoming"
      };
    }

    if (index < activeStageIndex) {
      return { ...step, state: "complete" };
    }

    if (index === activeStageIndex) {
      return { ...step, state: "current" };
    }

    return { ...step, state: "upcoming" };
  });

  const threatsForActiveScan = activeScan?.id
    ? threats.filter((threat) =>
        threat.scanJobId === activeScan.id)
    : [];

  useEffect(() => {
    let ignore = false;

    async function loadProgress() {
      if (!activeScanBase) {
        setScanProgressEvents([]);
        return;
      }

      try {
        const progress = await api.getScanProgress(activeScanBase.id);
        if (!ignore) {
          startTransition(() => {
            setScanProgressEvents(Array.isArray(progress) ? progress : []);
          });
        }
      } catch {
        if (!ignore) {
          setScanProgressEvents([]);
        }
      }
    }

    loadProgress();
    const intervalId = window.setInterval(loadProgress, hasLiveScan ? 2000 : 10000);

    return () => {
      ignore = true;
      window.clearInterval(intervalId);
    };
  }, [selectedTenant, activeScanBase?.id, hasLiveScan]);

  useEffect(() => {
    const nextSkippedEvent = [...scanProgressEvents]
      .reverse()
      .find((progressEvent) => progressEvent.isSkipped && !handledSkippedEventKeys.includes(getSkippedEventKey(progressEvent)));

    if (nextSkippedEvent) {
      setSkipPrompt(nextSkippedEvent);
    }
  }, [scanProgressEvents, handledSkippedEventKeys]);

  useEffect(() => {
    if (!activeScan || activeScan.status !== "Completed") {
      return;
    }

    if (handledAttentionScanIds.includes(activeScan.id)) {
      return;
    }

    if (dismissedAttentionScanId === activeScan.id) {
      return;
    }

    setAttentionPrompt({
      scan: activeScan,
      vulnerabilities: threatsForActiveScan
    });
  }, [activeScan, threatsForActiveScan, handledAttentionScanIds, dismissedAttentionScanId]);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      loadData({ syncLifecycle: false, preserveMessage: true });
    }, hasLiveScan ? 2000 : 10000);

    return () => window.clearInterval(intervalId);
  }, [selectedTenant, hasLiveScan]);

  useEffect(() => {
    if (!activeScan || !hasRunningScan) {
      return undefined;
    }

    const intervalId = window.setInterval(() => setAnalysisClock(Date.now()), 1000);
    return () => window.clearInterval(intervalId);
  }, [activeScan?.id, hasRunningScan]);

  async function handleScanSubmit(event) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    setMessage("");

    try {
      const createdScan = await api.startScan(scanRequest);
      setFocusedScanId(createdScan.id);
      setAnalysisClock(Date.now());
      await loadData({ syncLifecycle: false, preserveMessage: true });
      setMessage(`Enterprise scan #${createdScan.id} is live. Watch the analysis bar on the home page for realtime progress.`);
    } catch (submitError) {
      setError(submitError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleStopScan(scanId) {
    setStoppingScanId(scanId);
    setError("");
    setMessage("");

    try {
      const result = await api.stopScan(scanId);
      setMessage(result.message);
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (stopError) {
      setError(stopError.message);
    } finally {
      setStoppingScanId(null);
    }
  }

  function dismissSkippedPrompt() {
    if (!skipPrompt) {
      return;
    }

    const key = getSkippedEventKey(skipPrompt);
    setHandledSkippedEventKeys((current) => (current.includes(key) ? current : [...current, key]));
    setSkipPrompt(null);
  }

  function dismissAttentionPrompt(scanId = attentionPrompt?.scan?.id) {
    if (!scanId) {
      setAttentionPrompt(null);
      return;
    }

    setDismissedAttentionScanId(scanId);
    setHandledAttentionScanIds((current) => (current.includes(scanId) ? current : [...current, scanId]));
    setAttentionPrompt(null);
  }

  async function handleRetrySkippedFile() {
    if (!skipPrompt?.currentPath) {
      dismissSkippedPrompt();
      return;
    }

    setRetryingSkippedFile(true);
    setError("");
    setMessage("");

    try {
      const createdScan = await api.startScan({
        mode: "Custom",
        targetPath: skipPrompt.currentPath,
        requestedBy: activeScan?.requestedBy ?? scanRequest.requestedBy ?? "enterprise-operator",
        runHeuristics: true
      });
      setFocusedScanId(createdScan.id);
      setAnalysisClock(Date.now());
      setMessage(`Retry scan #${createdScan.id} started for skipped file ${skipPrompt.currentPath}.`);
      dismissSkippedPrompt();
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (retryError) {
      setError(retryError.message);
    } finally {
      setRetryingSkippedFile(false);
    }
  }

  async function handleQuarantine(id) {
    setError("");
    setMessage("");

    try {
      const result = await api.quarantineThreat(id);
      setMessage(result.message);
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (quarantineError) {
      setError(quarantineError.message);
    }
  }

  async function handleReview(threat) {
    setError("");
    setMessage("");

    try {
      await api.submitReview({
        threatDetectionId: threat.id,
        artifactHash: "pending-artifact-hash",
        ruleId: threat.name,
        scope: "TenantPolicy",
        analyst: "analyst-console",
        notes: `Submitted from enterprise dashboard for ${threat.resource ?? threat.name}.`
      });
      setMessage("False-positive review submitted into governance workflow.");
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (reviewError) {
      setError(reviewError.message);
    }
  }

  async function handleCaptureCompliance() {
    setError("");
    setMessage("");

    try {
      await api.captureCompliance();
      setMessage("Compliance posture snapshot captured.");
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (captureError) {
      setError(captureError.message);
    }
  }

  async function handleResolveIncident(id) {
    setError("");
    setMessage("");

    try {
      await api.resolveIncident(id);
      setMessage(`Incident #${id} marked as resolved.`);
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (resolveError) {
      setError(resolveError.message);
    }
  }

  async function handleExportAllScans() {
    setError("");
    setMessage("");

    try {
      const file = await api.exportAllScans();
      triggerDownload(file);
      setMessage(`Exported Excel report ${file.fileName}.`);
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (exportError) {
      setError(exportError.message);
    }
  }

  async function handleExportScan(scanId) {
    setError("");
    setMessage("");

    try {
      const file = await api.exportScan(scanId);
      triggerDownload(file);
      setMessage(`Exported Excel report for scan #${scanId}.`);
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (exportError) {
      setError(exportError.message);
    }
  }

  function triggerDownload(file) {
    const url = window.URL.createObjectURL(file.blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = file.fileName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.URL.revokeObjectURL(url);
  }

  const incidents = controlPlane?.incidents ?? [];
  const complianceReports = controlPlane?.complianceReports ?? [];
  const paritySnapshots = controlPlane?.paritySnapshots ?? [];
  const sandboxSubmissions = controlPlane?.sandboxSubmissions ?? [];
  const reviews = controlPlane?.falsePositiveReviews ?? [];
  const fleet = controlPlane?.fleet ?? null;
  const openIncidentCount = fleet?.openIncidentCount ?? incidents.filter((incident) => incident.status !== "Resolved").length;
  const quarantinedThreatCount = threats.filter((threat) => threat.isQuarantined).length;
  const tenantOptions = Array.from(
    new Map(
      [
        { tenantKey: "sentinel-demo", displayName: "Sentinel Demo", databaseName: "sentinel-demo" },
        controlPlane?.tenant,
        ...tenants
      ]
        .filter(Boolean)
        .map((tenant) => [tenant.tenantKey, tenant])
    ).values()
  );

  function handleRibbonNavigation(pageKey) {
    window.location.hash = pageKey;
    setCurrentPage(pageKey);
  }

  function handleFocusScan(scanId) {
    setFocusedScanId(scanId);
    setAnalysisClock(Date.now());
    handleRibbonNavigation("home");
  }

  function handleReviewAttention() {
    const scanId = attentionPrompt?.scan?.id;
    dismissAttentionPrompt(scanId);
    handleRibbonNavigation("detections");
  }

  return (
    <div className="app-shell">
      <div className="ambient ambient-left" />
      <div className="ambient ambient-right" />

      <Ribbon
        pageDefinitions={pageDefinitions}
        currentPage={currentPage}
        onNavigate={handleRibbonNavigation}
        health={health}
        fleet={fleet}
        openIncidentCount={openIncidentCount}
        tenantOptions={tenantOptions}
        selectedTenant={selectedTenant}
        setSelectedTenant={setSelectedTenant}
        onRefresh={() => loadData({ syncLifecycle: true, preserveMessage: true })}
        loading={loading}
      />

      {error ? <div className="banner error">{error}</div> : null}
      {message ? <div className="banner success">{message}</div> : null}

      <SkippedFileModal
        skipPrompt={skipPrompt}
        onDismiss={dismissSkippedPrompt}
        onRetry={handleRetrySkippedFile}
        retryingSkippedFile={retryingSkippedFile}
      />
      <AttentionModal
        scan={attentionPrompt?.scan}
        vulnerabilities={attentionPrompt?.vulnerabilities}
        onDismiss={() => dismissAttentionPrompt()}
        onReview={handleReviewAttention}
      />

      <main className="page-shell">
        {currentPage === "home" ? (
          <HomePage
            scanRequest={scanRequest}
            setScanRequest={setScanRequest}
            submitting={submitting}
            handleScanSubmit={handleScanSubmit}
            handleStopScan={handleStopScan}
            stoppingScanId={stoppingScanId}
            activeScan={activeScan}
            analysisProgress={analysisProgress}
            analysisSteps={analysisSteps}
            incidentsCount={openIncidentCount}
            threatCount={threats.length}
            quarantinedThreatCount={quarantinedThreatCount}
            fleet={fleet}
            health={health}
            onNavigate={handleRibbonNavigation}
          />
        ) : null}

        {currentPage === "incidents" ? (
          <IncidentsPage incidents={incidents} handleResolveIncident={handleResolveIncident} />
        ) : null}

        {currentPage === "detections" ? (
          <DetectionsPage
            threats={threats}
            query={detectionQuery}
            setQuery={setDetectionQuery}
            handleQuarantine={handleQuarantine}
            handleReview={handleReview}
          />
        ) : null}

        {currentPage === "telemetry" ? (
          <TelemetryPage
            fileEvents={fileEvents}
            scans={scans}
            telemetryQuery={telemetryQuery}
            setTelemetryQuery={setTelemetryQuery}
            onFocusScan={handleFocusScan}
            onExportScan={handleExportScan}
            onStopScan={handleStopScan}
            stoppingScanId={stoppingScanId}
            analysisClock={analysisClock}
          />
        ) : null}

        {currentPage === "fleet" ? <FleetPage controlPlane={controlPlane} health={health} /> : null}

        {currentPage === "governance" ? (
          <GovernancePage
            paritySnapshots={paritySnapshots}
            sandboxSubmissions={sandboxSubmissions}
            reviews={reviews}
          />
        ) : null}

        {currentPage === "reports" ? (
          <ReportsPage
            scanExports={scanExports}
            complianceReports={complianceReports}
            handleCaptureCompliance={handleCaptureCompliance}
            handleExportAllScans={handleExportAllScans}
          />
        ) : null}
      </main>
    </div>
  );
}
