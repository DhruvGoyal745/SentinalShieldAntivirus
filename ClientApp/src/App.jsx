import { startTransition, useEffect, useEffectEvent, useRef, useState } from "react";
import { RefreshCcw } from "lucide-react";
import { api, setTenantKey } from "./api";
import AppSidebar from "./components/AppSidebar";
import AttentionModal from "./components/AttentionModal";
import SkippedFileModal from "./components/SkippedFileModal";
import HomePage from "./pages/HomePage";
import IncidentsPage from "./pages/IncidentsPage";
import DetectionsPage from "./pages/DetectionsPage";
import TelemetryPage from "./pages/TelemetryPage";
import FleetPage from "./pages/FleetPage";
import GovernancePage from "./pages/GovernancePage";
import ReportsPage from "./pages/ReportsPage";
import { buildAgentPayload, buildHeartbeatPayload } from "./ui/agentPayloads";
import { liveScanStatuses, pageDefinitions, scanPipelineSteps, scanStageOrder } from "./ui/constants";
import { deriveScanProgress, getInitialPage, getLatestScanProgress, getSkippedEventKey, mergeScanWithProgress } from "./ui/presentation";
import { useDashboardStore } from "./state/useDashboardStore";

export default function App() {
  const [controlPlane, setControlPlane] = useState(null);
  const [tenants, setTenants] = useState([]);
  const [threats, setThreats] = useState([]);
  const [scans, setScans] = useState([]);
  const [scanExports, setScanExports] = useState([]);
  const [fileEvents, setFileEvents] = useState([]);
  const [health, setHealth] = useState(null);
  const [engineStatus, setEngineStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [stoppingScanId, setStoppingScanId] = useState(null);
  const [pendingThreatActionId, setPendingThreatActionId] = useState(null);
  const [pendingReviewId, setPendingReviewId] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [analysisClock, setAnalysisClock] = useState(() => Date.now());
  const [scanProgressEvents, setScanProgressEvents] = useState([]);
  const [handledSkippedEventKeys, setHandledSkippedEventKeys] = useState([]);
  const [handledAttentionScanIds, setHandledAttentionScanIds] = useState([]);
  const [dismissedAttentionScanId, setDismissedAttentionScanId] = useState(null);
  const [skipPrompt, setSkipPrompt] = useState(null);
  const [attentionPrompt, setAttentionPrompt] = useState(null);
  const [retryingSkippedFile, setRetryingSkippedFile] = useState(false);
  const [currentPage, setCurrentPage] = useState(getInitialPage);
  const [selectedTenant, setSelectedTenant] = useState("sentinel-demo");
  const [scanRequest, setScanRequest] = useState({
    mode: "Quick",
    targetPath: "",
    requestedBy: "soc-analyst",
    runHeuristics: true
  });

  const selectedScanId = useDashboardStore((state) => state.selectedScanId);
  const setSelectedScanId = useDashboardStore((state) => state.setSelectedScanId);
  const lastUpdatedByPage = useDashboardStore((state) => state.lastUpdatedByPage);
  const setLastUpdated = useDashboardStore((state) => state.setLastUpdated);
  const resetSessionState = useDashboardStore((state) => state.resetSessionState);

  const handledSkippedKeysRef = useRef(handledSkippedEventKeys);
  const handledAttentionIdsRef = useRef(handledAttentionScanIds);

  async function syncAgentLifecycle(currentControlPlane = null) {
    await api.registerAgent(buildAgentPayload());
    await api.heartbeat(buildHeartbeatPayload(currentControlPlane));
  }

  const stampAllPages = useEffectEvent((timestamp) => {
    pageDefinitions.forEach((page) => setLastUpdated(page.key, timestamp));
  });

  const loadData = useEffectEvent(async ({ syncLifecycle = false, preserveMessage = false } = {}) => {
    setLoading(true);
    setError("");

    try {
      if (syncLifecycle) {
        await syncAgentLifecycle(controlPlane);
      }

      const [
        controlPlaneResult,
        tenantsResult,
        threatsResult,
        scansResult,
        scanExportsResult,
        fileEventsResult,
        healthResult,
        engineStatusResult
      ] = await Promise.all([
        api.getControlPlaneSummary(),
        api.getTenants(),
        api.getThreats(),
        api.getScans(),
        api.getScanExports(),
        api.getFileEvents(),
        api.getHealth(),
        api.getEngineStatus().catch(() => null)
      ]);

      const timestamp = new Date().toISOString();

      startTransition(() => {
        setControlPlane(controlPlaneResult);
        setTenants(tenantsResult);
        setThreats(threatsResult);
        setScans(scansResult);
        setScanExports(scanExportsResult);
        setFileEvents(fileEventsResult);
        setHealth(healthResult);
        setEngineStatus(engineStatusResult);
        if (selectedScanId && !scansResult.some((scan) => scan.id === selectedScanId)) {
          setSelectedScanId(null);
        }
        if (!preserveMessage) {
          setMessage("");
        }
        stampAllPages(timestamp);
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
    resetSessionState();
    setScanProgressEvents([]);
    setHandledSkippedEventKeys([]);
    setHandledAttentionScanIds([]);
    setDismissedAttentionScanId(null);
    setSkipPrompt(null);
    setAttentionPrompt(null);
    loadData({ syncLifecycle: true });
  }, [selectedTenant]);

  const trackedScan = selectedScanId ? scans.find((scan) => scan.id === selectedScanId) ?? null : null;
  const activeScanBase = trackedScan ?? scans.find((scan) => liveScanStatuses.has(scan.status)) ?? scans[0] ?? null;
  const latestScanProgress = getLatestScanProgress(scanProgressEvents);
  const activeScan = mergeScanWithProgress(activeScanBase, latestScanProgress);
  const hasLiveScan = activeScan ? liveScanStatuses.has(activeScan.status) : false;
  const analysisProgress = deriveScanProgress(activeScan, analysisClock);
  const effectiveStage = activeScan?.stage === "Cancelled"
    ? latestScanProgress?.stage ?? "Observe"
    : activeScan?.stage ?? "Observe";
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
    ? threats.filter((threat) => threat.scanJobId === activeScan.id)
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
    const intervalId = window.setInterval(loadProgress, hasLiveScan || currentPage === "telemetry" ? 5000 : 10000);

    return () => {
      ignore = true;
      window.clearInterval(intervalId);
    };
  }, [selectedTenant, activeScanBase?.id, hasLiveScan, currentPage]);

  useEffect(() => {
    const nextSkippedEvent = [...scanProgressEvents]
      .reverse()
      .find((progressEvent) => progressEvent.isSkipped && !handledSkippedKeysRef.current.includes(getSkippedEventKey(progressEvent)));

    if (nextSkippedEvent) {
      setSkipPrompt(nextSkippedEvent);
    }
  }, [scanProgressEvents, handledSkippedEventKeys]);

  useEffect(() => {
    if (!activeScan || activeScan.status !== "Completed") {
      return;
    }

    if (handledAttentionIdsRef.current.includes(activeScan.id) || dismissedAttentionScanId === activeScan.id) {
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
    }, hasLiveScan || currentPage === "telemetry" ? 5000 : 15000);

    return () => window.clearInterval(intervalId);
  }, [selectedTenant, hasLiveScan, currentPage]);

  useEffect(() => {
    if (!activeScan || (activeScan.status !== "Running" && activeScan.status !== "Pending")) {
      return undefined;
    }

    const intervalId = window.setInterval(() => setAnalysisClock(Date.now()), 1000);
    return () => window.clearInterval(intervalId);
  }, [activeScan?.id, activeScan?.status]);

  async function handleScanSubmit(event) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    setMessage("");

    try {
      const createdScan = await api.startScan(scanRequest);
      setSelectedScanId(createdScan.id);
      setAnalysisClock(Date.now());
      await loadData({ syncLifecycle: false, preserveMessage: true });
      setMessage(`Enterprise scan #${createdScan.id} is live and now pinned as the active scan context.`);
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
    if (!handledSkippedKeysRef.current.includes(key)) {
      handledSkippedKeysRef.current = [...handledSkippedKeysRef.current, key];
    }
    setHandledSkippedEventKeys(handledSkippedKeysRef.current);
    setSkipPrompt(null);
  }

  function dismissAttentionPrompt(scanId = attentionPrompt?.scan?.id) {
    if (!scanId) {
      setAttentionPrompt(null);
      return;
    }

    if (!handledAttentionIdsRef.current.includes(scanId)) {
      handledAttentionIdsRef.current = [...handledAttentionIdsRef.current, scanId];
    }
    setDismissedAttentionScanId(scanId);
    setHandledAttentionScanIds(handledAttentionIdsRef.current);
    setAttentionPrompt(null);
  }

  async function handleRetrySkippedFile() {
    if (!skipPrompt?.currentPath || !skipPrompt?.scanJobId) {
      dismissSkippedPrompt();
      return;
    }

    setRetryingSkippedFile(true);
    setError("");
    setMessage("");

    try {
      await api.submitFileDecision(skipPrompt.scanJobId, skipPrompt.currentPath, "Retry");
      setMessage(`Retry submitted for ${skipPrompt.currentPath} in scan #${skipPrompt.scanJobId}.`);
      dismissSkippedPrompt();
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (retryError) {
      setError(retryError.message);
    } finally {
      setRetryingSkippedFile(false);
    }
  }

  async function handleSkipFile() {
    if (!skipPrompt?.currentPath || !skipPrompt?.scanJobId) {
      dismissSkippedPrompt();
      return;
    }

    setError("");
    setMessage("");

    try {
      await api.submitFileDecision(skipPrompt.scanJobId, skipPrompt.currentPath, "Skip");
      setMessage(`Skipped ${skipPrompt.currentPath} in scan #${skipPrompt.scanJobId}. Scan continues.`);
      dismissSkippedPrompt();
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (skipError) {
      setError(skipError.message);
      dismissSkippedPrompt();
    }
  }

  async function handleQuarantine(id) {
    setPendingThreatActionId(id);
    setError("");
    setMessage("");
    setThreats((current) =>
      current.map((threat) => threat.id === id ? { ...threat, isQuarantined: true } : threat)
    );

    try {
      const result = await api.quarantineThreat(id);
      setMessage(result.message);
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (quarantineError) {
      setError(quarantineError.message);
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } finally {
      setPendingThreatActionId(null);
    }
  }

  async function handleReview(threat) {
    setPendingThreatActionId(threat.id);
    setError("");
    setMessage("");

    try {
      await api.submitReview({
        threatDetectionId: threat.id,
        artifactHash: "pending-artifact-hash",
        ruleId: threat.name,
        scope: "TenantPolicy",
        analyst: "soc-analyst",
        notes: `Submitted from Sentinel Shield for ${threat.resource ?? threat.name}.`
      });
      setMessage("False-positive review submitted into governance workflow.");
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (reviewError) {
      setError(reviewError.message);
    } finally {
      setPendingThreatActionId(null);
    }
  }

  async function handleDecideReview(id, status) {
    setPendingReviewId(id);
    setError("");
    setMessage("");

    try {
      const result = await api.decideReview(id, {
        status,
        analyst: "soc-analyst",
        notes: `Decision recorded from Sentinel Shield dashboard: ${status}.`
      });
      setControlPlane((current) => current ? {
        ...current,
        falsePositiveReviews: current.falsePositiveReviews.map((review) => review.id === id ? result : review)
      } : current);
      setMessage(`Review #${id} marked as ${status.toLowerCase()}.`);
    } catch (decisionError) {
      setError(decisionError.message);
    } finally {
      setPendingReviewId(null);
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
      setMessage(`Exported report ${file.fileName}.`);
      await loadData({ syncLifecycle: false, preserveMessage: true });
    } catch (exportError) {
      setError(exportError.message);
    }
  }

  async function handleExportScan(scanId) {
    if (!scanId) {
      return;
    }

    setError("");
    setMessage("");

    try {
      const file = await api.exportScan(scanId);
      triggerDownload(file);
      setMessage(`Exported report for scan #${scanId}.`);
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
  const paritySnapshots = controlPlane?.paritySnapshots ?? [];
  const sandboxSubmissions = controlPlane?.sandboxSubmissions ?? [];
  const reviews = controlPlane?.falsePositiveReviews ?? [];
  const fleet = controlPlane?.fleet ?? null;
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

  function handleNavigation(pageKey) {
    window.location.hash = pageKey;
    setCurrentPage(pageKey);
  }

  function handleFocusScan(scanId) {
    setSelectedScanId(scanId);
    setAnalysisClock(Date.now());
    handleNavigation("home");
  }

  function handleReviewAttention() {
    const scanId = attentionPrompt?.scan?.id;
    if (scanId) {
      setSelectedScanId(scanId);
    }
    dismissAttentionPrompt(scanId);
    handleNavigation("detections");
  }

  return (
    <div className="soc-shell">
      <AppSidebar
        pageDefinitions={pageDefinitions}
        currentPage={currentPage}
        onNavigate={handleNavigation}
        engineStatus={engineStatus}
      />

      <div className="workspace-shell">
        <div className="workspace-toolbar">
          <label className="field tenant-field">
            <span>Tenant</span>
            <select value={selectedTenant} onChange={(event) => setSelectedTenant(event.target.value)}>
              {tenantOptions.map((tenant) => (
                <option key={tenant.tenantKey} value={tenant.tenantKey}>
                  {tenant.displayName}
                </option>
              ))}
            </select>
          </label>

          <button
            className="button button-secondary icon-button"
            type="button"
            aria-label="Refresh dashboard"
            onClick={() => loadData({ syncLifecycle: true, preserveMessage: true })}
          >
            <RefreshCcw size={16} />
          </button>
        </div>

        {message ? <div className="flash-banner flash-success">{message}</div> : null}

        <SkippedFileModal
          skipPrompt={skipPrompt}
          onDismiss={dismissSkippedPrompt}
          onRetry={handleRetrySkippedFile}
          onSkip={handleSkipFile}
          retryingSkippedFile={retryingSkippedFile}
        />
        <AttentionModal
          scan={attentionPrompt?.scan}
          vulnerabilities={attentionPrompt?.vulnerabilities}
          onDismiss={() => dismissAttentionPrompt()}
          onReview={handleReviewAttention}
        />

        <main className="content-shell">
          {currentPage === "home" ? (
            <HomePage
              scanRequest={scanRequest}
              setScanRequest={setScanRequest}
              submitting={submitting}
              onSubmit={handleScanSubmit}
              activeScan={activeScan}
              analysisProgress={analysisProgress}
              analysisSteps={analysisSteps}
              handleStopScan={handleStopScan}
              stoppingScanId={stoppingScanId}
              scans={scans}
              threats={threats}
              fileEvents={fileEvents}
              health={health}
              fleet={fleet}
              engineStatus={engineStatus}
              onRefresh={() => loadData({ syncLifecycle: false, preserveMessage: true })}
              onFocusScan={handleFocusScan}
              loading={loading}
              error={error}
              lastUpdated={lastUpdatedByPage.home}
            />
          ) : null}

          {currentPage === "incidents" ? (
            <IncidentsPage
              incidents={incidents}
              scans={scans}
              onResolveIncident={handleResolveIncident}
              loading={loading}
              error={error}
              onRefresh={() => loadData({ syncLifecycle: false, preserveMessage: true })}
              lastUpdated={lastUpdatedByPage.incidents}
            />
          ) : null}

          {currentPage === "detections" ? (
            <DetectionsPage
              threats={threats}
              scans={scans}
              onQuarantine={handleQuarantine}
              onReview={handleReview}
              pendingThreatActionId={pendingThreatActionId}
              loading={loading}
              error={error}
              onRefresh={() => loadData({ syncLifecycle: false, preserveMessage: true })}
              lastUpdated={lastUpdatedByPage.detections}
            />
          ) : null}

          {currentPage === "telemetry" ? (
            <TelemetryPage
              fileEvents={fileEvents}
              scans={scans}
              scanProgressEvents={scanProgressEvents}
              loading={loading}
              error={error}
              onRefresh={() => loadData({ syncLifecycle: false, preserveMessage: true })}
              lastUpdated={lastUpdatedByPage.telemetry}
            />
          ) : null}

          {currentPage === "fleet" ? (
            <FleetPage
              controlPlane={controlPlane}
              health={health}
              loading={loading}
              error={error}
              onRefresh={() => loadData({ syncLifecycle: false, preserveMessage: true })}
              lastUpdated={lastUpdatedByPage.fleet}
            />
          ) : null}

          {currentPage === "governance" ? (
            <GovernancePage
              paritySnapshots={paritySnapshots}
              sandboxSubmissions={sandboxSubmissions}
              reviews={reviews}
              scans={scans}
              onDecideReview={handleDecideReview}
              pendingReviewId={pendingReviewId}
              loading={loading}
              error={error}
              onRefresh={() => loadData({ syncLifecycle: false, preserveMessage: true })}
              lastUpdated={lastUpdatedByPage.governance}
            />
          ) : null}

          {currentPage === "reports" ? (
            <ReportsPage
              scanExports={scanExports}
              onCaptureCompliance={handleCaptureCompliance}
              onExportAllScans={handleExportAllScans}
              onExportScan={handleExportScan}
              scans={scans}
              loading={loading}
              error={error}
              onRefresh={() => loadData({ syncLifecycle: false, preserveMessage: true })}
              lastUpdated={lastUpdatedByPage.reports}
            />
          ) : null}
        </main>
      </div>
    </div>
  );
}
