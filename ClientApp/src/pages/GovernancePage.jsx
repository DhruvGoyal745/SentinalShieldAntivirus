import { useEffect, useMemo, useState } from "react";
import PageHeader from "../components/PageHeader";
import ScanSelector from "../components/ScanSelector";
import Timestamp from "../components/Timestamp";
import { EmptyState, ErrorState, TableSkeleton } from "../components/States";
import { useDashboardStore } from "../state/useDashboardStore";
import { governanceTabs } from "../ui/constants";
import { getGovernanceTabFromHash, formatPercent, reviewStatusTone, sandboxVerdictTone, ransomwareActionTone, formatEntropy } from "../ui/presentation";

export default function GovernancePage({
  paritySnapshots,
  sandboxSubmissions,
  reviews,
  ransomwareSignals = [],
  scans,
  onDecideReview,
  pendingReviewId,
  loading,
  error,
  onRefresh,
  lastUpdated
}) {
  const [activeTab, setActiveTab] = useState(getGovernanceTabFromHash);
  const selectedScanId = useDashboardStore((state) => state.selectedScanId);

  useEffect(() => {
    const onHashChange = () => setActiveTab(getGovernanceTabFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  function navigateTab(tabKey) {
    window.location.hash = `governance/${tabKey}`;
    setActiveTab(tabKey);
  }

  const filteredParitySnapshots = useMemo(() => {
    if (!selectedScanId) return paritySnapshots;
    return paritySnapshots.filter((snapshot) => snapshot.scanJobId === selectedScanId);
  }, [paritySnapshots, selectedScanId]);

  const filteredSandboxSubmissions = useMemo(() => {
    if (!selectedScanId) return sandboxSubmissions;
    return sandboxSubmissions.filter((submission) => submission.scanJobId === selectedScanId);
  }, [sandboxSubmissions, selectedScanId]);

  const filteredReviews = useMemo(() => {
    if (!selectedScanId) return reviews;
    return reviews.filter((review) => review.scanJobId === selectedScanId);
  }, [reviews, selectedScanId]);

  const showParity = activeTab === "legacy-parity";
  const showSandbox = activeTab === "sandbox-queue";
  const showReviews = activeTab === "false-positive-reviews";
  const showRansomwareAudit = activeTab === "ransomware-audit";

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Audit"
        title="Reviews"
        lastUpdated={lastUpdated}
        actions={<ScanSelector scans={scans} label="Scan context" id="governance-scan-selector" />}
      />

      {error ? <ErrorState message={error} onRetry={onRefresh} /> : null}

      <div className="tab-bar" role="tablist" aria-label="Governance sections">
        {governanceTabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.key}
            className={`tab-button ${activeTab === tab.key ? "active" : ""}`}
            onClick={() => navigateTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {loading ? (
        <TableSkeleton rows={6} columns={5} />
      ) : showParity ? (
        filteredParitySnapshots.length === 0 ? (
          <EmptyState title="No comparisons yet" description="Engine comparison data will appear after scans complete." />
        ) : (
          <div className="table-shell">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Malware Family</th>
                  <th>Match Rate</th>
                  <th>Mismatches</th>
                </tr>
              </thead>
              <tbody>
                {filteredParitySnapshots.map((snapshot) => {
                  const divergence = Math.round(100 - Number(snapshot.detectionRecallPercent ?? 0));
                  return (
                    <tr key={snapshot.id}>
                      <td>{snapshot.malwareFamily}</td>
                      <td>{formatPercent(snapshot.detectionRecallPercent)}</td>
                      <td className={divergence > 20 ? "text-warning" : ""}>{divergence}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      ) : showSandbox ? (
        filteredSandboxSubmissions.length === 0 ? (
          <EmptyState title="No sandbox results" description="No files have been sent for sandbox analysis yet." />
        ) : (
          <div className="table-shell">
            <table className="data-table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Verdict</th>
                  <th>Behavior Summary</th>
                  <th>Submitted</th>
                </tr>
              </thead>
              <tbody>
                {filteredSandboxSubmissions.map((submission) => (
                  <tr key={submission.id}>
                    <td title={submission.fileName}>{submission.fileName?.split("\\").pop() ?? submission.fileName}</td>
                    <td><span className={`pill pill-${sandboxVerdictTone(submission.verdict)}`}>{submission.verdict}</span></td>
                    <td>{submission.behaviorSummary}</td>
                    <td><Timestamp value={submission.updatedAt ?? submission.createdAt} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : filteredReviews.length === 0 ? (
        <EmptyState title="No reviews" description="No false positive reviews have been submitted yet." />
      ) : (
        <div className="table-shell">
          <table className="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Submitted by</th>
                <th>Notes</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredReviews.map((review) => (
                <tr key={review.id}>
                  <td><span className={`pill pill-${reviewStatusTone(review.status)}`}>{review.status}</span></td>
                  <td>{review.analyst}</td>
                  <td>{review.notes}</td>
                  <td className="row-actions">
                    <button
                      className="button button-secondary button-small"
                      type="button"
                      disabled={review.status !== "Submitted" || pendingReviewId === review.id}
                      onClick={() => onDecideReview(review.id, "Approved")}
                    >
                      Approve
                    </button>
                    <button
                      className="button button-secondary button-small"
                      type="button"
                      disabled={review.status !== "Submitted" || pendingReviewId === review.id}
                      onClick={() => onDecideReview(review.id, "Rejected")}
                    >
                      Reject
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showRansomwareAudit ? (
        ransomwareSignals.length === 0 ? (
          <EmptyState title="No ransomware signals" description="No ransomware activity has been detected." />
        ) : (
          <div className="table-shell">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Process</th>
                  <th>Files Affected</th>
                  <th>Max Entropy</th>
                  <th>Ext Changes</th>
                  <th>Action</th>
                  <th>Detected</th>
                </tr>
              </thead>
              <tbody>
                {ransomwareSignals.map((signal, index) => (
                  <tr key={index}>
                    <td title={signal.processPath}>{signal.processPath?.split("\\").pop() ?? signal.processPath}</td>
                    <td>{signal.affectedFileCount}</td>
                    <td className="entropy-indicator">{formatEntropy(signal.maxEntropyScore)}</td>
                    <td>{signal.extensionChangeCount}</td>
                    <td><span className={`pill pill-${ransomwareActionTone(signal.recommendedAction)}`}>{signal.recommendedAction}</span></td>
                    <td><Timestamp value={signal.detectedAt} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : null}
    </div>
  );
}
