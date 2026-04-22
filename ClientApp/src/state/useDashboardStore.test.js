import { describe, it, expect, beforeEach } from "vitest";
import { useDashboardStore } from "./useDashboardStore";

describe("useDashboardStore", () => {
  beforeEach(() => {
    useDashboardStore.getState().resetSessionState();
  });

  it("starts with null selectedScanId", () => {
    const state = useDashboardStore.getState();
    expect(state.selectedScanId).toBeNull();
  });

  it("sets selectedScanId", () => {
    useDashboardStore.getState().setSelectedScanId(42);
    expect(useDashboardStore.getState().selectedScanId).toBe(42);
  });

  it("tracks last updated per page", () => {
    const ts1 = "2026-04-19T12:00:00Z";
    const ts2 = "2026-04-19T12:05:00Z";

    useDashboardStore.getState().setLastUpdated("home", ts1);
    useDashboardStore.getState().setLastUpdated("detections", ts2);

    const state = useDashboardStore.getState();
    expect(state.lastUpdatedByPage.home).toBe(ts1);
    expect(state.lastUpdatedByPage.detections).toBe(ts2);
  });

  it("resetSessionState clears everything", () => {
    useDashboardStore.getState().setSelectedScanId(99);
    useDashboardStore.getState().setLastUpdated("home", "ts");

    useDashboardStore.getState().resetSessionState();

    const state = useDashboardStore.getState();
    expect(state.selectedScanId).toBeNull();
    expect(state.lastUpdatedByPage).toEqual({});
  });
});
