import { create } from "zustand";

export const useDashboardStore = create((set) => ({
  selectedScanId: null,
  lastUpdatedByPage: {},
  setSelectedScanId: (selectedScanId) => set({ selectedScanId }),
  setLastUpdated: (pageKey, timestamp) =>
    set((state) => ({
      lastUpdatedByPage: {
        ...state.lastUpdatedByPage,
        [pageKey]: timestamp
      }
    })),
  resetSessionState: () =>
    set({
      selectedScanId: null,
      lastUpdatedByPage: {}
    })
}));
