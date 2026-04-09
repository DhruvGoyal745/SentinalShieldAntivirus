export const scanModeOptions = [
  { value: "Quick", label: "Quick" },
  { value: "Full", label: "Full" },
  { value: "Custom", label: "Custom" }
];

export const pageDefinitions = [
  { key: "home", label: "Home" },
  { key: "incidents", label: "Incidents" },
  { key: "detections", label: "Detections" },
  { key: "telemetry", label: "Telemetry" },
  { key: "fleet", label: "Fleet" },
  { key: "governance", label: "Governance" },
  { key: "reports", label: "Reports" }
];

export const liveScanStatuses = new Set(["Pending", "Running"]);

export const scanPipelineSteps = [
  { key: "Observe", label: "Observe" },
  { key: "StaticAnalysis", label: "Static Analysis" },
  { key: "HeuristicAnalysis", label: "Heuristic Analysis" },
  { key: "ReputationLookup", label: "Reputation Lookup" },
  { key: "Response", label: "Response" },
  { key: "Telemetry", label: "Telemetry" },
  { key: "Completed", label: "Completed" }
];

export const scanStageOrder = new Map(scanPipelineSteps.map((step, index) => [step.key, index]));

export const governanceTabs = [
  { key: "legacy-parity", label: "Legacy Parity" },
  { key: "sandbox-queue", label: "Sandbox Queue" },
  { key: "false-positive-reviews", label: "False Positive Reviews" }
];
