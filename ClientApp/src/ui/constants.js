export const scanModeOptions = [
  {
    value: "Quick",
    label: "Quick scan",
    eyebrow: "Rapid sweep",
    description: "Checks hot zones like downloads, temp files, startup paths, and active user surfaces.",
    eta: "Fastest response"
  },
  {
    value: "Full",
    label: "Full scan",
    eyebrow: "Deep coverage",
    description: "Covers the broader monitored estate and is best for full reassurance on a customer endpoint.",
    eta: "Highest confidence"
  },
  {
    value: "Custom",
    label: "Custom path",
    eyebrow: "Focused review",
    description: "Targets one suspicious folder or mounted path when a customer needs evidence around a single area.",
    eta: "Flexible scope"
  }
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
  { key: "Queued", label: "Queued" },
  { key: "Observe", label: "Observe" },
  { key: "Normalize", label: "Normalize" },
  { key: "StaticAnalysis", label: "Static analysis" },
  { key: "HeuristicAnalysis", label: "Heuristics" },
  { key: "ReputationLookup", label: "Reputation" },
  { key: "Response", label: "Response" },
  { key: "Telemetry", label: "Telemetry" },
  { key: "Completed", label: "Completed" }
];

export const scanStageOrder = new Map(scanPipelineSteps.map((step, index) => [step.key, index]));
