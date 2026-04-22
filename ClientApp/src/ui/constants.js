export const scanModeOptions = [
  { value: "Quick", label: "Quick" },
  { value: "Full", label: "Full" },
  { value: "Custom", label: "Custom" }
];

export const pageDefinitions = [
  { key: "home", label: "Home" },
  { key: "incidents", label: "Alerts" },
  { key: "detections", label: "Threats" },
  { key: "quarantine", label: "Quarantine" },
  { key: "telemetry", label: "Activity" },
  { key: "fleet", label: "Devices" },
  { key: "governance", label: "Reviews" },
  { key: "intel", label: "Threat Intel" },
  { key: "reports", label: "Reports" },
  { key: "settings", label: "Settings" }
];

export const liveScanStatuses = new Set(["Pending", "Running"]);

export const scanPipelineSteps = [
  { key: "Observe", label: "Discovering files" },
  { key: "StaticAnalysis", label: "Checking signatures" },
  { key: "HeuristicAnalysis", label: "Behavior analysis" },
  { key: "ReputationLookup", label: "Reputation check" },
  { key: "Response", label: "Taking action" },
  { key: "Telemetry", label: "Finalizing" },
  { key: "Completed", label: "Done" }
];

export const scanStageOrder = new Map(scanPipelineSteps.map((step, index) => [step.key, index]));

export const governanceTabs = [
  { key: "legacy-parity", label: "Engine Comparison" },
  { key: "sandbox-queue", label: "Sandbox Analysis" },
  { key: "false-positive-reviews", label: "False Positive Reviews" },
  { key: "ransomware-audit", label: "Ransomware Audit" }
];
