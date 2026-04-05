function normalizeOs() {
  const platform = window.navigator.userAgent.toLowerCase();
  if (platform.includes("mac")) {
    return "MacOs";
  }

  if (platform.includes("linux")) {
    return "Linux";
  }

  return "Windows";
}

export function buildAgentPayload() {
  const deviceId = `${window.location.hostname || "localhost"}-agent`.toLowerCase();
  return {
    deviceId,
    deviceName: window.location.hostname || "Local endpoint",
    operatingSystem: normalizeOs(),
    agentVersion: "1.0.0",
    engineVersion: "engine-1.0.0",
    rolloutRing: "Canary",
    capabilities: [
      "realtime-file-watch",
      "static-signatures",
      "behavior-rules",
      "reputation",
      "sandbox-broker",
      "self-protection"
    ]
  };
}

export function buildHeartbeatPayload(controlPlane) {
  const deviceId = `${window.location.hostname || "localhost"}-agent`.toLowerCase();
  const packVersion = controlPlane?.fleet?.currentPackVersion ?? "pack-2026.03.29.1";
  return {
    deviceId,
    agentVersion: "1.0.0",
    engineVersion: "engine-1.0.0",
    signaturePackVersion: packVersion,
    policyVersion: controlPlane?.devices?.[0]?.policyVersion ?? "policy-1.0.0",
    baselineScanCompleted: controlPlane?.devices?.[0]?.baselineScanCompleted ?? false,
    legacyShadowModeEnabled: controlPlane?.devices?.[0]?.legacyShadowModeEnabled ?? true,
    selfProtection: {
      processProtectionEnabled: true,
      fileProtectionEnabled: true,
      serviceProtectionEnabled: true,
      driverProtectionEnabled: false,
      watchdogHealthy: true,
      signedUpdatesOnly: true
    }
  };
}
