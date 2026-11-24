import { describe, expect, it } from "vitest";

import { alertActions, detectorLabel, parsePorts, partyLabel, severityTone, splitList, textToBase64 } from "./netguard";

describe("netguard helpers", () => {
  it("maps severities to badge tones", () => {
    expect(severityTone("info")).toBe("neutral");
    expect(severityTone("medium")).toBe("warn");
    expect(severityTone("critical")).toBe("down");
    expect(severityTone("unknown")).toBe("neutral");
  });

  it("labels detectors and parties", () => {
    expect(detectorLabel("ng.port_scan")).toBe("Port scan");
    expect(detectorLabel("custom.rule")).toBe("custom.rule");
    expect(partyLabel({ ip: "10.255.0.2", kind: "vpn_device", name: "alice/laptop" })).toBe(
      "VPN device alice/laptop (10.255.0.2)",
    );
    expect(partyLabel({ ip: "10.20.1.9", kind: "unknown" })).toBe("Unattributed 10.20.1.9");
    expect(partyLabel(undefined)).toBe("—");
  });

  it("offers only the allowed alert transitions", () => {
    expect(alertActions("open")).toEqual(["acknowledged", "suppressed", "closed"]);
    expect(alertActions("suppressed")).toEqual(["open", "closed"]);
    expect(alertActions("closed")).toEqual([]);
  });

  it("encodes UTF-8 text as base64", () => {
    expect(textToBase64("é note")).toBe("w6kgbm90ZQ==");
  });

  it("parses lists and ports", () => {
    expect(splitList("10.0.0.0/24, 10.0.1.0/24  ")).toEqual(["10.0.0.0/24", "10.0.1.0/24"]);
    expect(parsePorts("22, 443")).toEqual([22, 443]);
    expect(parsePorts("22, 70000")).toBeNull();
    expect(parsePorts("")).toEqual([]);
  });
});
