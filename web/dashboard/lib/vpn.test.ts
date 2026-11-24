import { webcrypto } from "node:crypto";

import { describe, expect, it } from "vitest";

import { formatBytes, generateKeyPair, isKey, privateKeyFromPkcs8, remaining, renderConfig } from "./vpn";

describe("WireGuard keys", () => {
  it("generates a key pair whose public key matches the private key", async () => {
    const subtle = webcrypto.subtle as unknown as SubtleCrypto;
    const pair = await generateKeyPair(subtle);
    expect(isKey(pair.privateKey)).toBe(true);
    expect(isKey(pair.publicKey)).toBe(true);
    expect(pair.privateKey).not.toBe(pair.publicKey);

    // Re-import the private scalar and derive the public key from it.
    const scalar = Buffer.from(pair.privateKey, "base64");
    const header = Buffer.from("302e020100300506032b656e04220420", "hex");
    const imported = await webcrypto.subtle.importKey(
      "pkcs8",
      Buffer.concat([header, scalar]),
      { name: "X25519" },
      true,
      ["deriveBits"],
    );
    const jwk = await webcrypto.subtle.exportKey("jwk", imported);
    expect(Buffer.from(jwk.x ?? "", "base64url").toString("base64")).toBe(pair.publicKey);
  });

  it("rejects an unexpected PKCS#8 layout", () => {
    expect(() => privateKeyFromPkcs8(new Uint8Array(40))).toThrow();
  });

  it("recognises keys", () => {
    expect(isKey("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")).toBe(true);
    expect(isKey("not a key")).toBe(false);
  });
});

describe("client configuration", () => {
  it("renders a wg-quick file with the pre-shared key when there is one", () => {
    const text = renderConfig("PRIVATE", {
      address: "10.255.0.10/32",
      gateway_public_key: "GATEWAY",
      endpoint: "192.0.2.1:51820",
      allowed_ips: ["10.255.0.0/22", "10.20.1.0/24"],
      persistent_keepalive: 25,
      preshared_key: "PSK",
    });
    expect(text).toBe(
      "[Interface]\nPrivateKey = PRIVATE\nAddress = 10.255.0.10/32\n\n[Peer]\nPublicKey = GATEWAY\nPresharedKey = PSK\n" +
        "Endpoint = 192.0.2.1:51820\nAllowedIPs = 10.255.0.0/22, 10.20.1.0/24\nPersistentKeepalive = 25\n",
    );
  });
});

describe("presentation", () => {
  it("formats bytes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MiB");
  });

  it("shows the time left", () => {
    const now = Date.parse("2026-11-24T12:00:00Z");
    expect(remaining({ active: true, active_until: "2026-11-24T13:05:00Z" }, now)).toBe("1h 5m left");
    expect(remaining({ active: true, active_until: "2026-11-24T12:00:40Z" }, now)).toBe("40s left");
    expect(remaining({ active: false }, now)).toBe("");
  });
});
