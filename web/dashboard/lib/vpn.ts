// Helpers for the VPN pages: browser-side WireGuard key generation, client
// configuration rendering and presentation.

import type { VPNClientConfig, VPNDevice } from "@/lib/api/types";

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/**
 * The 32-byte private scalar inside a PKCS#8 X25519 key. The encoding is a
 * fixed 16-byte header followed by an OCTET STRING of 32 bytes.
 */
export function privateKeyFromPkcs8(pkcs8: Uint8Array): Uint8Array {
  if (pkcs8.length !== 48 || pkcs8[14] !== 0x04 || pkcs8[15] !== 0x20) {
    throw new Error("unexpected PKCS#8 encoding for an X25519 key");
  }
  return pkcs8.slice(16);
}

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

/**
 * Generates a WireGuard (X25519) key pair with WebCrypto. The private key
 * exists only in this page's memory; only the public key is sent anywhere.
 */
export async function generateKeyPair(subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<KeyPair> {
  const pair = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const publicRaw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
  return { privateKey: toBase64(privateKeyFromPkcs8(pkcs8)), publicKey: toBase64(publicRaw) };
}

const KEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

/** Whether s looks like a base64 WireGuard key (32 bytes). */
export function isKey(s: string): boolean {
  return KEY.test(s.trim());
}

/** A wg-quick configuration file for the device. */
export function renderConfig(privateKey: string, config: VPNClientConfig): string {
  const lines = [
    "[Interface]",
    `PrivateKey = ${privateKey}`,
    `Address = ${config.address}`,
    "",
    "[Peer]",
    `PublicKey = ${config.gateway_public_key}`,
  ];
  if (config.preshared_key) lines.push(`PresharedKey = ${config.preshared_key}`);
  lines.push(
    `Endpoint = ${config.endpoint}`,
    `AllowedIPs = ${config.allowed_ips.join(", ")}`,
    `PersistentKeepalive = ${config.persistent_keepalive}`,
    "",
  );
  return lines.join("\n");
}

/** 1536 -> "1.5 KiB". */
export function formatBytes(n: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = n;
  let unit = 0;
  while (Math.abs(value) >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return unit === 0 ? `${value} B` : `${value.toFixed(1)} ${units[unit]}`;
}

/** "1h 5m left", "40s left", or "" when not active. */
export function remaining(device: Pick<VPNDevice, "active" | "active_until">, now: number): string {
  if (!device.active || !device.active_until) return "";
  const seconds = Math.max(0, Math.floor((Date.parse(device.active_until) - now) / 1000));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m left`;
  if (m > 0) return `${m}m ${seconds % 60}s left`;
  return `${seconds}s left`;
}

export const ACTIVATION_CHOICES = [
  { label: "1 hour", seconds: 3600 },
  { label: "4 hours", seconds: 4 * 3600 },
  { label: "8 hours", seconds: 8 * 3600 },
  { label: "12 hours", seconds: 12 * 3600 },
] as const;

/** The current time in milliseconds (kept out of render functions). */
export function nowMs(): number {
  return Date.now();
}
