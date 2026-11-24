"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { bff, failureMessage } from "@/lib/api/browser";
import type { VPNDeviceCreate, VPNEnrolment } from "@/lib/api/types";
import { RESOURCE_NAME_PATTERN } from "@/lib/cloud";
import { generateKeyPair, isKey, renderConfig } from "@/lib/vpn";

const FIELD = "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal";

/**
 * Enrols a device. By default the key pair is generated here, in the
 * browser; only the public key is sent. The finished configuration (with
 * the private key) is shown once for download and then forgotten.
 */
export function EnrolForm({ pskAvailable }: { pskAvailable: boolean }) {
  const router = useRouter();
  const [mode, setMode] = useState<"generate" | "paste">("generate");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [result, setResult] = useState<{ name: string; text: string | null }>();

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const name = String(data.get("name") ?? "").trim();
    setBusy(true);
    setError(undefined);
    try {
      let privateKey: string | null = null;
      let publicKey = String(data.get("public_key") ?? "").trim();
      if (mode === "generate") {
        if (!globalThis.crypto?.subtle) {
          setError("This browser cannot generate keys here (WebCrypto X25519). Paste a public key instead.");
          return;
        }
        const pair = await generateKeyPair();
        privateKey = pair.privateKey;
        publicKey = pair.publicKey;
      } else if (!isKey(publicKey)) {
        setError("That is not a WireGuard public key (44 base64 characters ending in '=').");
        return;
      }
      const body: VPNDeviceCreate = { name, public_key: publicKey, preshared_key: data.get("psk") === "on" };
      const response = await bff("vpn/devices", "POST", body);
      if (!response.ok) {
        setError(await failureMessage(response));
        return;
      }
      const enrolment = (await response.json()) as VPNEnrolment;
      setResult({ name, text: privateKey ? renderConfig(privateKey, enrolment.config) : null });
      router.refresh();
    } catch {
      setError("Key generation or the request failed. Try again, or paste a public key instead.");
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    const download = result.text
      ? URL.createObjectURL(new Blob([result.text], { type: "text/plain" }))
      : undefined;
    return (
      <div className="space-y-3" data-testid="enrolment-result">
        <p className="text-sm text-slate-700">
          <span className="font-medium">{result.name}</span> is enrolled. Activate it below before it can send
          traffic.
        </p>
        {result.text ? (
          <>
            <p
              role="alert"
              className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900"
            >
              This configuration contains the device&apos;s private key. It is shown once and is not stored
              anywhere: download it now and import it in the WireGuard app.
            </p>
            <textarea
              readOnly
              aria-label="WireGuard configuration"
              value={result.text}
              rows={10}
              className="block w-full rounded-md border border-slate-300 bg-slate-50 p-2 font-mono text-xs"
            />
            <a
              href={download}
              download={`pf-${result.name}.conf`}
              className="inline-block rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700"
            >
              Download pf-{result.name}.conf
            </a>
          </>
        ) : (
          <p className="text-sm text-slate-600">
            Add the gateway as a peer in your WireGuard app using the device&apos;s configuration (open the
            device to see it).
          </p>
        )}
        <div>
          <button
            type="button"
            onClick={() => setResult(undefined)}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100"
          >
            Done (forget the key)
          </button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={(event) => void submit(event)} className="grid gap-3 sm:grid-cols-2">
      {error ? (
        <p
          role="alert"
          className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900 sm:col-span-2"
        >
          {error}
        </p>
      ) : null}
      <label className="text-sm font-medium text-slate-700">
        Device name
        <input
          name="name"
          required
          minLength={3}
          maxLength={40}
          pattern={RESOURCE_NAME_PATTERN}
          title="3–40 characters: lower-case letters, digits and hyphens, starting with a letter."
          placeholder="laptop"
          autoComplete="off"
          className={`${FIELD} font-mono`}
        />
      </label>
      <fieldset className="text-sm">
        <legend className="font-medium text-slate-700">Key pair</legend>
        <label className="mt-1 flex items-center gap-2">
          <input
            type="radio"
            name="mode"
            checked={mode === "generate"}
            onChange={() => setMode("generate")}
          />
          Generate in this browser
        </label>
        <label className="flex items-center gap-2">
          <input type="radio" name="mode" checked={mode === "paste"} onChange={() => setMode("paste")} />
          Paste a public key from the WireGuard app
        </label>
      </fieldset>
      {mode === "paste" ? (
        <label className="text-sm font-medium text-slate-700 sm:col-span-2">
          Public key
          <input name="public_key" required autoComplete="off" className={`${FIELD} font-mono`} />
        </label>
      ) : null}
      {pskAvailable ? (
        <label className="flex items-center gap-2 text-sm text-slate-700 sm:col-span-2">
          <input type="checkbox" name="psk" defaultChecked />
          Add a pre-shared key (an extra symmetric layer; shown once)
        </label>
      ) : null}
      <div className="sm:col-span-2">
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          {busy ? "Enrolling…" : "Enrol device"}
        </button>
      </div>
    </form>
  );
}
