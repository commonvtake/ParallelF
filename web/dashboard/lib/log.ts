// Structured JSON logging for server-side code, in the same shape as the
// Go and Python services (ts, level, msg, service, version, ...fields).

type Level = "DEBUG" | "INFO" | "WARN" | "ERROR";

function write(level: Level, msg: string, fields: Record<string, unknown>): void {
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    service: "pf-dashboard",
    version: process.env.PF_VERSION ?? "dev",
    ...fields,
  };
  const line = JSON.stringify(entry);
  if (level === "ERROR" || level === "WARN") console.error(line);
  else console.log(line);
}

/** Reduces an unknown thrown value to a loggable message. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const log = {
  info: (msg: string, fields: Record<string, unknown> = {}) => write("INFO", msg, fields),
  warn: (msg: string, fields: Record<string, unknown> = {}) => write("WARN", msg, fields),
  error: (msg: string, fields: Record<string, unknown> = {}) => write("ERROR", msg, fields),
};
