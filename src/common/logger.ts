export interface LogFields {
  taskId?: string;
  host?: string;
  event: string;
  tool?: string;
  durationMs?: number;
  status?: string;
  [key: string]: unknown;
}

export function log(level: "debug" | "info" | "warn" | "error", fields: LogFields): void {
  process.stderr.write(`${JSON.stringify({ time: new Date().toISOString(), level, ...fields })}\n`);
}
