import { isIP } from "node:net";
import type { RuntimeStore } from "../storage/runtime-store.js";
import { createReference } from "../tools/reference-utils.js";
import type { NetworkConnectionReferenceValue } from "./types.js";

function ipv4Bytes(value: string): number[] | undefined {
  if (isIP(value) !== 4) return undefined;
  const bytes = value.split(".").map(Number);
  return bytes.length === 4 && bytes.every((item) => Number.isInteger(item) && item >= 0 && item <= 255) ? bytes : undefined;
}

export function isPublicThreatIntelIp(value: string): boolean {
  const version = isIP(value);
  if (version === 4) {
    const bytes = ipv4Bytes(value)!;
    const [first, second, third] = bytes as [number, number, number, number];
    if (first === 0 || first === 10 || first === 127 || first >= 224) return false;
    if (first === 100 && second >= 64 && second <= 127) return false;
    if (first === 169 && second === 254) return false;
    if (first === 172 && second >= 16 && second <= 31) return false;
    if (first === 192 && ((second === 168) || (second === 0) || (second === 0 && third === 2))) return false;
    if (first === 198 && (second === 18 || second === 19 || (second === 51 && third === 100))) return false;
    if (first === 203 && second === 0 && third === 113) return false;
    return true;
  }
  if (version === 6) {
    const normalized = value.toLowerCase();
    const mappedIpv4 = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)?.[1];
    if (mappedIpv4) return isPublicThreatIntelIp(mappedIpv4);
    return normalized !== "::" && normalized !== "::1"
      && !normalized.startsWith("fe8") && !normalized.startsWith("fe9") && !normalized.startsWith("fea") && !normalized.startsWith("feb")
      && !normalized.startsWith("fc") && !normalized.startsWith("fd") && !normalized.startsWith("ff")
      && !normalized.startsWith("2001:db8:") && !normalized.startsWith("2001:10:");
  }
  return false;
}

export function parseNetworkEndpoint(value: unknown): { ip: string; port: number } | undefined {
  if (typeof value !== "string" || value.length > 256) return undefined;
  const separator = value.lastIndexOf(":");
  if (separator <= 0) return undefined;
  const ip = value.slice(0, separator).replace(/^\[|\]$/g, "");
  const port = Number(value.slice(separator + 1));
  if (isIP(ip) === 0 || !Number.isInteger(port) || port < 0 || port > 65_535) return undefined;
  return { ip, port };
}

export function attachConnectionReferences(
  store: RuntimeStore,
  taskId: string,
  connections: readonly Record<string, unknown>[],
  defaultProcessRef?: string,
): { items: Record<string, unknown>[]; refs: string[] } {
  const refs: string[] = [];
  const items = connections.map((connection) => {
    const remote = parseNetworkEndpoint(connection.remote);
    const state = typeof connection.state === "string" ? connection.state : "UNKNOWN";
    if (!remote || remote.port === 0 || state === "LISTEN" || !isPublicThreatIntelIp(remote.ip)) {
      return { ...connection, threatIntelEligible: false };
    }
    const processRef = typeof connection.processRef === "string" ? connection.processRef : defaultProcessRef;
    const value: NetworkConnectionReferenceValue = {
      protocol: typeof connection.protocol === "string" ? connection.protocol : "unknown",
      local: typeof connection.local === "string" ? connection.local : "unknown",
      remote: String(connection.remote),
      state,
      remoteIp: remote.ip,
      remotePort: remote.port,
      ...(processRef ? { processRef } : {}),
      observedAt: new Date().toISOString(),
    };
    const reference = createReference(store, taskId, "socket", "socket", value);
    refs.push(reference.ref);
    return { ...connection, connectionRef: reference.ref, remoteIp: remote.ip, remotePort: remote.port, threatIntelEligible: true };
  });
  return { items, refs };
}
