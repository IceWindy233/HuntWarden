import { SecurityError, type ProtocolV2ErrorCode } from "../common/errors.js";
import { COVERAGE_GAP_CODES, PROTOCOL_VERSION, type CoverageGap, type WireCost, type WireResponse } from "./types.js";

const errorCodes = new Set<ProtocolV2ErrorCode>([
  "INVALID_ARGUMENT", "PERMISSION_DENIED", "UNSUPPORTED_CAPABILITY", "STALE_REF", "EPOCH_MISMATCH",
  "SOURCE_CHANGED", "BUDGET_EXHAUSTED", "DEADLINE_EXCEEDED", "OUTPUT_LIMIT_EXCEEDED",
  "EVIDENCE_COLLECTION_FAILED", "PROBE_FAILED", "TARGET_UNAVAILABLE", "INTERNAL_ERROR",
]);
const gapCodes = new Set<CoverageGap["code"]>(COVERAGE_GAP_CODES);

const record = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

export function parseWireResponse(raw: string, expectedRequestId: string): WireResponse {
  let value: unknown;
  try { value = JSON.parse(raw); } catch (cause) { throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 返回无效 JSON", undefined, { cause }); }
  if (!record(value) || value.protocolVersion !== PROTOCOL_VERSION || value.requestId !== expectedRequestId) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 Envelope 身份不匹配");
  if (!isCost(value.cost)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 Envelope 缺少合法 cost");
  if (value.status === "ERROR") {
    if (!record(value.error) || typeof value.error.code !== "string" || !errorCodes.has(value.error.code as ProtocolV2ErrorCode)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 返回未知错误码");
    return value as unknown as WireResponse;
  }
  if (value.status !== "SUCCESS" && value.status !== "PARTIAL") throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 返回未知状态");
  if (!Array.isArray(value.objects) || !Array.isArray(value.edges) || !Array.isArray(value.gaps)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 成功 Envelope 缺少集合字段");
  for (const gap of value.gaps) if (!record(gap) || typeof gap.code !== "string" || !gapCodes.has(gap.code as CoverageGap["code"]) || typeof gap.resumable !== "boolean") throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 返回非法 CoverageGap");
  if (value.status === "PARTIAL" && value.gaps.length === 0) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "PARTIAL 必须声明 CoverageGap");
  return value as unknown as WireResponse;
}

function isCost(value: unknown): value is WireCost {
  if (!record(value)) return false;
  return ["remoteCalls", "nodes", "bytes", "wallTimeMs"].every((key) => Number.isFinite(value[key]) && Number(value[key]) >= 0);
}

export function assertCostWithinReservation(actual: WireCost, reserved: WireCost): void {
  for (const key of ["remoteCalls", "nodes", "bytes", "wallTimeMs", "probeCalls"] as const) {
    if ((actual[key] ?? 0) > (reserved[key] ?? 0)) throw new SecurityError("INTERNAL_ERROR", `Helper 实际成本超过预算预留: ${key}`, { actual: actual[key] ?? 0, reserved: reserved[key] ?? 0 });
  }
}
