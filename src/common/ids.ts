import { createHash, randomUUID } from "node:crypto";

const PREFIXES = {
  task: "TASK",
  finding: "FIND",
  evidence: "EV",
  approval: "APR",
  action: "ACT",
  candidate: "CAND",
  process: "PROC",
  component: "COMP",
  class: "CLASS",
  account: "ACCT",
  persistence: "PERSIST",
  report: "RPT",
} as const;

export type IdKind = keyof typeof PREFIXES;

export function createId(kind: IdKind): string {
  return `${PREFIXES[kind]}-${randomUUID()}`;
}

export function createDeterministicId(kind: IdKind, value: string): string {
  const bytes = createHash("sha256").update(value).digest().subarray(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${PREFIXES[kind]}-${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
