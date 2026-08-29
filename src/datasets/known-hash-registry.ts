import { randomUUID } from "node:crypto";
import { InvalidArgumentError } from "../common/errors.js";
import { digestObject } from "../common/json.js";

const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/;
const MAX_HASHES = 100_000;

export interface KnownHashSetImport {
  name: string;
  version: string;
  description?: string;
  sha256: string[];
}

export interface KnownHashDataSet {
  dataSetRef: string;
  kind: "known_hash_set";
  name: string;
  version: string;
  description?: string;
  digest: string;
  sha256: string[];
  importedAt: string;
}

export type KnownHashDataSetSummary = Omit<KnownHashDataSet, "sha256"> & { entryCount: number };

export function parseKnownHashSetImport(value: unknown): KnownHashSetImport {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new InvalidArgumentError("known_hash_set 必须是 JSON 对象");
  const input = value as Record<string, unknown>;
  const allowed = new Set(["name", "version", "description", "sha256"]);
  const unknown = Object.keys(input).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new InvalidArgumentError(`known_hash_set 包含未知字段: ${unknown.join(", ")}`);
  const name = typeof input.name === "string" ? input.name.trim() : "";
  const version = typeof input.version === "string" ? input.version.trim() : "";
  const description = typeof input.description === "string" ? input.description.trim() : undefined;
  if (!name || name.length > 128) throw new InvalidArgumentError("known_hash_set.name 必须为 1-128 个字符");
  if (!VERSION.test(version)) throw new InvalidArgumentError("known_hash_set.version 格式无效");
  if (description !== undefined && description.length > 1024) throw new InvalidArgumentError("known_hash_set.description 不能超过 1024 个字符");
  if (!Array.isArray(input.sha256) || input.sha256.length === 0 || input.sha256.length > MAX_HASHES) {
    throw new InvalidArgumentError(`known_hash_set.sha256 必须包含 1-${MAX_HASHES} 个摘要`);
  }
  const hashes = [...new Set(input.sha256.map((item) => {
    if (typeof item !== "string" || !SHA256.test(item.toLowerCase())) throw new InvalidArgumentError("known_hash_set 仅接受 64 位 SHA-256 十六进制摘要");
    return item.toLowerCase();
  }))].sort();
  return { name, version, ...(description ? { description } : {}), sha256: hashes };
}

export function createKnownHashDataSet(input: KnownHashSetImport, importedAt = new Date().toISOString()): KnownHashDataSet {
  const normalized = parseKnownHashSetImport(input);
  return {
    dataSetRef: `DATASET-${randomUUID()}`,
    kind: "known_hash_set",
    ...normalized,
    digest: digestObject({ kind: "known_hash_set", ...normalized }),
    importedAt,
  };
}

export function summarizeKnownHashDataSet(value: KnownHashDataSet): KnownHashDataSetSummary {
  const { sha256, ...summary } = value;
  return { ...summary, entryCount: sha256.length };
}
