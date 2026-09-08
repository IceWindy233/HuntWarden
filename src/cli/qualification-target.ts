import YAML from "yaml";
import type { TargetConfig } from "../domain/types.js";
import { validateTargetConfig } from "../domain/validation.js";

const TARGET_KEYS = new Set(["host", "port", "username", "hostFingerprint", "privateKeyPath", "knownHostsPath"]);

export function parseQualificationTarget(text: string, source: string): TargetConfig {
  let raw: unknown;
  try {
    raw = YAML.parse(text);
  } catch (error) {
    throw new Error(`目标 YAML 解析失败 (${source}): ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`目标 YAML 不是对象: ${source}`);
  const target = raw as TargetConfig & Record<string, unknown>;
  const extra = Object.keys(target).filter((key) => !TARGET_KEYS.has(key));
  if (extra.length > 0) throw new Error(`目标 YAML 包含未知字段 (${source}): ${extra.join(", ")}`);
  validateTargetConfig(target);
  return target;
}
