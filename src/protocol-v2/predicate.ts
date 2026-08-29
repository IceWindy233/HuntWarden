import { InvalidArgumentError } from "../common/errors.js";
import { PROTOCOL_MANIFEST, assertManifestField, type FieldType } from "./manifest.js";
import type { NamespaceName, Predicate, PredicateOperator } from "./types.js";

const comparison = new Set<PredicateOperator>(["lt", "lte", "gt", "gte"]);
const stringOnly = new Set<PredicateOperator>(["contains", "starts_with"]);

export function validatePredicate(namespace: NamespaceName, predicate: Predicate | undefined, limits?: { depth: number; nodes: number }): void {
  if (!predicate) return;
  const maximumDepth = limits?.depth ?? PROTOCOL_MANIFEST.hardLimits.predicateDepth!;
  const maximumNodes = limits?.nodes ?? PROTOCOL_MANIFEST.hardLimits.predicateNodes!;
  let nodes = 0;
  const visit = (node: Predicate, depth: number): void => {
    nodes += 1;
    if (nodes > maximumNodes) throw new InvalidArgumentError("Predicate 节点超过上限");
    if (depth > maximumDepth) throw new InvalidArgumentError("Predicate 深度超过上限");
    if ("args" in node) {
      if (node.args.length < 1 || node.args.length > 32) throw new InvalidArgumentError(`${node.op} 参数数量无效`);
      for (const child of node.args) visit(child, depth + 1);
      return;
    }
    if ("arg" in node) { visit(node.arg, depth + 1); return; }
    const field = assertManifestField(namespace, node.field, "filterable");
    validateValue(node.op, field.type, node.value);
  };
  visit(predicate, 1);
}

function validateValue(op: PredicateOperator, type: FieldType, value: Predicate extends infer _ ? unknown : never): void {
  if (op === "exists") {
    if (value !== undefined && typeof value !== "boolean") throw new InvalidArgumentError("exists.value 必须省略或为 boolean");
    return;
  }
  if (value === undefined) throw new InvalidArgumentError(`${op} 缺少 value`);
  if (typeof value === "string" && Buffer.byteLength(value, "utf8") > PROTOCOL_MANIFEST.hardLimits.predicateStringBytes!) throw new InvalidArgumentError("Predicate 字符串超过上限");
  if (op === "in") {
    if (!Array.isArray(value) || value.length < 1 || value.length > PROTOCOL_MANIFEST.hardLimits.predicateInItems!) throw new InvalidArgumentError("in.value 必须是有界数组");
    for (const item of value) if (!["string", "number", "boolean"].includes(typeof item)) throw new InvalidArgumentError("in.value 含非法类型");
    return;
  }
  if (Array.isArray(value) || (typeof value === "object" && value !== null)) throw new InvalidArgumentError(`${op}.value 必须是标量`);
  if (stringOnly.has(op) && type !== "string") throw new InvalidArgumentError(`${op} 仅支持字符串字段`);
  if (comparison.has(op) && !["integer", "number", "timestamp", "string"].includes(type)) throw new InvalidArgumentError(`${op} 与字段类型不兼容`);
}

export function evaluatePredicate(predicate: Predicate | undefined, payload: Record<string, unknown>): boolean {
  if (!predicate) return true;
  if ("args" in predicate) return predicate.op === "and" ? predicate.args.every((value) => evaluatePredicate(value, payload)) : predicate.args.some((value) => evaluatePredicate(value, payload));
  if ("arg" in predicate) return !evaluatePredicate(predicate.arg, payload);
  const actual = payload[predicate.field];
  const expected = predicate.value;
  switch (predicate.op) {
    case "exists": return (expected ?? true) ? actual !== undefined && actual !== null : actual === undefined || actual === null;
    case "eq": return actual === expected;
    case "neq": return actual !== expected;
    case "lt": return comparable(actual) < comparable(expected);
    case "lte": return comparable(actual) <= comparable(expected);
    case "gt": return comparable(actual) > comparable(expected);
    case "gte": return comparable(actual) >= comparable(expected);
    case "in": return Array.isArray(expected) && expected.includes(actual as never);
    case "contains": return typeof actual === "string" && typeof expected === "string" && actual.includes(expected);
    case "starts_with": return typeof actual === "string" && typeof expected === "string" && actual.startsWith(expected);
  }
}

function comparable(value: unknown): string | number {
  if (typeof value === "number" || typeof value === "string") return value;
  return "";
}
