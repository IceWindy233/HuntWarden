import { digestObject } from "../common/json.js";
import type { FactRecord } from "../protocol-v2/types.js";

export interface JavaClassInspectionTarget {
  className: string;
  classLoaderId: string;
}

const PLACEHOLDER_IDENTIFIERS = new Set(["unknown", "unavailable", "n/a", "none", "null", "-"]);

export function isUsableJavaClassIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && !PLACEHOLDER_IDENTIFIERS.has(value.trim().toLowerCase());
}

/**
 * Tomcat 的静态注册信息可能先给出 unknown ClassLoader，运行时枚举随后会为同一组件
 * 给出精确 Loader。只有同一逻辑组件完全没有精确身份时才算覆盖缺口。
 */
export function selectJavaClassInspectionTargets(
  facts: readonly Pick<FactRecord, "namespace" | "subjectRef" | "privatePayload">[],
  objectRefs: readonly string[],
  maximum: number,
): { targets: JavaClassInspectionTarget[]; incomplete: boolean } {
  const allowedRefs = new Set(objectRefs);
  const groups = new Map<string, { usable: JavaClassInspectionTarget[]; unresolved: boolean }>();
  let incomplete = false;

  for (const fact of facts) {
    if (fact.namespace !== "java_component" || !allowedRefs.has(fact.subjectRef)) continue;
    const fields = fact.privatePayload;
    const className = fields.className;
    const classLoaderId = fields.classLoaderId;
    if (!isUsableJavaClassIdentifier(className)) {
      incomplete = true;
      continue;
    }
    const logicalKey = digestObject({
      className,
      context: fields.context ?? fields.contextPath ?? null,
      componentKind: fields.componentKind ?? null,
      name: fields.name ?? null,
    });
    const group = groups.get(logicalKey) ?? { usable: [], unresolved: false };
    if (isUsableJavaClassIdentifier(classLoaderId)) group.usable.push({ className, classLoaderId });
    else group.unresolved = true;
    groups.set(logicalKey, group);
  }

  const deduped = new Map<string, JavaClassInspectionTarget>();
  for (const group of groups.values()) {
    if (group.usable.length === 0) {
      incomplete = true;
      continue;
    }
    for (const target of group.usable) deduped.set(`${target.className}\0${target.classLoaderId}`, target);
  }
  const allTargets = [...deduped.values()];
  return { targets: allTargets.slice(0, maximum), incomplete: incomplete || allTargets.length > maximum };
}
