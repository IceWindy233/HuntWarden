import { digestObject } from "../common/json.js";
import { MANIFEST_VERSION } from "../protocol-v2/types.js";
import type { TaskGrant } from "../protocol-v2/types.js";
import { PLAYBOOK_DEFINITIONS, PLAYBOOK_REGISTRY_VERSION } from "../playbooks/registry.js";
import type { AuthorizationEnvelope } from "./types.js";
import { categoryNamespaces } from "../protocol-v2/capability.js";
import { PROTOCOL_MANIFEST } from "../protocol-v2/manifest.js";
import type { CheckCategory } from "../domain/types.js";
import type { WireCost } from "../protocol-v2/types.js";

export const INVESTIGATION_ENGINE_VERSION = "1.0.0";
export const AUTHORIZATION_ENVELOPE_VERSION = "1.0.0";
export const RULE_REGISTRY_VERSION = "2.3.0";

export const PLAYBOOK_REGISTRY_DIGEST = digestObject({
  version: PLAYBOOK_REGISTRY_VERSION,
  playbooks: PLAYBOOK_DEFINITIONS,
});

export const RULE_REGISTRY_DIGEST = digestObject({
  version: RULE_REGISTRY_VERSION,
  manifestVersion: MANIFEST_VERSION,
});

export interface InvestigationCompatibility {
  protocolVersion: 2;
  manifestVersion: string;
  minimumHelperVersion: string;
  engineVersion: string;
  resumable: boolean;
}

export const INVESTIGATION_COMPATIBILITY: readonly InvestigationCompatibility[] = [{
  protocolVersion: 2,
  manifestVersion: MANIFEST_VERSION,
  minimumHelperVersion: "3.0.0",
  engineVersion: INVESTIGATION_ENGINE_VERSION,
  resumable: true,
}];

export function computeAuthorizationVersion(targetFingerprint: string, grants: readonly TaskGrant[], now = Date.now()): string {
  const activeGrants = grants
    .filter((grant) => grant.status === "ACTIVE" && grant.targetFingerprint === targetFingerprint && (!grant.expiresAt || Date.parse(grant.expiresAt) > now))
    .map((grant) => ({ kind: grant.kind, binding: grant.binding, expiresAt: grant.expiresAt }))
    .sort((left, right) => digestObject(left).localeCompare(digestObject(right)));
  return `${AUTHORIZATION_ENVELOPE_VERSION}:${digestObject({ targetFingerprint, activeGrants })}`;
}

export function buildAuthorizationEnvelope(targetFingerprint: string, grants: readonly TaskGrant[], budget: WireCost, now = Date.now()): AuthorizationEnvelope {
  const active = grants.filter((grant) => grant.status === "ACTIVE" && grant.targetFingerprint === targetFingerprint && (!grant.expiresAt || Date.parse(grant.expiresAt) > now));
  const categories = active.flatMap((grant) => grant.kind === "CATEGORY" && typeof grant.binding.category === "string" ? [grant.binding.category as CheckCategory] : []);
  const namespaces = [...new Set(categories.flatMap(categoryNamespaces))];
  const derivedRelations = [...new Set(namespaces.flatMap((namespace) => PROTOCOL_MANIFEST.namespaces[namespace].relations))].sort();
  const probes = active.flatMap((grant) => grant.kind === "PROBE" && typeof grant.binding.probeKind === "string" ? [grant.binding.probeKind] : []).sort();
  const scopeRefs = active.filter((grant) => grant.kind === "SCOPE").map((grant) => grant.grantId).sort();
  const expires = active.flatMap((grant) => grant.expiresAt ? [grant.expiresAt] : []).sort();
  return {
    version: computeAuthorizationVersion(targetFingerprint, grants, now), targetFingerprint,
    namespaces, scopeRefs, derivedRelations,
    sensitiveRead: active.some((grant) => grant.kind === "SENSITIVE_READ"),
    collectEvidence: namespaces.some((namespace) => ["file", "process", "jvm", "class"].includes(namespace)),
    probes, ...(expires.length > 0 ? { expiresAt: expires[0] } : {}), budget: structuredClone(budget),
  };
}

export function assertInvestigationCompatibility(input: { protocolVersion: number; manifestVersion: string; helperVersion: string; engineVersion?: string }): void {
  const compatible = INVESTIGATION_COMPATIBILITY.some((entry) => entry.protocolVersion === input.protocolVersion
    && entry.manifestVersion === input.manifestVersion
    && compareVersion(input.helperVersion, entry.minimumHelperVersion) >= 0
    && (!input.engineVersion || input.engineVersion === entry.engineVersion)
    && entry.resumable);
  if (!compatible) throw new Error(`调查版本组合不兼容：protocol=${input.protocolVersion}, manifest=${input.manifestVersion}, helper=${input.helperVersion}, engine=${input.engineVersion ?? "new"}`);
}

function compareVersion(left: string, right: string): number {
  const parse = (value: string) => value.split(".").slice(0, 3).map((part) => Number.parseInt(part, 10));
  const a = parse(left);
  const b = parse(right);
  if (a.some((part) => !Number.isFinite(part)) || b.some((part) => !Number.isFinite(part))) return -1;
  for (let index = 0; index < 3; index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}
