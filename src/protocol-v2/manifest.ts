import { InvalidArgumentError } from "../common/errors.js";
import { MANIFEST_VERSION, NAMESPACE_NAMES, type ModelExposure, type NamespaceName, type Sensitivity } from "./types.js";

export type FieldType = "string" | "integer" | "number" | "boolean" | "timestamp" | "string[]" | "object";
export interface ManifestField {
  type: FieldType;
  identity?: boolean;
  enumerable: boolean;
  projectable: boolean;
  filterable: boolean;
  sortable: boolean;
  cost: "CHEAP" | "MODERATE" | "EXPENSIVE";
  sensitivity: Sensitivity;
  modelExposure: ModelExposure;
}

export interface NamespaceManifest {
  name: NamespaceName;
  fields: Readonly<Record<string, ManifestField>>;
  relations: readonly string[];
  maxEnumerate: number;
  maxProjectFields: number;
}

const publicField = (type: FieldType, options: Partial<ManifestField> = {}): ManifestField => ({
  type, enumerable: true, projectable: true, filterable: true, sortable: type !== "object" && type !== "string[]",
  cost: "CHEAP", sensitivity: "PUBLIC", modelExposure: "VALUE", ...options,
});
const sensitiveField = (type: FieldType, exposure: ModelExposure = "VALUE", options: Partial<ManifestField> = {}): ManifestField => ({
  ...publicField(type), sensitivity: "SENSITIVE", modelExposure: exposure, ...options,
});
const secretField = (type: FieldType): ManifestField => ({
  ...publicField(type), sensitivity: "SECRET", modelExposure: "PRESENCE_ONLY", filterable: false, sortable: false,
});

const definitions: Record<NamespaceName, { identity: readonly string[]; fields: Record<string, ManifestField>; relations?: readonly string[] }> = {
  host: { identity: ["bootId"], fields: { bootId: publicField("string"), hostname: publicField("string"), os: publicField("string"), release: publicField("string"), architecture: publicField("string"), timezone: publicField("string"), observedAt: publicField("timestamp") } },
  process: { identity: ["bootId", "pid", "startTicks", "exeInode", "exeSha256"], fields: { bootId: publicField("string"), pid: publicField("integer"), startTicks: publicField("string"), ppid: publicField("integer"), uid: publicField("integer"), username: publicField("string"), comm: publicField("string"), exe: sensitiveField("string"), exeInode: publicField("string"), exeSha256: publicField("string", { cost: "EXPENSIVE", enumerable: true }), command: sensitiveField("string"), state: publicField("string"), startedAt: publicField("timestamp") }, relations: ["parent", "children", "opens", "connects"] },
  socket: { identity: ["protocol", "localAddress", "localPort", "remoteAddress", "remotePort", "inode"], fields: { protocol: publicField("string"), localAddress: publicField("string"), localPort: publicField("integer"), remoteAddress: publicField("string"), remotePort: publicField("integer"), state: publicField("string"), inode: publicField("string"), pid: publicField("integer"), intelProvider: publicField("string", { enumerable: false }), intelMalicious: publicField("boolean", { enumerable: false }), intelRiskLevel: publicField("string", { enumerable: false }), intelConfidence: publicField("number", { enumerable: false }), intelThreatTypes: publicField("string[]", { enumerable: false, sortable: false }), intelQueriedAt: publicField("timestamp", { enumerable: false }) }, relations: ["owned_by"] },
  file: { identity: ["mountId", "device", "inode"], fields: { mountId: publicField("string"), device: publicField("string"), inode: publicField("string"), path: sensitiveField("string"), canonicalPath: sensitiveField("string", "HASH_ONLY"), kind: publicField("string"), size: publicField("integer"), mode: publicField("integer"), uid: publicField("integer"), gid: publicField("integer"), mtime: publicField("timestamp"), sha256: publicField("string", { cost: "EXPENSIVE", enumerable: false }), contentClass: publicField("string"), content: sensitiveField("string", "VALUE", { enumerable: false, projectable: false, filterable: false, sortable: false, cost: "EXPENSIVE" }), baseline: publicField("string", { enumerable: false }), baselineStatus: publicField("string", { enumerable: false }), intelProvider: publicField("string", { enumerable: false }), intelMalicious: publicField("boolean", { enumerable: false }), intelRiskLevel: publicField("string", { enumerable: false }), intelConfidence: publicField("number", { enumerable: false }), intelThreatTypes: publicField("string[]", { enumerable: false, sortable: false }), intelQueriedAt: publicField("timestamp", { enumerable: false }) }, relations: ["same_inode", "same_sha256", "opened_by", "referenced_by_persistence", "requested_in"] },
  account: { identity: ["uid", "username"], fields: { uid: publicField("integer"), username: publicField("string"), gid: publicField("integer"), home: sensitiveField("string"), shell: publicField("string"), groups: publicField("string[]", { sortable: false }), locked: publicField("boolean"), passwordHash: secretField("string") }, relations: ["authorized_key", "login_event"] },
  ssh_key: { identity: ["fingerprint", "ownerUid"], fields: { fingerprint: publicField("string"), ownerUid: publicField("integer"), type: publicField("string"), bits: publicField("integer"), comment: sensitiveField("string"), sourceFile: sensitiveField("string") }, relations: ["owned_by"] },
  delegation_rule: { identity: ["mechanism", "sourceDigest", "line", "ruleDigest"], fields: { mechanism: publicField("string"), sourceDigest: publicField("string"), line: publicField("integer"), ruleDigest: publicField("string"), source: sensitiveField("string"), effect: publicField("string"), subject: publicField("string"), runAs: publicField("string"), statement: sensitiveField("string") } },
  ssh_trust_config: { identity: ["scope", "directive", "valueDigest"], fields: { scope: publicField("string"), directive: publicField("string"), valueDigest: publicField("string"), value: sensitiveField("string"), source: sensitiveField("string"), effective: publicField("boolean") } },
  cron_entry: { identity: ["source", "line", "digest"], fields: { source: sensitiveField("string"), line: publicField("integer"), digest: publicField("string"), schedule: publicField("string"), user: publicField("string"), command: sensitiveField("string") }, relations: ["executes"] },
  unit: { identity: ["name", "fragmentDigest"], fields: { name: publicField("string"), fragmentDigest: publicField("string"), path: sensitiveField("string"), enabled: publicField("boolean"), active: publicField("boolean"), execStart: sensitiveField("string"), user: publicField("string") }, relations: ["executes"] },
  persistence: { identity: ["kind", "sourceDigest"], fields: { kind: publicField("string"), sourceDigest: publicField("string"), source: sensitiveField("string"), user: publicField("string"), command: sensitiveField("string"), enabled: publicField("boolean") }, relations: ["executes"] },
  module: { identity: ["name", "address"], fields: { name: publicField("string"), address: publicField("string"), size: publicField("integer"), path: sensitiveField("string"), sha256: publicField("string", { cost: "EXPENSIVE", enumerable: false }) } },
  log_source: { identity: ["sourceId", "generation"], fields: { sourceId: publicField("string"), generation: publicField("string"), kind: publicField("string"), path: sensitiveField("string"), firstEventAt: publicField("timestamp"), lastEventAt: publicField("timestamp") }, relations: ["contains"] },
  log_event: { identity: ["sourceId", "cursor"], fields: { sourceId: publicField("string"), cursor: publicField("string"), timestamp: publicField("timestamp"), program: publicField("string"), message: sensitiveField("string"), fields: sensitiveField("object", "VALUE", { sortable: false }) } },
  auth_event: { identity: ["sourceId", "cursor"], fields: { sourceId: publicField("string"), cursor: publicField("string"), timestamp: publicField("timestamp"), eventType: publicField("string"), username: publicField("string"), sourceAddress: publicField("string"), program: publicField("string"), success: publicField("boolean") } },
  exec_event: { identity: ["sourceId", "cursor"], fields: { sourceId: publicField("string"), cursor: publicField("string"), timestamp: publicField("timestamp"), pid: publicField("integer"), uid: publicField("integer"), executable: sensitiveField("string"), arguments: sensitiveField("string"), cwd: sensitiveField("string") } },
  web_stack: { identity: ["kind", "instanceId"], fields: { kind: publicField("string"), instanceId: publicField("string"), version: publicField("string"), pid: publicField("integer"), configPaths: sensitiveField("string[]") }, relations: ["serves_root"] },
  web_root: { identity: ["mountId", "device", "inode"], fields: { mountId: publicField("string"), device: publicField("string"), inode: publicField("string"), path: sensitiveField("string"), server: publicField("string"), effective: publicField("boolean") }, relations: ["served_by"] },
  jvm: { identity: ["bootId", "pid", "startTicks"], fields: { bootId: publicField("string"), pid: publicField("integer"), startTicks: publicField("string"), version: publicField("string"), command: sensitiveField("string"), attachSupported: publicField("boolean"), container: publicField("string") }, relations: ["hosts_component", "loads_class"] },
  java_component: { identity: ["jvmDigest", "componentKind", "name"], fields: { jvmDigest: publicField("string"), componentKind: publicField("string"), name: publicField("string"), className: publicField("string"), mappings: sensitiveField("string[]") }, relations: ["implemented_by"] },
  class: { identity: ["jvmDigest", "className", "loaderId"], fields: { jvmDigest: publicField("string"), className: publicField("string"), loaderId: publicField("string"), codeSource: sensitiveField("string"), bytecodeSha256: publicField("string"), modifiable: publicField("boolean") }, relations: ["loaded_by", "defined_in"] },
  package: { identity: ["manager", "name", "version", "architecture"], fields: { manager: publicField("string"), name: publicField("string"), version: publicField("string"), architecture: publicField("string"), installedAt: publicField("timestamp"), integrity: publicField("string") }, relations: ["owns_file"] },
  task_ioc: { identity: ["kind", "valueDigest"], fields: { kind: publicField("string"), valueDigest: publicField("string"), value: sensitiveField("string"), suppliedAt: publicField("timestamp"), intelProvider: publicField("string", { enumerable: false }), intelMalicious: publicField("boolean", { enumerable: false }), intelRiskLevel: publicField("string", { enumerable: false }), intelConfidence: publicField("number", { enumerable: false }), intelThreatTypes: publicField("string[]", { enumerable: false, sortable: false }), intelQueriedAt: publicField("timestamp", { enumerable: false }) }, relations: ["matches"] },
};

for (const definition of Object.values(definitions)) {
  for (const field of definition.identity) definition.fields[field] = { ...definition.fields[field]!, identity: true };
}

export const PROTOCOL_MANIFEST: Readonly<{ version: string; namespaces: Readonly<Record<NamespaceName, NamespaceManifest>>; relations: readonly string[]; hardLimits: Readonly<Record<string, number>> }> = Object.freeze({
  version: MANIFEST_VERSION,
  namespaces: Object.freeze(Object.fromEntries(NAMESPACE_NAMES.map((name) => [name, Object.freeze({
    name,
    fields: Object.freeze(definitions[name].fields),
    relations: Object.freeze(definitions[name].relations ?? []),
    maxEnumerate: 500,
    maxProjectFields: 32,
  })])) as Record<NamespaceName, NamespaceManifest>),
  relations: Object.freeze([...new Set(Object.values(definitions).flatMap((value) => value.relations ?? []))]),
  hardLimits: Object.freeze({ predicateDepth: 4, predicateNodes: 32, queryPredicateDepth: 6, queryPredicateNodes: 64, predicateStringBytes: 256, predicateInItems: 64, enumerateLimit: 500, projectFields: 32, readBytes: 65_536, collectBytes: 104_857_600, matchRefs: 128, matchHits: 500, factBatchRows: 2_048 }),
});

export function requireNamespace(name: string): NamespaceManifest {
  const manifest = PROTOCOL_MANIFEST.namespaces[name as NamespaceName];
  if (!manifest) throw new InvalidArgumentError(`未知 namespace: ${name}`);
  return manifest;
}

export function identityFields(namespace: NamespaceName): string[] {
  return Object.entries(requireNamespace(namespace).fields).filter(([, field]) => field.identity).map(([name]) => name);
}

export function assertManifestField(namespace: NamespaceName, field: string, capability: "enumerable" | "projectable" | "filterable" | "sortable"): ManifestField {
  const definition = requireNamespace(namespace).fields[field];
  if (!definition?.[capability]) throw new InvalidArgumentError(`${namespace}.${field} 不允许 ${capability}`);
  return definition;
}
