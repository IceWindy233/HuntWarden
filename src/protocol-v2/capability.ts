import { SecurityError } from "../common/errors.js";
import type { CheckCategory } from "../domain/types.js";
import { MANIFEST_VERSION, PROTOCOL_VERSION, type HelperCapabilitiesV2, type NamespaceName, type TaskGrant } from "./types.js";
import { PROTOCOL_MANIFEST } from "./manifest.js";

export interface EffectiveCapabilities {
  namespaces: Partial<Record<NamespaceName, { fields: Set<string>; relations: Set<string>; verbs: Set<HelperCapabilitiesV2["verbs"][number]> }>>;
  matchers: Set<"literal" | "re2" | "yara">;
  probes: Set<"jvm.tomcat.inventory" | "jvm.class.inspect">;
  verbs: Set<HelperCapabilitiesV2["verbs"][number]>;
  limits: HelperCapabilitiesV2["limits"];
  protocolAnomalies: string[];
}

const CATEGORY_NAMESPACES: Readonly<Record<CheckCategory, ReadonlySet<NamespaceName>>> = {
  webshell: new Set(["host", "process", "file", "log_source", "log_event", "web_stack", "web_root"]),
  java_memory_shell: new Set(["host", "process", "file", "module", "jvm", "java_component", "class"]),
  backdoor_account: new Set(["host", "account", "ssh_key", "delegation_rule", "ssh_trust_config", "file", "log_source", "auth_event"]),
  linux_persistence: new Set(["host", "process", "file", "ssh_key", "cron_entry", "unit", "persistence", "module"]),
  linux_intrusion_triage: new Set(["host", "process", "socket", "file", "account", "ssh_key", "cron_entry", "unit", "persistence", "module", "log_source", "log_event", "auth_event", "exec_event", "package"]),
};

export function categoryGrantAllowsNamespace(grants: readonly TaskGrant[], namespace: NamespaceName, now = Date.now()): boolean {
  return grants.some((grant) => grant.kind === "CATEGORY" && grant.status === "ACTIVE"
    && (!grant.expiresAt || Date.parse(grant.expiresAt) > now)
    && typeof grant.binding.category === "string"
    && CATEGORY_NAMESPACES[grant.binding.category as CheckCategory]?.has(namespace));
}

export function gateCapabilities(helper: HelperCapabilitiesV2, grants: readonly TaskGrant[]): EffectiveCapabilities {
  if (helper.protocolVersion !== PROTOCOL_VERSION || helper.manifestVersion !== MANIFEST_VERSION) {
    throw new SecurityError("UNSUPPORTED_ENVIRONMENT", `Helper v2 协议不兼容：protocol=${helper.protocolVersion}, manifest=${helper.manifestVersion}`);
  }
  const active = grants.filter((grant) => grant.status === "ACTIVE" && (!grant.expiresAt || Date.parse(grant.expiresAt) > Date.now()));
  const anomalies: string[] = [];
  const namespaces: EffectiveCapabilities["namespaces"] = {};
  for (const [rawName, advertised] of Object.entries(helper.namespaces)) {
    const name = rawName as NamespaceName;
    const manifest = PROTOCOL_MANIFEST.namespaces[name];
    if (!manifest || name === "task_ioc") { anomalies.push(`helper_advertised_unknown_namespace:${rawName}`); continue; }
    if (!categoryGrantAllowsNamespace(active, name)) continue;
    const fields = new Set(advertised.fields.filter((field) => {
      if (manifest.fields[field]) return true;
      anomalies.push(`helper_advertised_unknown_field:${name}.${field}`);
      return false;
    }));
    const relations = new Set(advertised.relations.filter((relation) => {
      if (manifest.relations.includes(relation)) return true;
      anomalies.push(`helper_advertised_unknown_relation:${name}.${relation}`);
      return false;
    }));
    const verbs = new Set((advertised.verbs ?? []).filter((verb) => {
      if (["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"].includes(verb) && helper.verbs.includes(verb)) return true;
      anomalies.push(`helper_advertised_unknown_verb:${name}.${verb}`);
      return false;
    }));
    namespaces[name] = { fields, relations, verbs };
  }
  return {
    namespaces,
    matchers: new Set(helper.matchers.filter((value) => ["literal", "re2", "yara"].includes(value))),
    probes: new Set(helper.probes.filter((value) => ["jvm.tomcat.inventory", "jvm.class.inspect"].includes(value))),
    verbs: new Set(helper.verbs.filter((value) => ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"].includes(value))),
    limits: {
      maxObjects: Math.min(helper.limits.maxObjects, PROTOCOL_MANIFEST.hardLimits.enumerateLimit!),
      maxOutputBytes: Math.min(helper.limits.maxOutputBytes, 1_572_864),
      maxReadBytes: Math.min(helper.limits.maxReadBytes, PROTOCOL_MANIFEST.hardLimits.readBytes!),
      maxCollectBytes: Math.min(helper.limits.maxCollectBytes, PROTOCOL_MANIFEST.hardLimits.collectBytes!),
    },
    protocolAnomalies: anomalies,
  };
}
