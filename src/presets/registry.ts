import type { PresetDefinition } from "./types.js";

export const PRESET_REGISTRY: readonly PresetDefinition[] = [
  {
    presetId: "webshell-baseline", version: "2.2.0", category: "webshell",
    requiredCapabilities: [{ namespace: "web_stack", verb: "enumerate" }, { namespace: "web_root", verb: "enumerate" }, { namespace: "file", verb: "enumerate" }, { namespace: "log_source", verb: "enumerate" }],
    steps: [
      { stepId: "web-stack", verb: "enumerate", params: { namespace: "web_stack", fields: ["kind", "instanceId", "pid", "configPaths"], limit: 100 }, required: true },
      { stepId: "web-root", verb: "enumerate", params: { namespace: "web_root", fields: ["mountId", "device", "inode", "path", "server"], limit: 200 }, required: true },
      { stepId: "web-candidate-file", verb: "enumerate", params: { namespace: "file", fields: ["mountId", "device", "inode", "path", "size", "mtime", "contentClass"], limit: 500, predicate: { op: "gte", field: "mtime", value: "1970-01-01T00:00:00.000Z" } }, required: true },
      { stepId: "web-log-sources", verb: "enumerate", params: { namespace: "log_source", fields: ["sourceId", "generation", "kind", "path"], limit: 200 }, required: true },
    ],
    coverageCriteria: [{ criterion: "web-stack-and-roots", stepIds: ["web-stack", "web-root"] }, { criterion: "candidate-files", stepIds: ["web-candidate-file"] }, { criterion: "web-log-sources", stepIds: ["web-log-sources"] }],
  },
  {
    presetId: "java-memory-baseline", version: "2.2.0", category: "java_memory_shell",
    requiredCapabilities: [{ namespace: "jvm", verb: "enumerate" }, { namespace: "jvm", verb: "probe" }],
    steps: [
      { stepId: "jvm-discovery", verb: "enumerate", params: { namespace: "jvm", fields: ["bootId", "pid", "startTicks", "command", "attachSupported", "container"], limit: 100 }, required: true },
      { stepId: "tomcat-inventory", verb: "probe", params: { probeKind: "jvm.tomcat.inventory", parameters: {} }, required: true },
      { stepId: "jvm-class-inspect", verb: "probe", params: { probeKind: "jvm.class.inspect", parameters: {} }, required: true },
    ],
    coverageCriteria: [{ criterion: "jvm-discovery", stepIds: ["jvm-discovery"] }, { criterion: "tomcat-inventory", stepIds: ["tomcat-inventory"] }, { criterion: "class-integrity", stepIds: ["jvm-class-inspect"] }],
  },
  {
    presetId: "account-baseline", version: "2.1.0", category: "backdoor_account",
    requiredCapabilities: [{ namespace: "account", verb: "enumerate", fields: ["uid", "username", "gid", "shell", "home", "locked"] }, { namespace: "ssh_key", verb: "enumerate" }, { namespace: "auth_event", verb: "enumerate" }],
    steps: [
      { stepId: "account-db", verb: "enumerate", params: { namespace: "account", fields: ["uid", "username", "gid", "shell", "home", "groups", "locked"], limit: 500 }, required: true },
      { stepId: "authorized-keys", verb: "enumerate", params: { namespace: "ssh_key", fields: ["fingerprint", "ownerUid", "type", "comment", "sourceFile"], limit: 500 }, required: true },
      { stepId: "account-auth-events", verb: "enumerate", params: { namespace: "auth_event", fields: ["sourceId", "cursor", "timestamp", "eventType", "username", "sourceAddress", "program", "success"], limit: 500, sinceHours: 168 }, required: true },
    ],
    coverageCriteria: [{ criterion: "account-db", stepIds: ["account-db"] }, { criterion: "privileged-groups", stepIds: ["account-db"] }, { criterion: "ssh-trust", stepIds: ["authorized-keys"] }, { criterion: "login-history", stepIds: ["account-auth-events"] }],
  },
  {
    presetId: "persistence-baseline", version: "2.1.0", category: "linux_persistence",
    requiredCapabilities: [{ namespace: "cron_entry", verb: "enumerate" }, { namespace: "unit", verb: "enumerate" }, { namespace: "persistence", verb: "enumerate" }],
    steps: [
      { stepId: "cron-source", verb: "enumerate", params: { namespace: "cron_entry", fields: ["source", "line", "digest", "schedule", "user", "command"], limit: 500 }, required: true },
      { stepId: "unit-source", verb: "enumerate", params: { namespace: "unit", fields: ["name", "fragmentDigest", "path", "enabled", "active", "execStart", "user"], limit: 500 }, required: true },
      { stepId: "extended-source", verb: "enumerate", params: { namespace: "persistence", fields: ["kind", "sourceDigest", "source", "user", "command", "enabled"], limit: 500 }, required: true },
      { stepId: "ssh-persistence", verb: "enumerate", params: { namespace: "persistence", fields: ["kind", "sourceDigest", "source", "user", "command", "enabled"], predicate: { op: "eq", field: "kind", value: "ssh" }, limit: 500 }, required: true },
      { stepId: "shell-loader-persistence", verb: "enumerate", params: { namespace: "persistence", fields: ["kind", "sourceDigest", "source", "user", "command", "enabled"], predicate: { op: "in", field: "kind", value: ["shell", "extended"] }, limit: 500 }, required: true },
    ],
    coverageCriteria: [{ criterion: "cron", stepIds: ["cron-source"] }, { criterion: "systemd", stepIds: ["unit-source"] }, { criterion: "ssh", stepIds: ["ssh-persistence"] }, { criterion: "shell-and-loader", stepIds: ["shell-loader-persistence"] }, { criterion: "extended", stepIds: ["extended-source"] }],
  },
  {
    presetId: "linux-triage-baseline", version: "2.2.0", category: "linux_intrusion_triage",
    requiredCapabilities: [{ namespace: "process", verb: "enumerate" }, { namespace: "socket", verb: "enumerate" }, { namespace: "auth_event", verb: "enumerate" }, { namespace: "exec_event", verb: "enumerate" }, { namespace: "module", verb: "enumerate" }, { namespace: "package", verb: "enumerate" }],
    steps: [
      { stepId: "process-snapshot", verb: "enumerate", params: { namespace: "process", fields: ["bootId", "pid", "startTicks", "ppid", "uid", "username", "comm", "exe", "exeInode", "exeSha256", "state", "startedAt"], limit: 500 }, required: true },
      { stepId: "socket-snapshot", verb: "enumerate", params: { namespace: "socket", fields: ["protocol", "localAddress", "localPort", "remoteAddress", "remotePort", "state", "inode", "pid"], limit: 500 }, required: true },
      { stepId: "auth-events", verb: "enumerate", params: { namespace: "auth_event", fields: ["sourceId", "cursor", "timestamp", "eventType", "username", "sourceAddress", "program", "success"], limit: 500, sinceHours: 24 }, required: true },
      { stepId: "exec-events", verb: "enumerate", params: { namespace: "exec_event", fields: ["sourceId", "cursor", "timestamp", "pid", "uid", "executable", "arguments", "cwd"], limit: 500, sinceHours: 24 }, required: true },
      { stepId: "kernel-modules", verb: "enumerate", params: { namespace: "module", fields: ["name", "address", "size", "path"], limit: 500 }, required: true },
      { stepId: "package-baseline", verb: "enumerate", params: { namespace: "package", fields: ["manager", "name", "version", "architecture"], limit: 500 }, required: true },
    ],
    coverageCriteria: [{ criterion: "volatile-state", stepIds: ["process-snapshot", "socket-snapshot"] }, { criterion: "event-sources", stepIds: ["auth-events", "exec-events"] }, { criterion: "kernel-modules", stepIds: ["kernel-modules"] }, { criterion: "package-baseline", stepIds: ["package-baseline"] }],
  },
] as const;

export function selectedPresets(categories: readonly string[]): PresetDefinition[] {
  const selected = new Set(categories);
  return PRESET_REGISTRY.filter((preset) => selected.has(preset.category));
}
