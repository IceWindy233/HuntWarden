import { SecurityError } from "../common/errors.js";

/**
 * Helper 协议单一事实源。控制端只接受该版本的 Helper Envelope 与能力清单；
 * 目标端 `host-helper/huntwarden_helper.py` 的 `PROTOCOL_VERSION` 必须与此一致。
 */
export const REQUIRED_HELPER_PROTOCOL_VERSION = 1;

export interface HostCapabilities {
  protocolVersion: number;
  helper: { name: string; version: string };
  platform: {
    system: string;
    release: string;
    architecture: string;
    python: string;
    distribution?: {
      id: string;
      idLike: string[];
      name: string;
      prettyName: string;
      versionId: string;
      versionCodename: string;
      source: string;
    };
  };
  /** 目标主机时区：IANA 名（如 Asia/Shanghai），取不到时为 ±HH:MM 偏移。 */
  timezone: string;
  /** 目标主机相对 UTC 的偏移秒数，东为正。 */
  utcOffsetSeconds: number;
  /** 目标主机采集时刻，统一为带 Z 的 UTC ISO8601，用于评估与控制端的时间偏差。 */
  hostTimeUtc: string;
  operations: string[];
  artifactTransfer: { supported: boolean; protocolVersion: number; maxBytes: number };
  features: { yara: boolean; javaAttach: boolean; tomcatProbe: boolean };
  /** Backward-compatible booleans above are retained for existing planners. */
  featureStatus?: Record<string, {
    status: "SUPPORTED" | "PARTIAL" | "UNSUPPORTED" | "PERMISSION_DENIED";
    reason: string;
  }>;
  runtime?: {
    bootId?: string;
    initSystem: string;
    container: string;
    euid: number;
    currentUser: string;
    rootHelper: boolean;
  };
  securityContext?: {
    hidepid: string;
    pidNamespace: string;
    mountNamespace: string;
    selinux: string;
    apparmor: string;
  };
  partial: boolean;
  warnings: string[];
}

/**
 * 协议兼容闸门。`protocolVersion` 与 `helper.version` 是 helper 唯一的自述身份，
 * 不兼容时必须拒绝任务：字段漂移一旦被当作"目标缺能力"静默降级，PARTIAL 结论就不可信。
 */
export function assertCompatibleHelper(capabilities: HostCapabilities): void {
  const actual: unknown = capabilities.protocolVersion;
  if (typeof actual !== "number" || !Number.isInteger(actual)) {
    throw new SecurityError("UNSUPPORTED_ENVIRONMENT",
      `目标端 helper 未上报有效的协议版本（protocolVersion=${String(actual)}），期望 ${REQUIRED_HELPER_PROTOCOL_VERSION}。`
      + "请升级目标端 helper（host-helper/install-helper.sh）后重新发起任务。",
      { actualProtocolVersion: actual, expectedProtocolVersion: REQUIRED_HELPER_PROTOCOL_VERSION });
  }
  if (actual !== REQUIRED_HELPER_PROTOCOL_VERSION) {
    throw new SecurityError("UNSUPPORTED_ENVIRONMENT",
      `目标端 helper 协议版本不兼容：实际 ${actual}，期望 ${REQUIRED_HELPER_PROTOCOL_VERSION}。`
      + "请升级目标端 helper（host-helper/install-helper.sh）后重新发起任务。",
      { actualProtocolVersion: actual, expectedProtocolVersion: REQUIRED_HELPER_PROTOCOL_VERSION });
  }
  const version: unknown = capabilities.helper?.version;
  if (typeof version !== "string" || version.trim() === "") {
    throw new SecurityError("UNSUPPORTED_ENVIRONMENT",
      `目标端 helper 未上报版本号（helper.version=${String(version)}），视为协议不兼容（期望协议版本 ${REQUIRED_HELPER_PROTOCOL_VERSION}）。`
      + "请升级目标端 helper（host-helper/install-helper.sh）后重新发起任务。",
      { actualHelperVersion: version, expectedProtocolVersion: REQUIRED_HELPER_PROTOCOL_VERSION });
  }
}

export interface RemoteArtifact {
  artifactToken: string;
  sha256: string;
  size: number;
  expiresAt: string;
}

export interface CollectedArtifactOutput {
  sha256: string;
  size: number;
  artifact?: RemoteArtifact;
  /** Faux/legacy executors may still return inline data. SSH never does. */
  dataBase64?: string;
}

export interface ArtifactTransferResult {
  sha256: string;
  size: number;
}

export interface StableProcessIdentity {
  bootId: string;
  pid: number;
  startTicks: string;
  exeInode: string;
  exeSha256: string;
}

export interface PartialItemsOutput {
  items: Record<string, unknown>[];
  partial: boolean;
  warnings: string[];
}

export type StableProcessRequest = StableProcessIdentity;

export interface HostOperationMap {
  get_capabilities: { input: Record<string, never>; output: HostCapabilities };
  capture_volatile_snapshot: { input: { maxProcesses: number; maxConnections: number }; output: Record<string, unknown> & { processes: Record<string, unknown>[]; partial: boolean; warnings: string[] } };
  list_suspicious_processes: { input: { maxProcesses: number }; output: PartialItemsOutput };
  inspect_process_tree: { input: StableProcessRequest & { maxDepth: number; maxNodes: number }; output: PartialItemsOutput };
  inspect_process_fds: { input: StableProcessRequest & { maxItems: number }; output: PartialItemsOutput };
  inspect_process_memory_maps: { input: StableProcessRequest & { maxItems: number }; output: PartialItemsOutput };
  collect_process_executable: { input: StableProcessRequest & { maxBytes: number }; output: CollectedArtifactOutput & { process: StableProcessIdentity } };
  list_recent_executables: { input: { modifiedWithinHours: number; maxItems: number; maxFileSizeBytes: number }; output: PartialItemsOutput };
  list_privileged_files: { input: { maxItems: number }; output: PartialItemsOutput };
  verify_package_integrity: { input: { path: string; expectedInode: string; expectedSha256: string }; output: Record<string, unknown> & { partial: boolean; warnings: string[] } };
  inspect_dynamic_loader: { input: { maxItems: number }; output: PartialItemsOutput };
  query_auth_events: { input: { sinceHours: number; maxEvents: number }; output: PartialItemsOutput };
  query_exec_events: { input: { sinceHours: number; maxEvents: number }; output: PartialItemsOutput };
  build_incident_timeline: { input: { sinceHours: number; maxEvents: number }; output: PartialItemsOutput };
  get_host_info: { input: Record<string, never>; output: Record<string, unknown> };
  list_processes: { input: { pattern?: string }; output: Record<string, unknown>[] };
  inventory_web_stacks: { input: Record<string, never>; output: PartialItemsOutput & { binaries: Record<string, string | null>; configPaths: string[]; processes: Record<string, unknown>[] } };
  discover_effective_web_roots: { input: Record<string, never>; output: PartialItemsOutput };
  discover_web_roots: { input: Record<string, never>; output: { path: string; server: string }[] };
  list_recent_web_artifacts: {
    input: { roots: string[]; modifiedWithinHours: number; maxFiles: number; maxFileSizeBytes: number };
    output: PartialItemsOutput & { visited: number; skipped: number };
  };
  list_upload_temp_artifacts: {
    input: { modifiedWithinHours: number; maxFiles: number; maxFileSizeBytes: number };
    output: PartialItemsOutput & { visited: number; skipped: number; roots: string[] };
  };
  find_recent_web_files: {
    input: { roots: string[]; modifiedWithinHours: number; maxFiles: number; maxFileSizeBytes: number };
    output: Record<string, unknown>[];
  };
  inspect_web_runtime_config: { input: { root: string; maxItems: number }; output: PartialItemsOutput };
  correlate_web_requests: { input: { path: string; expectedSha256: string; maxEvents: number }; output: PartialItemsOutput };
  find_web_related_processes: { input: { path: string; expectedSha256: string; maxProcesses: number }; output: PartialItemsOutput };
  yara_scan_files: { input: { paths: string[]; rulePath: string }; output: Record<string, unknown>[] };
  inspect_script_file: { input: { path: string; maxBytes: number }; output: Record<string, unknown> };
  search_web_access_log: { input: { path: string; fileName: string; maxLines: number }; output: Record<string, unknown>[] };
  collect_file: { input: { path: string; maxBytes: number }; output: CollectedArtifactOutput };
  list_java_processes: { input: Record<string, never>; output: Record<string, unknown>[] };
  detect_java_container: { input: { pid: number }; output: Record<string, unknown> };
  run_tomcat_probe: {
    input: { pid: number; command: "list_components" | "inspect_class" | "dump_class"; className?: string };
    output: Record<string, unknown> & Partial<CollectedArtifactOutput>;
  };
  search_class_on_disk: { input: { pid: number; className: string }; output: Record<string, unknown> };
  list_privileged_accounts: { input: Record<string, never>; output: Record<string, unknown>[] };
  inspect_privilege_delegation: { input: { maxItems: number }; output: PartialItemsOutput };
  inspect_account: { input: { username: string }; output: Record<string, unknown> };
  inspect_ssh_trust_configuration: { input: Record<string, never>; output: PartialItemsOutput & { effective: Record<string, unknown>; trustFiles: Record<string, unknown>[] } };
  inspect_authorized_keys: { input: { username: string }; output: Record<string, unknown>[] };
  get_login_history: { input: { username: string; maxEntries: number }; output: Record<string, unknown>[] };
  list_cron_entries: { input: { maxItems: number; includeUserScope: boolean }; output: { items: Record<string, unknown>[]; partial: boolean; warnings: string[] } };
  list_systemd_units: { input: { maxItems: number; includeUserScope: boolean }; output: { items: Record<string, unknown>[]; partial: boolean; warnings: string[] } };
  list_extended_persistence: { input: { maxItems: number; includeUserScope: boolean }; output: { items: Record<string, unknown>[]; partial: boolean; warnings: string[] } };
  list_ssh_persistence: { input: { maxItems: number; includeUserScope: boolean }; output: { items: Record<string, unknown>[]; partial: boolean; warnings: string[]; sshdConfig: Record<string, unknown> } };
  list_shell_startup_files: { input: { maxItems: number; includeUserScope: boolean }; output: { items: Record<string, unknown>[]; partial: boolean; warnings: string[] } };
  inspect_persistence_item: { input: { kind: string; path: string; username?: string; expectedSha256?: string }; output: Record<string, unknown> };
  find_related_processes: { input: { kind: string; path: string; commandHint?: string; expectedSha256?: string; maxProcesses: number }; output: Record<string, unknown>[] };
  list_process_connections: {
    /** 必须携带完整稳定身份：裸 PID 查询存在 PID 复用风险。 */
    input: StableProcessRequest & { maxConnections: number };
    output: { items: Record<string, unknown>[]; partial: boolean; warnings: string[] };
  };
  collect_persistence_artifact: { input: { kind: string; path: string; expectedSha256: string; maxBytes: number }; output: CollectedArtifactOutput };
  release_artifact: { input: { artifactToken: string }; output: { released: boolean } };
  get_action_receipt: { input: { actionId: string }; output: Record<string, unknown> };
  quarantine_file: {
    input: { actionId: string; path: string; expectedSha256: string; quarantineRoot: string };
    output: Record<string, unknown>;
  };
  disable_account: { input: { actionId: string; username: string; executorUsername: string }; output: Record<string, unknown> };
}

export type HostOperation = keyof HostOperationMap;
export type HostOperationInput<T extends HostOperation> = HostOperationMap[T]["input"];
export type HostOperationOutput<T extends HostOperation> = HostOperationMap[T]["output"];

export interface HostOperationRequest<T extends HostOperation> {
  operation: T;
  params: HostOperationInput<T>;
  timeoutMs?: number;
  actionId?: string;
}

export interface HostExecutor {
  invoke<T extends HostOperation>(
    request: HostOperationRequest<T>,
    signal?: AbortSignal,
  ): Promise<HostOperationOutput<T>>;
  downloadArtifact(
    artifact: RemoteArtifact,
    onChunk: (chunk: Buffer) => void | Promise<void>,
    signal?: AbortSignal,
    timeoutMs?: number,
  ): Promise<ArtifactTransferResult>;
  close(): Promise<void>;
}
