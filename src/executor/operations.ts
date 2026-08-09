export interface HostCapabilities {
  protocolVersion: number;
  helper: { name: string; version: string };
  platform: { system: string; release: string; architecture: string; python: string };
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
    input: { pid: number; maxConnections: number } & Partial<StableProcessRequest>;
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
