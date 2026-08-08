export interface HostOperationMap {
  get_host_info: { input: Record<string, never>; output: Record<string, unknown> };
  list_processes: { input: { pattern?: string }; output: Record<string, unknown>[] };
  discover_web_roots: { input: Record<string, never>; output: { path: string; server: string }[] };
  find_recent_web_files: {
    input: { roots: string[]; modifiedWithinHours: number; maxFiles: number; maxFileSizeBytes: number };
    output: Record<string, unknown>[];
  };
  yara_scan_files: { input: { paths: string[]; rulePath: string }; output: Record<string, unknown>[] };
  inspect_script_file: { input: { path: string; maxBytes: number }; output: Record<string, unknown> };
  search_web_access_log: { input: { path: string; fileName: string; maxLines: number }; output: Record<string, unknown>[] };
  collect_file: { input: { path: string; maxBytes: number }; output: { dataBase64: string; sha256: string; size: number } };
  list_java_processes: { input: Record<string, never>; output: Record<string, unknown>[] };
  detect_java_container: { input: { pid: number }; output: Record<string, unknown> };
  run_tomcat_probe: {
    input: { pid: number; command: "list_components" | "inspect_class" | "dump_class"; className?: string };
    output: Record<string, unknown>;
  };
  search_class_on_disk: { input: { pid: number; className: string }; output: Record<string, unknown> };
  list_privileged_accounts: { input: Record<string, never>; output: Record<string, unknown>[] };
  inspect_account: { input: { username: string }; output: Record<string, unknown> };
  inspect_authorized_keys: { input: { username: string }; output: Record<string, unknown>[] };
  get_login_history: { input: { username: string; maxEntries: number }; output: Record<string, unknown>[] };
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
  close(): Promise<void>;
}
