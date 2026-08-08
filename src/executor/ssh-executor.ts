import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Client, type ClientChannel, type ConnectConfig } from "ssh2";
import { InvalidArgumentError, PermissionDeniedError, SecurityError, TargetUnavailableError, ToolTimeoutError } from "../common/errors.js";
import type { TargetConfig } from "../domain/types.js";
import type { HostExecutor, HostOperation, HostOperationOutput, HostOperationRequest } from "./operations.js";

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const SAFE_HELPER_PATH = /^\/[A-Za-z0-9_./-]+$/;
const HOST_OPERATIONS = new Set<HostOperation>([
  "get_host_info", "list_processes", "discover_web_roots", "find_recent_web_files", "yara_scan_files",
  "inspect_script_file", "search_web_access_log", "collect_file", "list_java_processes", "detect_java_container",
  "run_tomcat_probe", "search_class_on_disk", "list_privileged_accounts", "inspect_account",
  "inspect_authorized_keys", "get_login_history", "get_action_receipt", "quarantine_file", "disable_account",
  "list_cron_entries", "list_systemd_units", "list_ssh_persistence", "list_shell_startup_files",
  "inspect_persistence_item", "find_related_processes", "list_process_connections",
  "collect_persistence_artifact",
]);

interface HelperEnvelope<T> {
  ok: boolean;
  result?: T;
  error?: { code?: string; message?: string };
}

export function sshFingerprint(key: Buffer): string {
  return `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}`;
}

export class SSHExecutor implements HostExecutor {
  private client: Client | undefined;
  private connecting: Promise<Client> | undefined;

  constructor(
    private readonly target: TargetConfig,
    private readonly helperPath: string,
    private readonly defaultTimeoutMs = 30_000,
  ) {
    if (!SAFE_HELPER_PATH.test(helperPath) || helperPath.includes("..")) {
      throw new InvalidArgumentError("helperPath 必须是无目录穿越的绝对路径");
    }
  }

  async invoke<T extends HostOperation>(
    request: HostOperationRequest<T>,
    signal?: AbortSignal,
  ): Promise<HostOperationOutput<T>> {
    if (!HOST_OPERATIONS.has(request.operation)) throw new InvalidArgumentError("未知 HostOperation");
    const client = await this.connect(signal);
    const command = `sudo -n -- ${this.helperPath} ${request.operation}`;
    const payload = JSON.stringify({ ...request.params, ...(request.actionId ? { actionId: request.actionId } : {}) });
    const raw = await this.exec(client, command, payload, request.timeoutMs ?? this.defaultTimeoutMs, signal);
    let envelope: HelperEnvelope<HostOperationOutput<T>>;
    try {
      envelope = JSON.parse(raw) as HelperEnvelope<HostOperationOutput<T>>;
    } catch (error) {
      throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "目标辅助程序返回了无效 JSON", { preview: raw.slice(0, 512) }, { cause: error });
    }
    if (!envelope.ok || envelope.result === undefined) {
      const code = envelope.error?.code ?? "UNSUPPORTED_ENVIRONMENT";
      const message = envelope.error?.message ?? "目标操作失败";
      if (code === "PERMISSION_DENIED") throw new PermissionDeniedError(message);
      throw new SecurityError(code as never, message);
    }
    return envelope.result;
  }

  async close(): Promise<void> {
    this.client?.end();
    this.client = undefined;
    this.connecting = undefined;
  }

  private async connect(signal?: AbortSignal): Promise<Client> {
    if (this.client) return this.client;
    if (this.connecting) return this.connecting;
    this.connecting = (async () => {
      const [privateKey, knownHosts] = await Promise.all([
        readFile(this.target.privateKeyPath),
        readFile(this.target.knownHostsPath, "utf8"),
      ]);
      if (!knownHosts.includes(this.target.hostFingerprint)) {
        throw new SecurityError("INVALID_TARGET", "known_hosts 中不存在配置的目标指纹");
      }
      const client = new Client();
      const config: ConnectConfig = {
        host: this.target.host,
        port: this.target.port,
        username: this.target.username,
        privateKey,
        readyTimeout: this.defaultTimeoutMs,
        hostVerifier: (key: Buffer) => Buffer.isBuffer(key) && sshFingerprint(key) === this.target.hostFingerprint,
      };
      await new Promise<void>((resolve, reject) => {
        const abort = () => { client.end(); reject(new TargetUnavailableError("SSH 连接已中止")); };
        signal?.addEventListener("abort", abort, { once: true });
        client.once("ready", () => { signal?.removeEventListener("abort", abort); resolve(); });
        client.once("error", (error) => { signal?.removeEventListener("abort", abort); reject(new TargetUnavailableError(`SSH 连接失败: ${error.message}`, { cause: error })); });
        client.connect(config);
      });
      this.client = client;
      client.once("close", () => { this.client = undefined; this.connecting = undefined; });
      return client;
    })();
    try { return await this.connecting; } finally { this.connecting = undefined; }
  }

  private exec(client: Client, command: string, stdin: string, timeoutMs: number, signal?: AbortSignal): Promise<string> {
    return new Promise((resolve, reject) => {
      let channel: ClientChannel | undefined;
      let stdout = Buffer.alloc(0);
      let stderr = Buffer.alloc(0);
      let settled = false;
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        if (error) reject(error); else resolve(stdout.toString("utf8"));
      };
      const abort = () => { channel?.close(); finish(new SecurityError("RECOVERY_UNCERTAIN", "远程操作被中止，执行状态需要恢复确认")); };
      const timer = setTimeout(() => { channel?.close(); finish(new ToolTimeoutError(`远程操作超过 ${timeoutMs}ms`)); }, timeoutMs);
      signal?.addEventListener("abort", abort, { once: true });
      client.exec(command, (error, stream) => {
        if (error) { finish(new TargetUnavailableError(`无法启动远程辅助程序: ${error.message}`, { cause: error })); return; }
        channel = stream;
        stream.on("data", (data: Buffer) => {
          stdout = Buffer.concat([stdout, data]);
          if (stdout.length > MAX_OUTPUT_BYTES) {
            stream.close();
            finish(new SecurityError("UNSUPPORTED_ENVIRONMENT", "目标输出超过 2 MiB 限制"));
          }
        });
        stream.stderr.on("data", (data: Buffer) => { stderr = Buffer.concat([stderr, data]).subarray(0, MAX_OUTPUT_BYTES); });
        stream.once("close", (code: number) => {
          if (code !== 0 && stdout.length === 0) finish(new SecurityError("UNSUPPORTED_ENVIRONMENT", `目标辅助程序退出码 ${code}: ${stderr.toString("utf8").slice(0, 1000)}`));
          else finish();
        });
        stream.end(stdin);
      });
    });
  }
}
