import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Client, type ClientChannel, type ConnectConfig, type SFTPWrapper } from "ssh2";
import { InvalidArgumentError, PermissionDeniedError, SecurityError, TargetUnavailableError, ToolTimeoutError } from "../common/errors.js";
import type { TargetConfig } from "../domain/types.js";
import type { ArtifactTransferResult, HostExecutor, HostOperation, HostOperationOutput, HostOperationRequest, RemoteArtifact } from "./operations.js";
import { evaluateKnownHosts } from "./ssh-host-key-service.js";
import { effectiveHostOperationTimeout } from "./timeout-context.js";

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 100 * 1024 * 1024;
const ARTIFACT_TOKEN = /^[a-f0-9]{64}$/;
const ARTIFACT_ROOT = "/var/lib/huntwarden/artifacts";
const ARTIFACT_CHUNK_BYTES = 256 * 1024;
const SAFE_HELPER_PATH = /^\/[A-Za-z0-9_./-]+$/;
const HOST_OPERATIONS = new Set<HostOperation>([
  "get_capabilities", "get_host_info", "list_processes", "discover_web_roots", "find_recent_web_files", "yara_scan_files",
  "inspect_script_file", "search_web_access_log", "collect_file", "list_java_processes", "detect_java_container",
  "run_tomcat_probe", "search_class_on_disk", "list_privileged_accounts", "inspect_account",
  "inspect_authorized_keys", "get_login_history", "get_action_receipt", "quarantine_file", "disable_account",
  "list_cron_entries", "list_systemd_units", "list_ssh_persistence", "list_shell_startup_files",
  "inspect_persistence_item", "find_related_processes", "list_process_connections",
  "collect_persistence_artifact", "release_artifact",
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
    const timeoutMs = effectiveHostOperationTimeout(request.timeoutMs, this.defaultTimeoutMs);
    const raw = await this.exec(client, command, payload, timeoutMs, signal);
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

  async downloadArtifact(
    artifact: RemoteArtifact,
    onChunk: (chunk: Buffer) => void | Promise<void>,
    signal?: AbortSignal,
    timeoutMs?: number,
  ): Promise<ArtifactTransferResult> {
    if (!ARTIFACT_TOKEN.test(artifact.artifactToken)) throw new InvalidArgumentError("无效的 artifactToken");
    if (!Number.isSafeInteger(artifact.size) || artifact.size < 0 || artifact.size > MAX_ARTIFACT_BYTES) {
      throw new InvalidArgumentError("远程 Artifact 大小无效或超过限制");
    }
    if (!/^[a-f0-9]{64}$/.test(artifact.sha256)) throw new InvalidArgumentError("远程 Artifact SHA-256 无效");
    if (!Number.isFinite(Date.parse(artifact.expiresAt)) || Date.parse(artifact.expiresAt) <= Date.now()) {
      throw new SecurityError("RECOVERY_UNCERTAIN", "远程 Artifact 已过期");
    }

    const effectiveTimeout = effectiveHostOperationTimeout(timeoutMs, this.defaultTimeoutMs);
    const timeoutController = new AbortController();
    const timer = setTimeout(() => timeoutController.abort(new ToolTimeoutError(`Artifact 传输超过 ${effectiveTimeout}ms`)), effectiveTimeout);
    const transferSignal = signal ? AbortSignal.any([signal, timeoutController.signal]) : timeoutController.signal;
    try {
      const client = await this.connect(transferSignal);
      const result = await this.readArtifactBySftp(client, artifact, onChunk, transferSignal);
      if (result.size !== artifact.size || result.sha256 !== artifact.sha256) {
        throw new SecurityError("EVIDENCE_COLLECTION", "SFTP Artifact 大小或 SHA-256 校验失败");
      }
      return result;
    } catch (error) {
      if (timeoutController.signal.aborted) throw timeoutController.signal.reason;
      if (signal?.aborted) throw new TargetUnavailableError("SFTP Artifact 传输已中止", { cause: error });
      throw error;
    } finally {
      clearTimeout(timer);
      await this.invoke({ operation: "release_artifact", params: { artifactToken: artifact.artifactToken }, timeoutMs: 10_000 }).catch(() => undefined);
    }
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
      const client = new Client();
      let hostKeyFailure: SecurityError | undefined;
      const config: ConnectConfig = {
        host: this.target.host,
        port: this.target.port,
        username: this.target.username,
        privateKey,
        readyTimeout: this.defaultTimeoutMs,
        hostVerifier: (key: Buffer) => {
          if (!Buffer.isBuffer(key) || sshFingerprint(key) !== this.target.hostFingerprint) {
            hostKeyFailure = new SecurityError("INVALID_TARGET", "目标 Host Key 与任务绑定指纹不一致");
            return false;
          }
          const trust = evaluateKnownHosts(knownHosts, this.target.host, this.target.port, [], key);
          if (trust.trustStatus !== "TRUSTED") {
            hostKeyFailure = new SecurityError("INVALID_TARGET", trust.trustStatus === "REVOKED"
              ? "目标 Host Key 已在 known_hosts 中撤销"
              : trust.trustStatus === "CHANGED"
                ? "目标 Host Key 与 known_hosts 中的主机绑定冲突"
                : "known_hosts 中没有当前 host + port 的可信 Host Key");
            return false;
          }
          return true;
        },
      };
      await new Promise<void>((resolve, reject) => {
        const abort = () => { client.end(); reject(new TargetUnavailableError("SSH 连接已中止")); };
        signal?.addEventListener("abort", abort, { once: true });
        client.once("ready", () => { signal?.removeEventListener("abort", abort); resolve(); });
        client.once("error", (error) => { signal?.removeEventListener("abort", abort); reject(hostKeyFailure ?? new TargetUnavailableError(`SSH 连接失败: ${error.message}`, { cause: error })); });
        client.connect(config);
      });
      this.client = client;
      client.once("close", () => { this.client = undefined; this.connecting = undefined; });
      return client;
    })();
    try { return await this.connecting; } finally { this.connecting = undefined; }
  }

  private async readArtifactBySftp(
    client: Client,
    artifact: RemoteArtifact,
    onChunk: (chunk: Buffer) => void | Promise<void>,
    signal: AbortSignal,
  ): Promise<ArtifactTransferResult> {
    const sftp = await new Promise<SFTPWrapper>((resolve, reject) => {
      signal.throwIfAborted();
      client.sftp((error, value) => error ? reject(new TargetUnavailableError(`无法启动 SFTP: ${error.message}`, { cause: error })) : resolve(value));
    });
    const abort = () => sftp.end();
    signal.addEventListener("abort", abort, { once: true });
    let handle: Buffer | undefined;
    try {
      const remotePath = `${ARTIFACT_ROOT}/${artifact.artifactToken}.artifact`;
      handle = await new Promise<Buffer>((resolve, reject) => {
        sftp.open(remotePath, "r", (error, value) => error ? reject(new SecurityError("EVIDENCE_COLLECTION", `无法打开远程 Artifact: ${error.message}`, {}, { cause: error })) : resolve(value));
      });
      const digest = createHash("sha256");
      let position = 0;
      while (position < artifact.size) {
        signal.throwIfAborted();
        const requested = Math.min(ARTIFACT_CHUNK_BYTES, artifact.size - position);
        const buffer = Buffer.allocUnsafe(requested);
        const bytesRead = await new Promise<number>((resolve, reject) => {
          sftp.read(handle!, buffer, 0, requested, position, (error, count) => error ? reject(new SecurityError("EVIDENCE_COLLECTION", `读取远程 Artifact 失败: ${error.message}`, {}, { cause: error })) : resolve(count));
        });
        if (bytesRead <= 0) throw new SecurityError("EVIDENCE_COLLECTION", "远程 Artifact 在预期大小之前结束");
        const chunk = buffer.subarray(0, bytesRead);
        digest.update(chunk);
        await onChunk(chunk);
        position += bytesRead;
      }
      return { sha256: digest.digest("hex"), size: position };
    } finally {
      signal.removeEventListener("abort", abort);
      if (handle) await new Promise<void>((resolve) => sftp.close(handle!, () => resolve())).catch(() => undefined);
      sftp.end();
    }
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
