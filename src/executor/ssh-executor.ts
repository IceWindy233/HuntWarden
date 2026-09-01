import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Client, type ClientChannel, type ConnectConfig, type SFTPWrapper } from "ssh2";
import { InvalidArgumentError, SecurityError, TargetUnavailableError, ToolTimeoutError } from "../common/errors.js";
import type { TargetConfig } from "../domain/types.js";
import type { ArtifactTransferResult, RemoteArtifact } from "./artifacts.js";
import { evaluateKnownHosts } from "./ssh-host-key-service.js";
import { effectiveDeadlineTimeout } from "./deadline-timeout.js";
import { FORENSIC_VERBS, MAINTENANCE_VERBS, type ForensicVerb, type MaintenanceVerb, type ProtocolV2Executor } from "./protocol-v2-executor.js";
import { MANIFEST_VERSION, PROTOCOL_VERSION, type HelperCapabilitiesV2, type WireRequest, type WireResponse } from "../protocol-v2/types.js";
import { parseWireResponse } from "../protocol-v2/wire.js";

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
/** 目标端 helper 自身的输出预算（host-helper MAX_OUTPUT_BYTES），仅用于错误文案说明两级预算的关系。 */
const HELPER_OUTPUT_BUDGET_BYTES = 1_572_864;
/** 留给 SSH 往返与 envelope 传输的余量，使 helper 先到期返回 partial，而不是被控制端切断连接。 */
const HELPER_DEADLINE_HEADROOM_MS = 5_000;
const MIN_HELPER_DEADLINE_MS = 1_000;
const MAX_HELPER_DEADLINE_MS = 600_000;
const MAX_ARTIFACT_BYTES = 100 * 1024 * 1024;
const ARTIFACT_TOKEN = /^[a-f0-9]{64}$/;
/**
 * Artifact spool 由目标端 helper 固定在 `ARTIFACT_DIR`（host-helper/huntwarden_helper.py），
 * 两端必须一致，因此这是协议常量而不是可配置项：配置化只会让控制端与 helper 分叉。
 */
const ARTIFACT_ROOT = "/var/lib/huntwarden/artifacts";
const ARTIFACT_CHUNK_BYTES = 256 * 1024;
const SAFE_HELPER_PATH = /^\/[A-Za-z0-9_./-]+$/;
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** helper 侧墙钟预算：控制端超时之前 helper 应先到期并返回已采集部分。 */
export function helperDeadline(timeoutMs: number): number {
  return Math.max(MIN_HELPER_DEADLINE_MS, Math.min(MAX_HELPER_DEADLINE_MS, timeoutMs - HELPER_DEADLINE_HEADROOM_MS));
}

export function validateRemoteArtifactMetadata(artifact: RemoteArtifact): void {
  if (!ARTIFACT_TOKEN.test(artifact.artifactToken)) throw new InvalidArgumentError("无效的 artifactToken");
  if (!Number.isSafeInteger(artifact.size) || artifact.size < 0 || artifact.size > MAX_ARTIFACT_BYTES) {
    throw new InvalidArgumentError("远程 Artifact 大小无效或超过限制");
  }
  if (!/^[a-f0-9]{64}$/.test(artifact.sha256)) throw new InvalidArgumentError("远程 Artifact SHA-256 无效");
  if (!Number.isFinite(Date.parse(artifact.expiresAt))) throw new InvalidArgumentError("远程 Artifact expiresAt 无效");
}

export function sshFingerprint(key: Buffer): string {
  return `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}`;
}

export class SSHExecutor implements ProtocolV2Executor {
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

  async getCapabilitiesV2(signal?: AbortSignal): Promise<HelperCapabilitiesV2> {
    const client = await this.connect(signal);
    const requestId = `PRECHECK-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const timeoutMs = Math.min(this.defaultTimeoutMs, 30_000);
    const deadlineMs = helperDeadline(timeoutMs);
    const raw = await this.exec(client, `sudo -n -- ${this.helperPath} capabilities`, JSON.stringify({
      protocolVersion: PROTOCOL_VERSION, requestId, epochId: "PRECHECK", deadlineMs,
      reservation: { reservationId: "PRECHECK", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: deadlineMs, probeCalls: 0 } },
      params: {},
    }), timeoutMs, deadlineMs, signal);
    let envelope: unknown;
    try { envelope = JSON.parse(raw); } catch (cause) { throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 capabilities 返回无效 JSON", undefined, { cause }); }
    if (!isRecord(envelope) || envelope.protocolVersion !== PROTOCOL_VERSION || envelope.requestId !== requestId || envelope.status !== "SUCCESS" || !isRecord(envelope.capabilities)) {
      throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 capabilities Envelope 不符合协议");
    }
    const capabilities = envelope.capabilities as unknown as HelperCapabilitiesV2;
    if (capabilities.protocolVersion !== PROTOCOL_VERSION || capabilities.manifestVersion !== MANIFEST_VERSION || !Array.isArray(capabilities.verbs)) {
      throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "Helper v2 capabilities 与控制端 Manifest 不兼容");
    }
    return capabilities;
  }

  async invokeV2(verb: ForensicVerb, request: WireRequest, signal?: AbortSignal): Promise<WireResponse> {
    if (!(FORENSIC_VERBS as readonly string[]).includes(verb)) throw new InvalidArgumentError("未知 v2 forensic verb");
    if (request.protocolVersion !== PROTOCOL_VERSION) throw new InvalidArgumentError("v2 Request protocolVersion 必须为 2");
    const client = await this.connect(signal);
    const timeoutMs = effectiveDeadlineTimeout(request.deadlineMs + HELPER_DEADLINE_HEADROOM_MS, this.defaultTimeoutMs);
    const raw = await this.exec(client, `sudo -n -- ${this.helperPath} ${verb}`, JSON.stringify(request), timeoutMs, request.deadlineMs, signal);
    return parseWireResponse(raw, request.requestId);
  }

  async invokeMaintenanceV2(verb: MaintenanceVerb, request: WireRequest, signal?: AbortSignal): Promise<Record<string, unknown>> {
    if (!(MAINTENANCE_VERBS as readonly string[]).includes(verb)) throw new InvalidArgumentError("未知 v2 maintenance verb");
    if (request.protocolVersion !== PROTOCOL_VERSION) throw new InvalidArgumentError("v2 Request protocolVersion 必须为 2");
    const client = await this.connect(signal);
    const timeoutMs = effectiveDeadlineTimeout(request.deadlineMs + HELPER_DEADLINE_HEADROOM_MS, this.defaultTimeoutMs);
    const raw = await this.exec(client, `sudo -n -- ${this.helperPath} ${verb}`, JSON.stringify(request), timeoutMs, request.deadlineMs, signal);
    const parsed = parseWireResponse(raw, request.requestId);
    if (parsed.status === "ERROR") throw new SecurityError("RECOVERY_UNCERTAIN", parsed.error.message ?? parsed.error.code, { protocolCode: parsed.error.code });
    let envelope: unknown;
    try { envelope = JSON.parse(raw); } catch { throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "v2 maintenance 返回无效 JSON"); }
    if (!isRecord(envelope) || !isRecord(envelope.maintenanceResult)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "v2 maintenance 缺少 maintenanceResult");
    return envelope.maintenanceResult;
  }

  async downloadArtifact(
    artifact: RemoteArtifact,
    onChunk: (chunk: Buffer) => void | Promise<void>,
    signal?: AbortSignal,
    timeoutMs?: number,
  ): Promise<ArtifactTransferResult> {
    validateRemoteArtifactMetadata(artifact);
    // expiresAt 由目标主机时钟产生，不能与控制端墙钟直接比较；真实主机可能存在较大时钟漂移。
    // collect 返回后立即进入本方法，安全边界由随机 token、SFTP 文件存在性、size/SHA-256 校验和
    // finally 中的 artifact_release 共同保证。把远端绝对时间当作本地授权边界会误拒刚生成的制品。

    const effectiveTimeout = effectiveDeadlineTimeout(timeoutMs, this.defaultTimeoutMs);
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
      await this.releaseArtifactV2(artifact.artifactToken).catch(() => undefined);
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

  private async releaseArtifactV2(artifactToken: string): Promise<void> {
    const requestId = `ARTIFACT-RELEASE-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const timeoutMs = 10_000;
    const deadlineMs = helperDeadline(timeoutMs);
    await this.invokeMaintenanceV2("artifact_release", {
      protocolVersion: PROTOCOL_VERSION,
      requestId,
      epochId: "MAINTENANCE",
      deadlineMs,
      reservation: { reservationId: requestId, estimate: { remoteCalls: 1, nodes: 1, bytes: 1024, wallTimeMs: deadlineMs, probeCalls: 0 } },
      params: { artifactToken },
    });
  }

  private exec(client: Client, command: string, stdin: string, timeoutMs: number, helperDeadlineMs: number, signal?: AbortSignal): Promise<string> {
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
      const timer = setTimeout(() => {
        channel?.close();
        finish(new ToolTimeoutError(
          `远程操作超过 ${timeoutMs}ms，已关闭 SSH channel。目标端 helper 的墙钟预算为 ${helperDeadlineMs}ms，`
          + "正常情况下 v2 helper 会先到期并返回带 CoverageGap 的 PARTIAL；未返回说明 helper 运行异常，"
          + "请在目标主机确认辅助程序状态后再重试。",
        ));
      }, timeoutMs);
      signal?.addEventListener("abort", abort, { once: true });
      client.exec(command, (error, stream) => {
        if (error) { finish(new TargetUnavailableError(`无法启动远程辅助程序: ${error.message}`, { cause: error })); return; }
        channel = stream;
        stream.on("data", (data: Buffer) => {
          stdout = Buffer.concat([stdout, data]);
          if (stdout.length > MAX_OUTPUT_BYTES) {
            stream.close();
            finish(new SecurityError("BUDGET_EXCEEDED",
              `目标输出超过 ${MAX_OUTPUT_BYTES} 字节协议硬顶。目标端 helper 自身有 ${HELPER_OUTPUT_BUDGET_BYTES} 字节（1.5 MiB）输出预算并会截断后置 partial，`
              + "因此触发硬顶说明目标端 helper 未启用输出预算或协议异常：请确认目标端 helper 版本，"
              + "并降低配置中的 triage.maxProcesses / triage.maxConnections / triage.maxFiles / triage.maxTimelineEvents 或缩小任务时间窗后重试。"
              + "本次结果已整体丢弃，这是数据量问题而不是目标能力缺失。",
              { limitBytes: MAX_OUTPUT_BYTES, helperBudgetBytes: HELPER_OUTPUT_BUDGET_BYTES }));
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
