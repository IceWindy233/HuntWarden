import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, copyFile, mkdir, open, readFile, readdir, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { basename, join, resolve, sep } from "node:path";
import { createDeterministicId, createId } from "../common/ids.js";
import { SecurityError } from "../common/errors.js";
import type { Evidence } from "../domain/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";

function safeName(value: string): string {
  return basename(value).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120) || "artifact.bin";
}

type EvidenceBinding = Pick<Evidence, "taskId" | "host" | "type" | "source" | "tool" | "toolCallId" | "metadata">;

function metadataEpoch(metadata?: Record<string, unknown>): string | undefined {
  return typeof metadata?.epochId === "string" ? metadata.epochId : undefined;
}

function evidenceSeed(input: EvidenceBinding): string {
  return `${input.taskId}:${metadataEpoch(input.metadata) ?? "LEGACY"}:${input.toolCallId}`;
}

function findBoundEvidence(runtime: RuntimeStore, input: EvidenceBinding): Evidence | undefined {
  if (!input.toolCallId) return undefined;
  const matches = runtime.listEvidence(input.taskId).filter((item) => item.toolCallId === input.toolCallId);
  if (matches.length > 1) throw new SecurityError("RECOVERY_UNCERTAIN", "同一 ToolCall 存在多份 Evidence，拒绝自动选择");
  const existing = matches[0];
  if (!existing) return undefined;
  const sameBinding = metadataEpoch(existing.metadata) === metadataEpoch(input.metadata)
    && existing.host === input.host
    && existing.type === input.type
    && existing.source === input.source
    && existing.tool === input.tool;
  if (!sameBinding) {
    throw new SecurityError("RECOVERY_UNCERTAIN", "ToolCall Evidence 已绑定其他 Epoch、主机、类型、来源或工具，拒绝复用");
  }
  return existing;
}

async function verifyExistingArtifact(existing: Evidence, expectedSha256?: string, expectedSize?: number): Promise<void> {
  if (!existing.storagePath || !existing.sha256) throw new SecurityError("EVIDENCE_COLLECTION", "幂等 Evidence 缺少落盘路径或摘要");
  if (expectedSha256 && existing.sha256 !== expectedSha256) throw new SecurityError("EVIDENCE_COLLECTION", "同一 ToolCall 的 Evidence 摘要冲突");
  const info = await stat(existing.storagePath);
  const actualSha256 = await hashFile(existing.storagePath);
  if (!info.isFile() || actualSha256 !== existing.sha256 || (expectedSize !== undefined && info.size !== expectedSize)) {
    throw new SecurityError("EVIDENCE_COLLECTION", "幂等 Evidence 文件完整性或大小校验失败");
  }
}
export interface EvidenceExportResult {
  directory: string;
  manifestPath: string;
  evidenceCount: number;
  artifactCount: number;
  manifestSha256: string;
}


export class EvidenceStore {
  constructor(
    private readonly baseDir: string,
    private readonly runtime: RuntimeStore,
    private readonly checkpoint?: (name: string) => void,
  ) {}

  async exportTask(taskId: string, destination: string): Promise<EvidenceExportResult> {
    const task = this.runtime.getTask(taskId);
    if (!task) throw new Error(`任务不存在: ${taskId}`);
    const root = resolve(this.baseDir);
    const directory = resolve(destination);
    if (directory === root || directory.startsWith(`${root}${sep}`)) throw new Error("Evidence 离线导出目录必须位于 HuntWarden 受管数据目录之外");
    try {
      await mkdir(directory, { mode: 0o700 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("Evidence 离线导出目录已存在，拒绝覆盖");
      throw error;
    }
    try {
      const artifactsDir = join(directory, "artifacts");
      const evidence = this.runtime.listEvidence(taskId).sort((left, right) => left.evidenceId.localeCompare(right.evidenceId));
      const records: Array<Record<string, unknown>> = [];
      let artifactCount = 0;
      for (const item of evidence) {
        let artifact: { path: string; bytes: number; sha256: string } | undefined;
        if (item.storagePath) {
          if (!item.sha256 || !/^[a-f0-9]{64}$/.test(item.sha256)) throw new Error(`Evidence ${item.evidenceId} 缺少有效 SHA-256`);
          const sourceInfo = await stat(item.storagePath);
          const sourceDigest = await hashFile(item.storagePath);
          if (!sourceInfo.isFile() || sourceDigest !== item.sha256) throw new Error(`Evidence ${item.evidenceId} 本地文件完整性校验失败`);
          if (artifactCount === 0) await mkdir(artifactsDir, { mode: 0o700 });
          const fileName = `${item.evidenceId}_${safeName(item.source)}`;
          const exportedPath = join(artifactsDir, fileName);
          await copyFile(item.storagePath, exportedPath, 1);
          await chmod(exportedPath, 0o600);
          if (await hashFile(exportedPath) !== sourceDigest) throw new Error(`Evidence ${item.evidenceId} 导出后摘要不一致`);
          artifact = { path: `artifacts/${fileName}`, bytes: sourceInfo.size, sha256: sourceDigest };
          artifactCount += 1;
        }
        records.push({
          evidenceId: item.evidenceId,
          taskId: item.taskId,
          host: item.host,
          type: item.type,
          source: item.source,
          collectedAt: item.collectedAt,
          tool: item.tool,
          ...(item.toolCallId ? { toolCallId: item.toolCallId } : {}),
          ...(item.sha256 ? { sha256: item.sha256 } : {}),
          ...(item.metadata ? { metadata: sanitizeExportValue(item.metadata) } : {}),
          ...(artifact ? { artifact } : {}),
        });
      }
      const manifestPath = join(directory, "EVIDENCE-MANIFEST.json");
      const manifest = {
        schemaVersion: 1,
        taskId,
        ...(task.activeEpochId ? { epochId: task.activeEpochId } : {}),
        exportedAt: new Date().toISOString(),
        evidenceCount: records.length,
        artifactCount,
        evidence: records,
      };
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
      const manifestSha256 = await hashFile(manifestPath);
      const checksums = [
        `${manifestSha256}  EVIDENCE-MANIFEST.json`,
        ...records.flatMap((record) => {
          const exported = record.artifact as { path: string; sha256: string } | undefined;
          return exported ? [`${exported.sha256}  ${exported.path}`] : [];
        }),
      ];
      await writeFile(join(directory, "SHA256SUMS"), `${checksums.join("\n")}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
      return { directory, manifestPath, evidenceCount: records.length, artifactCount, manifestSha256 };
    } catch (error) {
      await rm(directory, { recursive: true, force: true });
      throw error;
    }
  }

  async reconcileTask(taskId: string): Promise<{ verified: number; failed: string[]; orphanPaths: string[]; temporaryPaths: string[] }> {
    const taskDir = join(this.baseDir, "evidence", taskId);
    const evidence = this.runtime.listEvidence(taskId);
    const knownPaths = new Set(evidence.flatMap((item) => item.storagePath ? [item.storagePath] : []));
    const failed: string[] = [];
    let verified = 0;
    for (const item of evidence) {
      if (!item.storagePath) continue;
      try {
        const info = await stat(item.storagePath);
        const digest = await hashFile(item.storagePath);
        if (!info.isFile() || !item.sha256 || digest !== item.sha256) throw new Error("本地文件摘要与 Evidence 元数据不一致");
        this.runtime.putEvidence({ ...item, metadata: { ...item.metadata, artifactDigest: digest, artifactSize: info.size, integrityStatus: "VERIFIED", integrityCheckedAt: new Date().toISOString() } });
        verified += 1;
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        failed.push(item.evidenceId);
        this.runtime.putEvidence({ ...item, metadata: { ...item.metadata, complete: false, integrityStatus: "FAILED", integrityReason: reason, integrityCheckedAt: new Date().toISOString() } });
      }
    }
    let names: string[] = [];
    try { names = await readdir(taskDir); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    const paths = names.map((name) => join(taskDir, name));
    const temporaryPaths = paths.filter((path) => path.endsWith(".tmp") || /\.\d+\.tmp$/.test(path));
    const orphanPaths = paths.filter((path) => !temporaryPaths.includes(path) && !knownPaths.has(path));
    return { verified, failed, orphanPaths, temporaryPaths };
  }

  async putBuffer(input: {
    taskId: string; host: string; type: string; source: string; tool: string;
    data: Buffer; toolCallId?: string; metadata?: Record<string, unknown>;
  }): Promise<Evidence> {
    const expectedSha256 = createHash("sha256").update(input.data).digest("hex");
    const existing = findBoundEvidence(this.runtime, input);
    if (existing) {
      await verifyExistingArtifact(existing, expectedSha256, input.data.length);
      return existing;
    }
    const evidenceId = input.toolCallId
      ? createDeterministicId("evidence", evidenceSeed(input))
      : createId("evidence");
    const taskDir = join(this.baseDir, "evidence", input.taskId);
    await mkdir(taskDir, { recursive: true, mode: 0o700 });
    await chmod(taskDir, 0o700);
    const fileName = `${evidenceId}_${safeName(input.source)}`;
    const finalPath = join(taskDir, fileName);
    let alreadyWritten = false;
    try {
      const present = await readFile(finalPath);
      if (createHash("sha256").update(present).digest("hex") !== expectedSha256) throw new Error("同一 toolCallId 的 Evidence 内容冲突");
      alreadyWritten = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (!alreadyWritten) {
      const tempPath = `${finalPath}.${process.pid}.tmp`;
      const handle = await open(tempPath, "wx", 0o600);
      try {
        await handle.writeFile(input.data);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(tempPath, finalPath);
      this.checkpoint?.("evidence_file_written_before_metadata");
    }
    await chmod(finalPath, 0o600);
    const evidence: Evidence = {
      evidenceId,
      taskId: input.taskId,
      host: input.host,
      type: input.type,
      source: input.source,
      sha256: expectedSha256,
      collectedAt: new Date().toISOString(),
      tool: input.tool,
      ...(input.toolCallId ? { toolCallId: input.toolCallId } : {}),
      storagePath: finalPath,
      metadata: { ...input.metadata, range: input.metadata?.range ?? { start: 0, length: input.data.length, complete: input.metadata?.complete === true }, artifactDigest: expectedSha256, artifactSize: input.data.length, integrityStatus: "VERIFIED", integrityCheckedAt: new Date().toISOString() },
    };
    this.runtime.putEvidence(evidence);
    return evidence;
  }

  async putStream(input: {
    taskId: string; host: string; type: string; source: string; tool: string;
    toolCallId?: string; metadata?: Record<string, unknown>;
    transfer: (onChunk: (chunk: Buffer) => Promise<void>) => Promise<{ sha256: string; size: number }>;
  }): Promise<Evidence> {
    const existing = findBoundEvidence(this.runtime, input);
    if (existing) {
      const expectedSha256 = typeof input.metadata?.remoteSha256 === "string"
        ? input.metadata.remoteSha256
        : typeof input.metadata?.sourceDigest === "string" ? input.metadata.sourceDigest : undefined;
      const expectedSize = typeof input.metadata?.remoteSize === "number" ? input.metadata.remoteSize : undefined;
      await verifyExistingArtifact(existing, expectedSha256, expectedSize);
      return existing;
    }
    const evidenceId = input.toolCallId
      ? createDeterministicId("evidence", evidenceSeed(input))
      : createId("evidence");
    const taskDir = join(this.baseDir, "evidence", input.taskId);
    await mkdir(taskDir, { recursive: true, mode: 0o700 });
    await chmod(taskDir, 0o700);
    const finalPath = join(taskDir, `${evidenceId}_${safeName(input.source)}`);
    const tempPath = `${finalPath}.${process.pid}.tmp`;
    const handle = await open(tempPath, "wx", 0o600);
    const digest = createHash("sha256");
    let size = 0;
    try {
      const transfer = await input.transfer(async (chunk) => {
        if (!Buffer.isBuffer(chunk) || chunk.length === 0) return;
        digest.update(chunk);
        size += chunk.length;
        await handle.write(chunk);
      });
      const actualSha256 = digest.digest("hex");
      if (transfer.size !== size || transfer.sha256 !== actualSha256) throw new Error("流式 Evidence 大小或 SHA-256 校验失败");
      await handle.sync();
      await handle.close();
      await rename(tempPath, finalPath);
      this.checkpoint?.("evidence_file_written_before_metadata");
      await chmod(finalPath, 0o600);
      const evidence: Evidence = {
        evidenceId,
        taskId: input.taskId,
        host: input.host,
        type: input.type,
        source: input.source,
        sha256: actualSha256,
        collectedAt: new Date().toISOString(),
        tool: input.tool,
        ...(input.toolCallId ? { toolCallId: input.toolCallId } : {}),
        storagePath: finalPath,
        metadata: { ...input.metadata, range: input.metadata?.range ?? { start: 0, length: size, complete: input.metadata?.complete === true }, artifactDigest: actualSha256, artifactSize: size, integrityStatus: "VERIFIED", integrityCheckedAt: new Date().toISOString() },
      };
      this.runtime.putEvidence(evidence);
      return evidence;
    } catch (error) {
      await handle.close().catch(() => undefined);
      await unlink(tempPath).catch(() => undefined);
      throw error;
    }
  }

  putStructured(input: Omit<Evidence, "evidenceId" | "collectedAt">): Evidence {
    const existing = findBoundEvidence(this.runtime, input);
    if (existing) {
      if (input.sha256 && existing.sha256 !== input.sha256) throw new SecurityError("EVIDENCE_COLLECTION", "同一 ToolCall 的结构化 Evidence 摘要冲突");
      return existing;
    }
    const evidence: Evidence = {
      ...input,
      evidenceId: input.toolCallId
        ? createDeterministicId("evidence", evidenceSeed(input))
        : createId("evidence"),
      collectedAt: new Date().toISOString(),
    };
    this.runtime.putEvidence(evidence);
    return evidence;
  }
}

function sanitizeExportValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => sanitizeExportValue(item));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([name, item]) =>
    /(?:token|secret|credential|private.?key|storage.?path)/i.test(name) ? [] : [[name, sanitizeExportValue(item)]]));
  return value;
}

async function hashFile(path: string): Promise<string> {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk as Buffer);
  return digest.digest("hex");
}
