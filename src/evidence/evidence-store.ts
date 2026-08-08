import { createHash } from "node:crypto";
import { chmod, mkdir, open, readFile, rename } from "node:fs/promises";
import { basename, join } from "node:path";
import { createDeterministicId, createId } from "../common/ids.js";
import type { Evidence } from "../domain/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";

function safeName(value: string): string {
  return basename(value).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120) || "artifact.bin";
}

export class EvidenceStore {
  constructor(
    private readonly baseDir: string,
    private readonly runtime: RuntimeStore,
    private readonly checkpoint?: (name: string) => void,
  ) {}

  async putBuffer(input: {
    taskId: string; host: string; type: string; source: string; tool: string;
    data: Buffer; toolCallId?: string; metadata?: Record<string, unknown>;
  }): Promise<Evidence> {
    const existing = input.toolCallId
      ? this.runtime.listEvidence(input.taskId).find((item) => item.toolCallId === input.toolCallId)
      : undefined;
    if (existing) return existing;
    const evidenceId = input.toolCallId
      ? createDeterministicId("evidence", `${input.taskId}:${input.toolCallId}`)
      : createId("evidence");
    const taskDir = join(this.baseDir, "evidence", input.taskId);
    await mkdir(taskDir, { recursive: true, mode: 0o700 });
    await chmod(taskDir, 0o700);
    const fileName = `${evidenceId}_${safeName(input.source)}`;
    const finalPath = join(taskDir, fileName);
    const expectedSha256 = createHash("sha256").update(input.data).digest("hex");
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
      ...(input.metadata ? { metadata: input.metadata } : {}),
    };
    this.runtime.putEvidence(evidence);
    return evidence;
  }

  putStructured(input: Omit<Evidence, "evidenceId" | "collectedAt">): Evidence {
    const existing = input.toolCallId
      ? this.runtime.listEvidence(input.taskId).find((item) => item.toolCallId === input.toolCallId)
      : undefined;
    if (existing) return existing;
    const evidence: Evidence = {
      ...input,
      evidenceId: input.toolCallId
        ? createDeterministicId("evidence", `${input.taskId}:${input.toolCallId}`)
        : createId("evidence"),
      collectedAt: new Date().toISOString(),
    };
    this.runtime.putEvidence(evidence);
    return evidence;
  }
}
