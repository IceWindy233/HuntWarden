import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))));

describe("Evidence 流式落盘", () => {
  it("分块写入、校验 SHA-256 并以 0600 文件持久化", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-evidence-stream-"));
    directories.push(directory);
    const runtime = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    runtime.createTask(task);
    const payload = Buffer.alloc(3 * 1024 * 1024 + 17, 0x41);
    const expected = createHash("sha256").update(payload).digest("hex");
    const evidence = await new EvidenceStore(directory, runtime).putStream({
      taskId: task.taskId, host: task.target.host, type: "file", source: "/tmp/large.bin", tool: "collect_file", toolCallId: "stream-call",
      transfer: async (onChunk) => {
        for (let offset = 0; offset < payload.length; offset += 256 * 1024) await onChunk(payload.subarray(offset, offset + 256 * 1024));
        return { sha256: expected, size: payload.length };
      },
    });

    expect(evidence.sha256).toBe(expected);
    expect(await readFile(evidence.storagePath!)).toEqual(payload);
    expect((await stat(evidence.storagePath!)).mode & 0o777).toBe(0o600);
    runtime.close();
  });

  it("传输摘要不匹配时不留下临时文件或 Evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-evidence-stream-fail-"));
    directories.push(directory);
    const runtime = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    runtime.createTask(task);
    const store = new EvidenceStore(directory, runtime);

    await expect(store.putStream({
      taskId: task.taskId, host: task.target.host, type: "file", source: "/tmp/bad.bin", tool: "collect_file", toolCallId: "bad-stream-call",
      transfer: async (onChunk) => { await onChunk(Buffer.from("payload")); return { sha256: "0".repeat(64), size: 7 }; },
    })).rejects.toThrow(/SHA-256/);

    expect(runtime.listEvidence(task.taskId)).toHaveLength(0);
    expect(await readdir(join(directory, "evidence", task.taskId))).toHaveLength(0);
    runtime.close();
  });
});
