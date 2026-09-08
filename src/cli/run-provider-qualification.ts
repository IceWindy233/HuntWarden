import { execFileSync } from "node:child_process";
import { readFile, rename, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createModelBundle } from "../agent/model.js";
import { loadConfig } from "../config/load-config.js";
import type { TargetConfig, TaskContext } from "../domain/types.js";
import { MANIFEST_VERSION } from "../protocol-v2/types.js";
import { Application } from "../runtime/application.js";
import { RuntimeStore } from "../storage/runtime-store.js";
import { optionValue } from "./options.js";
import { parseQualificationTarget } from "./qualification-target.js";

const args = process.argv.slice(2);
const configPath = resolve(optionValue(args, "--config", true)!);
const linuxTargetPath = resolve(optionValue(args, "--linux-target", true)!);
const javaTargetPath = resolve(optionValue(args, "--java-target", true)!);
const outputPath = resolve(optionValue(args, "--output", true)!);
const root = fileURLToPath(new URL("../..", import.meta.url));
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" }).trim();
if (dirty) throw new Error("真实 Provider 任务只能从干净固定提交运行；请先提交或移除工作树修改");

const config = await loadConfig(configPath);
for (const [label, path] of [["storage.baseDir", config.storage.baseDir], ["--output", outputPath]] as const) {
  const pathFromRoot = relative(root, path);
  if (!pathFromRoot.startsWith("..") && !isAbsolute(pathFromRoot)) throw new Error(`${label} 必须位于仓库外，避免验收数据污染固定提交`);
}

const linuxTarget = await readTarget(linuxTargetPath);
const javaTarget = await readTarget(javaTargetPath);
const store = await RuntimeStore.open(config.storage.baseDir, config.storage.databaseFile);
const { models, model } = createModelBundle(config);
const app = new Application(config, store, models, model);
const startedAt = new Date().toISOString();
const record: ProviderTaskRunRecord = {
  schemaVersion: 1,
  status: "RUNNING",
  commit,
  manifestVersion: MANIFEST_VERSION,
  startedAt,
  tasks: {},
};

try {
  record.tasks.linux = await runTask(app, store, "linux", linuxTarget);
  await persistRecord(record);
  record.tasks.java = await runTask(app, store, "java", javaTarget);
  record.status = "PASS";
  record.finishedAt = new Date().toISOString();
  await persistRecord(record);
  process.stdout.write(`Provider 验收任务已完成：linux=${record.tasks.linux.taskId}，java=${record.tasks.java.taskId}，记录=${outputPath}\n`);
} catch (error) {
  record.status = "FAIL";
  record.finishedAt = new Date().toISOString();
  record.error = error instanceof Error ? error.message : String(error);
  await persistRecord(record);
  throw error;
} finally {
  await app.close();
}

async function runTask(app: Application, runtimeStore: RuntimeStore, kind: "linux" | "java", target: TargetConfig): Promise<ProviderTaskRecord> {
  const task = app.createTask({
    request: kind === "linux" ? linuxRequest : javaRequest,
    mode: "SCAN",
    checks: kind === "linux" ? ["linux_intrusion_triage", "linux_persistence"] : ["java_memory_shell"],
    profile: "DEEP",
    timeWindowHours: kind === "linux" ? 1 : 168,
    target,
  });
  process.stdout.write(`Provider 验收任务已创建：kind=${kind} task=${task.taskId}\n`);
  let reportId: string | undefined;
  try {
    await app.startTask(task.taskId);
    const report = await app.generateReport(task.taskId);
    reportId = report.reportId;
    const summary = summarizeTask(runtimeStore, task, reportId);
    const closed = summary.investigationStatus === "CLOSED_WITH_FINDINGS" || summary.investigationStatus === "CLOSED_NO_OBSERVED_FINDING";
    if (summary.taskStatus !== "COMPLETED" || summary.epochStatus !== "COMPLETED" || !closed) {
      throw new Error(`${kind} 验收任务未闭合：task=${summary.taskStatus} epoch=${summary.epochStatus ?? "NONE"} investigation=${summary.investigationStatus ?? "NONE"}`);
    }
    return summary;
  } catch (error) {
    const failed = summarizeTask(runtimeStore, task, reportId);
    record.tasks[kind] = { ...failed, error: error instanceof Error ? error.message : String(error) };
    await persistRecord(record);
    throw error;
  }
}

function summarizeTask(runtimeStore: RuntimeStore, task: TaskContext, reportId?: string): ProviderTaskRecord {
  const current = runtimeStore.getTask(task.taskId) ?? task;
  const epoch = current.activeEpochId ? runtimeStore.getScanEpoch(task.taskId, current.activeEpochId) : undefined;
  const session = current.activeEpochId ? runtimeStore.getInvestigationSession(task.taskId, current.activeEpochId) : undefined;
  return {
    taskId: task.taskId,
    ...(reportId ? { reportId } : {}),
    taskStatus: current.status,
    ...(current.activeEpochId ? { epochId: current.activeEpochId } : {}),
    ...(epoch ? { epochStatus: epoch.status } : {}),
    ...(session ? { investigationStatus: session.investigationStatus } : {}),
  };
}

async function readTarget(path: string): Promise<TargetConfig> {
  return parseQualificationTarget(await readFile(path, "utf8"), path);
}

async function persistRecord(value: ProviderTaskRunRecord): Promise<void> {
  const temporary = `${outputPath}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporary, outputPath);
}

interface ProviderTaskRecord {
  taskId: string;
  reportId?: string;
  taskStatus: TaskContext["status"];
  epochId?: string;
  epochStatus?: string;
  investigationStatus?: string;
  error?: string;
}

interface ProviderTaskRunRecord {
  schemaVersion: 1;
  status: "RUNNING" | "PASS" | "FAIL";
  commit: string;
  manifestVersion: string;
  startedAt: string;
  finishedAt?: string;
  tasks: Partial<Record<"linux" | "java", ProviderTaskRecord>>;
  error?: string;
}

const linuxRequest = "对当前 Ubuntu systemd 主机执行零 IOC 自主深度取证，覆盖 Linux 入侵分诊与持久化。先复核确定性预置、事实、关系、义务和反证；必须分别通过 propose_hypothesis 和 propose_actions 提交至少一个有事实依据、白名单且非重复的模型假设与调查动作，并为每个已观察类别写入模型 Assessment。不得把未检查范围解释为安全。";
const javaRequest = "对当前 Tomcat 9/JDK 17 运行态执行 Java 内存马自主深度取证。复核运行时组件、精确 ClassLoader、类检查和完整字节码 Evidence；必须分别通过 propose_hypothesis 和 propose_actions 提交至少一个有事实依据、白名单且非重复的模型假设与调查动作，写入 Java 类别模型 Assessment，并确保最终结论引用实际类字节码 Evidence。不得把 unknown Loader 或未检查范围解释为安全。";
