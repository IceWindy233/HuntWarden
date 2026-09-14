import { createHash } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { mkdir, open, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Type, type Static } from "typebox";
import { Value } from "typebox/value";
import { createModelBundle } from "../agent/model.js";
import { loadConfig } from "../config/load-config.js";
import { investigationEpochIdentity, investigationEpochIdentityFailures, type InvestigationEpochIdentity } from "../evaluation/investigation-evaluator.js";
import { Application } from "../runtime/application.js";
import { RuntimeStore } from "../storage/runtime-store.js";
import { optionValue } from "./options.js";
import { parseQualificationTarget } from "./qualification-target.js";

const strict = { additionalProperties: false } as const;
const identifier = Type.String({ pattern: "^[A-Za-z0-9._-]+$", minLength: 1, maxLength: 128 });
const values = Type.Array(Type.String({ minLength: 1, maxLength: 4096 }), { maxItems: 1 });
const schema = Type.Object({
  schemaVersion: Type.Literal(1),
  suiteId: identifier,
  evaluationMode: Type.Union([Type.Literal("DEVELOPMENT"), Type.Literal("BLIND_RELEASE")]),
  profile: Type.Union([Type.Literal("QUICK"), Type.Literal("STANDARD"), Type.Literal("DEEP")]),
  timeWindowHours: Type.Integer({ minimum: 1, maximum: 8760 }),
  cases: Type.Array(Type.Object({
    caseId: identifier,
    runKind: Type.Union([Type.Literal("FIRST"), Type.Literal("RETRY")]),
    retryOfCaseId: Type.Optional(identifier),
    targetFile: Type.String({ minLength: 1, maxLength: 4096 }),
    checks: Type.Array(Type.Union([Type.Literal("webshell"), Type.Literal("java_memory_shell"), Type.Literal("backdoor_account"), Type.Literal("linux_persistence"), Type.Literal("linux_intrusion_triage")]), { minItems: 1, maxItems: 5, uniqueItems: true }),
    entryMode: Type.Union([Type.Literal("ZERO_IOC"), Type.Literal("SINGLE_LEAD")]),
    iocs: Type.Optional(Type.Object({ hash: Type.Optional(values), domain: Type.Optional(values), ip: Type.Optional(values), path: Type.Optional(values), processName: Type.Optional(values) }, strict)),
  }, strict), { minItems: 1, maxItems: 500 }),
}, strict);
type RunManifest = Static<typeof schema>;
type CaseResult = {
  caseId: string; runKind: "FIRST" | "RETRY"; retryOfCaseId?: string;
  state: "STARTED" | "FINISHED" | "FAILED";
  taskId?: string; epochId?: string; taskStatus?: string; epochStatus?: string;
  investigationStatus?: string; reportId?: string; failureStage?: string;
  cleanupSucceeded?: boolean;
  epochs?: InvestigationEpochIdentity[];
  identityFailures?: string[];
};

const args = process.argv.slice(2);
const configPath = resolve(optionValue(args, "--config", true)!);
const manifestPath = resolve(optionValue(args, "--manifest", true)!);
const outputDirectory = resolve(optionValue(args, "--output-dir", true)!);
const controllerOption = optionValue(args, "--controller");
const root = fileURLToPath(new URL("../..", import.meta.url));
const outside = (path: string) => { const child = relative(root, path); return child === ".." || child.startsWith("../") || isAbsolute(child); };
const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
if (process.env.HUNTWARDEN_INVESTIGATION_CONFIRM !== "I_HAVE_AUTHORIZATION") throw new Error("必须设置 HUNTWARDEN_INVESTIGATION_CONFIRM=I_HAVE_AUTHORIZATION");
const manifestBytes = await readFile(manifestPath);
const raw: unknown = JSON.parse(manifestBytes.toString("utf8"));
const errors = [...Value.Errors(schema, raw)];
if (errors.length) throw new Error(`运行清单必须是无答案的严格 schema v1: ${errors.map((error) => error.instancePath).join(", ")}`);
const manifest = raw as RunManifest;
const caseIds = new Map<string, RunManifest["cases"][number]>();
for (const item of manifest.cases) {
  if (caseIds.has(item.caseId)) throw new Error(`重复 caseId: ${item.caseId}`);
  const leadCount = Object.values(item.iocs ?? {}).flat().length;
  if (leadCount !== (item.entryMode === "ZERO_IOC" ? 0 : 1)) throw new Error(`入口线索数量不一致: ${item.caseId}`);
  if (item.runKind === "FIRST" && item.retryOfCaseId) throw new Error("FIRST 不能引用重试来源");
  if (item.runKind === "RETRY") {
    const first = item.retryOfCaseId ? caseIds.get(item.retryOfCaseId) : undefined;
    if (first?.runKind !== "FIRST" || first.entryMode !== item.entryMode || JSON.stringify(first.checks) !== JSON.stringify(item.checks) || JSON.stringify(first.iocs ?? {}) !== JSON.stringify(item.iocs ?? {})) throw new Error(`RETRY 必须引用此前相同入口的 FIRST: ${item.caseId}`);
  }
  caseIds.set(item.caseId, item);
}
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const clean = !execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" }).trim();
if (manifest.evaluationMode === "BLIND_RELEASE" && !clean) throw new Error("正式盲测必须从干净固定提交运行");
if (process.env.HUNTWARDEN_BUILD_COMMIT || process.env.HUNTWARDEN_BUILD_CLEAN) throw new Error("批跑不允许覆盖运行时构建身份");
const config = await loadConfig(configPath);
if (!outside(config.storage.baseDir) || !outside(outputDirectory) || !outside(await realpath(dirname(outputDirectory)))) throw new Error("运行库和结果目录必须位于仓库外");
if (!config.storage.databaseFile || config.storage.databaseFile === "." || config.storage.databaseFile === ".." || /[\\/\0]/.test(config.storage.databaseFile)) throw new Error("批跑 databaseFile 必须是单纯文件名，不能包含目录或绝对路径");
// A fresh database prevents existing tasks or recovery from contaminating a FIRST population.
try { await stat(resolve(config.storage.baseDir, config.storage.databaseFile)); throw new Error("批跑必须使用不存在的独立数据库，不能复用已运行的 FIRST"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
let controller: string | undefined;
if (controllerOption) {
  if (!isAbsolute(controllerOption)) throw new Error("场景控制器必须是明确授权的绝对可执行路径");
  controller = await realpath(controllerOption);
  if (!outside(controller) || !(await stat(controller)).isFile()) throw new Error("场景控制器必须是仓库外独立部署文件");
}
const targets = new Map<string, ReturnType<typeof parseQualificationTarget>>();
for (const item of manifest.cases) {
  const path = resolve(dirname(manifestPath), item.targetFile);
  targets.set(item.caseId, parseQualificationTarget(await readFile(path, "utf8"), path));
}
await mkdir(outputDirectory, { mode: 0o700 });
const journal = await open(resolve(outputDirectory, "events.jsonl"), "wx", 0o600);
const cases: CaseResult[] = [];
const identity = {
  schemaVersion: 1, suiteId: manifest.suiteId, evaluationMode: manifest.evaluationMode,
  commit, clean, manifestSha256: sha256(manifestBytes), configSha256: sha256(await readFile(configPath)),
  helperSha256: sha256(await readFile(resolve(root, "host-helper/huntwarden_helper.py"))),
  ...(controller ? { controllerSha256: sha256(await readFile(controller)) } : {}),
  startedAt: new Date().toISOString(),
};
const record = async (event: string, data: object) => { await journal.write(`${JSON.stringify({ event, at: new Date().toISOString(), ...data })}\n`); await journal.sync(); };
await record("RUN_STARTED", identity);
await writeFile(resolve(outputDirectory, "run-input.json"), manifestBytes, { mode: 0o600, flag: "wx" });
const controllerEnv: NodeJS.ProcessEnv = {};
for (const name of ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ"]) {
  if (process.env[name] !== undefined) controllerEnv[name] = process.env[name];
}
const control = async (operation: "prepare" | "cleanup", caseId: string) => {
  if (!controller) return;
  const log = await open(resolve(outputDirectory, `${caseId}.${operation}.log`), "wx", 0o600);
  try {
    await new Promise<void>((accept, reject) => {
      const child = spawn(controller!, [operation, caseId], { cwd: dirname(controller!), env: controllerEnv, stdio: ["ignore", log.fd, log.fd], timeout: 180_000 });
      child.once("error", reject);
      child.once("exit", (code, signal) => code === 0 ? accept() : reject(new Error(`SCENARIO_${operation.toUpperCase()}_${signal ?? code}`)));
    });
  } finally { await log.close(); }
};
const store = await RuntimeStore.open(config.storage.baseDir, config.storage.databaseFile);
const { models, model } = createModelBundle(config);
const app = new Application(config, store, models, model);
let interrupted = false;
const stop = () => { interrupted = true; void app.close(); };
process.once("SIGINT", stop);
process.once("SIGTERM", stop);
try {
  for (const definition of manifest.cases) {
    if (interrupted) break;
    const item: CaseResult = { caseId: definition.caseId, runKind: definition.runKind, ...(definition.retryOfCaseId ? { retryOfCaseId: definition.retryOfCaseId } : {}), state: "STARTED" };
    cases.push(item);
    await record("CASE_STARTED", item);
    let stage = "PREPARE";
    try {
      await control("prepare", definition.caseId);
      await record("SCENARIO_READY", { caseId: definition.caseId });
      stage = "CREATE_TASK";
      const task = app.createTask({
        request: "执行授权类别的自主深度取证。按已观察事实、关系、反证与 Evidence 作出结论；缺失信息必须保留为范围限制，不得将未检查范围解释为安全。",
        mode: "SCAN", checks: definition.checks, profile: manifest.profile, timeWindowHours: manifest.timeWindowHours,
        ...(definition.iocs ? { iocs: definition.iocs } : {}), target: targets.get(definition.caseId)!,
      });
      item.taskId = task.taskId;
      await record("TASK_CREATED", item);
      stage = "INVESTIGATE";
      await app.startTask(task.taskId);
      stage = "REPORT";
      item.reportId = (await app.generateReport(task.taskId)).reportId;
      item.state = "FINISHED";
    } catch {
      item.state = "FAILED";
      item.failureStage = interrupted ? "INTERRUPTED" : stage;
    } finally {
      if (item.taskId && !interrupted) {
        const task = store.getTask(item.taskId);
        if (task) item.taskStatus = task.status;
        if (task?.activeEpochId) {
          item.epochId = task.activeEpochId;
          const epoch = store.getScanEpoch(item.taskId, item.epochId);
          const session = store.getInvestigationSession(item.taskId, item.epochId);
          if (epoch) item.epochStatus = epoch.status;
          if (session) item.investigationStatus = session.investigationStatus;
        }
        const epochs = store.listScanEpochs(item.taskId);
        item.epochs = epochs.map(investigationEpochIdentity);
        if (manifest.evaluationMode === "BLIND_RELEASE") {
          item.identityFailures = epochs.flatMap((epoch) => investigationEpochIdentityFailures(epoch, identity).map((failure) => `${epoch.epochId}: ${failure}`));
          if (epochs.length === 0) item.identityFailures.push("EPOCH_MISSING");
          if (item.identityFailures.length > 0) {
            item.state = "FAILED";
            item.failureStage ??= "EPOCH_IDENTITY";
          }
        }
      }
      if (controller) {
        try { await control("cleanup", definition.caseId); item.cleanupSucceeded = true; }
        catch { item.cleanupSucceeded = false; item.state = "FAILED"; item.failureStage ??= "CLEANUP"; }
      }
      await record("CASE_FINISHED", item);
    }
    // Never silently recover or replay a still-active task as another FIRST.
    if (!interrupted && store.hasActiveTask()) break;
  }
} finally {
  process.removeListener("SIGINT", stop);
  process.removeListener("SIGTERM", stop);
  await app.close();
  const state = !interrupted && cases.length === manifest.cases.length && cases.every((item) => item.state === "FINISHED") ? "FINISHED" : "FAILED";
  const result = { ...identity, finishedAt: new Date().toISOString(), state, plannedCases: manifest.cases.length, cases };
  await record("RUN_FINISHED", result);
  await journal.close();
  await writeFile(resolve(outputDirectory, "run-result.json"), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  process.stdout.write(`调查批跑 ${state}: ${cases.length}/${manifest.cases.length}，结果 ${outputDirectory}\n`);
  if (state !== "FINISHED") process.exitCode = 1;
}
