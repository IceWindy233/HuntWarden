import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { Value } from "typebox/value";
import { InvestigationEvaluationTruthSchema, InvestigationRunRecordSchema, parseInvestigationEvaluationManifest, verifyInvestigationTruthArchive } from "../evaluation/investigation-evaluator.js";
import { optionValue } from "./options.js";

const args = process.argv.slice(2);
const truthOption = resolve(optionValue(args, "--truth", true)!);
const runOption = resolve(optionValue(args, "--run", true)!);
const outputOption = resolve(optionValue(args, "--output", true)!);
const archiveOption = optionValue(args, "--truth-archive");
const [truthPath, runPath, outputDirectory] = await Promise.all([
  realpath(truthOption), realpath(runOption), realpath(dirname(outputOption)),
]);
const runDirectory = dirname(runPath);
const outputPath = resolve(outputDirectory, basename(outputOption));
const archivePath = archiveOption ? await realpath(resolve(archiveOption)) : undefined;
function isInRunDirectory(path: string): boolean {
  const pathRelative = relative(runDirectory, path);
  return !isAbsolute(pathRelative) && pathRelative !== ".." && !pathRelative.startsWith(`..${sep}`);
}
if (isInRunDirectory(outputDirectory)) throw new Error("含答案的评分清单不能写入运行端目录");
if (isInRunDirectory(truthPath) || (archivePath && isInRunDirectory(archivePath))) throw new Error("真值清单和归档原件不能位于运行端目录");
const truth: unknown = JSON.parse(await readFile(truthPath, "utf8"));
if (!Value.Check(InvestigationEvaluationTruthSchema, truth)) throw new Error("真值清单必须沿用 evaluator schema v2，但不得包含 taskId/epochId");
const run: unknown = JSON.parse(await readFile(runPath, "utf8"));
if (!Value.Check(InvestigationRunRecordSchema, run)) throw new Error("批跑结果无效或尚未结束");
if (truth.suiteId !== run.suiteId || (truth.evaluationMode ?? "DEVELOPMENT") !== run.evaluationMode || truth.environment.commit !== run.commit) throw new Error("真值和运行记录的套件、评测模式或提交不一致");
if (truth.cases.length !== run.plannedCases || run.cases.length !== run.plannedCases) throw new Error("必须保留全部计划案例，不能删除失败或未运行的 FIRST");
if (run.evaluationMode === "BLIND_RELEASE") {
  if (!run.clean || !archivePath || !truth.truthSet) throw new Error("正式盲测需要干净提交及独立真值归档原件");
  const digest = createHash("sha256").update(await readFile(archivePath)).digest("hex");
  if (digest !== truth.truthSet.archiveSha256) throw new Error("独立真值归档 SHA-256 不一致");
  const { stdout } = await promisify(execFile)("tar", ["-xOf", archivePath, "truth.json"], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  const archivedTruth: unknown = JSON.parse(stdout);
  verifyInvestigationTruthArchive(truth, archivedTruth, digest);
  const frozenAt = Date.parse(truth.truthSet.frozenAt);
  const startedAt = Date.parse(run.startedAt);
  if (!Number.isFinite(frozenAt) || !Number.isFinite(startedAt) || frozenAt > startedAt) throw new Error("真值集必须在首次运行前冻结");
}
const runCases = new Map(run.cases.map((item) => [item.caseId, item]));
if (runCases.size !== run.cases.length) throw new Error("批跑结果包含重复 caseId");
const manifest = parseInvestigationEvaluationManifest({
  ...truth,
  cases: truth.cases.map((definition) => {
    const actual = runCases.get(definition.caseId);
    if (!actual?.taskId || !actual.epochId) throw new Error(`案例未形成可评分 Task/Epoch，不能丢弃或伪造: ${definition.caseId}`);
    if (actual.runKind !== definition.runKind || actual.retryOfCaseId !== definition.retryOfCaseId) throw new Error(`FIRST/RETRY 账本不一致: ${definition.caseId}`);
    return { ...definition, taskId: actual.taskId, epochId: actual.epochId };
  }),
});
await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: "wx" });
process.stdout.write(`评分清单已绑定 ${manifest.cases.length} 个实际 Task/Epoch；未执行评分、未声明通过。\n`);
