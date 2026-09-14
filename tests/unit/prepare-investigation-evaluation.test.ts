import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type { InvestigationEvaluationManifest } from "../../src/evaluation/investigation-evaluator.js";

const run = promisify(execFile);
const cliPath = resolve("src/cli/prepare-investigation-evaluation.ts");
const directories: string[] = [];
afterEach(async () => await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))));

type Truth = Omit<InvestigationEvaluationManifest, "cases"> & {
  cases: Omit<InvestigationEvaluationManifest["cases"][number], "taskId" | "epochId">[];
};

async function fixture(mode: "BLIND_RELEASE" | "DEVELOPMENT" = "BLIND_RELEASE", compressed = false) {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-prepare-evaluation-"));
  directories.push(directory);
  const runDirectory = join(directory, "runner");
  const evaluationDirectory = join(directory, "evaluator");
  const frozenDirectory = join(evaluationDirectory, "frozen");
  await Promise.all([mkdir(runDirectory), mkdir(frozenDirectory, { recursive: true })]);
  const caseDefinition = (index: number, disposition: "MALICIOUS" | "BENIGN" | "LIMITED"): Truth["cases"][number] => ({
    caseId: `${disposition.toLowerCase()}-${index}`, disposition,
    entryMode: index % 2 === 0 ? "ZERO_IOC" : "SINGLE_LEAD", runKind: "FIRST",
    expectedCategories: ["linux_intrusion_triage"],
    expectedFacts: [{ namespace: "process", field: "exe", value: `/fixture/${disposition}/${index}`, ...(disposition === "MALICIOUS" ? { evidenceRequired: true } : {}) }],
    ...(disposition === "LIMITED" ? { expectedGapCodes: ["FIXTURE_UNAVAILABLE"] } : {}),
  });
  const truth: Truth = {
    schemaVersion: 2, suiteId: "frozen-truth-binding", evaluationMode: mode,
    environment: {
      targetOs: "frozen-matrix", architecture: "x86_64", transport: "SSH", applicationVersion: "0.2.0", protocolVersion: 2,
      manifestVersion: "3.0.0", helperVersion: "3.0.0", investigationEngineVersion: "1.0.0",
      ruleRegistryVersion: "2.3.0", playbookRegistryVersion: "1.3.0", commit: "a".repeat(40), budgetProfile: "STANDARD",
    },
    cases: mode === "DEVELOPMENT" ? [caseDefinition(0, "MALICIOUS")] : [
      ...Array.from({ length: 100 }, (_, index) => caseDefinition(index, "MALICIOUS")),
      ...Array.from({ length: 100 }, (_, index) => caseDefinition(index, "BENIGN")),
      caseDefinition(0, "LIMITED"),
    ],
    thresholds: { minCollectionRecall: 0.95, minDiscoveryRecall: 0.95, minEvidencePreservation: 0.95, minObligationClosure: 1, maxBenignFalsePositive: 0.05 },
  };
  const archivePath = join(evaluationDirectory, compressed ? "truth.tar.gz" : "truth.tar");
  const frozenTruthPath = join(frozenDirectory, "truth.json");
  if (mode === "BLIND_RELEASE") {
    const frozenTruthSet = {
      frozenAt: "2026-09-07T00:00:00.000Z", curator: "independent-curator", runner: "release-runner", independentFromTuning: true as const,
      isolation: { targetAuthorizationContainsTruth: false as const, helperReceivesTruth: false as const, modelReceivesTruth: false as const },
    };
    await writeFile(frozenTruthPath, JSON.stringify({ ...truth, truthSet: frozenTruthSet }));
    await run("tar", [compressed ? "-czf" : "-cf", archivePath, "-C", frozenDirectory, "truth.json"]);
    truth.truthSet = { ...frozenTruthSet, archiveSha256: createHash("sha256").update(await readFile(archivePath)).digest("hex") };
  }
  const ledger = {
    schemaVersion: 1, suiteId: truth.suiteId, evaluationMode: mode, commit: truth.environment.commit, clean: true, helperSha256: "b".repeat(64),
    startedAt: "2026-09-08T00:00:00.000Z", finishedAt: "2026-09-08T01:00:00.000Z", state: "FINISHED", plannedCases: truth.cases.length,
    cases: truth.cases.map((item) => ({ caseId: item.caseId, runKind: item.runKind, taskId: `TASK-${item.caseId}`, epochId: `EPOCH-${item.caseId}`, state: "FINISHED" })),
  };
  const truthPath = join(evaluationDirectory, "truth.json");
  const runPath = join(runDirectory, "run.json");
  const outputPath = join(evaluationDirectory, "manifest.json");
  await Promise.all([writeFile(truthPath, JSON.stringify(truth)), writeFile(runPath, JSON.stringify(ledger))]);
  const prepare = (paths: { truth?: string; run?: string; output?: string; archive?: string } = {}) => run(process.execPath, [
    "--import", "tsx", cliPath, "--truth", paths.truth ?? truthPath, "--run", paths.run ?? runPath, "--output", paths.output ?? outputPath,
    ...(mode === "BLIND_RELEASE" ? ["--truth-archive", paths.archive ?? archivePath] : []),
  ]);
  return { directory, runDirectory, evaluationDirectory, frozenDirectory, frozenTruthPath, truthPath, runPath, archivePath, outputPath, truth, ledger, prepare };
}

async function expectNoOutput(path: string) {
  await expect(readFile(path)).rejects.toMatchObject({ code: "ENOENT" });
}

describe("调查评分清单真值绑定", () => {
  it("将 tar.gz 内省略自引用摘要的冻结真值绑定到实际 Task/Epoch", async () => {
    const value = await fixture("BLIND_RELEASE", true);
    await value.prepare();
    const manifest = JSON.parse(await readFile(value.outputPath, "utf8"));
    expect(manifest).toEqual({ ...value.truth, cases: value.truth.cases.map((item, index) => ({ ...item, taskId: value.ledger.cases[index]!.taskId, epochId: value.ledger.cases[index]!.epochId })) });
  });

  it("归档不变时拒绝改写答案，且不生成评分清单", async () => {
    const value = await fixture();
    value.truth.cases[0]!.expectedFacts[0]!.value = "/fixture/substituted-answer";
    await writeFile(value.truthPath, JSON.stringify(value.truth));
    await expect(value.prepare()).rejects.toMatchObject({ code: 1 });
    await expectNoOutput(value.outputPath);
  });

  it("归档不变时拒绝改写环境或冻结元数据", async () => {
    const value = await fixture();
    const changedEnvironment = { ...value.truth, environment: { ...value.truth.environment, targetOs: "substituted-environment" } };
    await writeFile(value.truthPath, JSON.stringify(changedEnvironment));
    await expect(value.prepare()).rejects.toMatchObject({ code: 1 });
    await expectNoOutput(value.outputPath);
    const changedFreeze = { ...value.truth, truthSet: { ...value.truth.truthSet!, frozenAt: "2026-09-06T00:00:00.000Z" } };
    await writeFile(value.truthPath, JSON.stringify(changedFreeze));
    await expect(value.prepare()).rejects.toMatchObject({ code: 1 });
    await expectNoOutput(value.outputPath);
  });

  it("拒绝指向真实运行目录的输出父目录符号链接，即使 run 本身也是链接", async () => {
    const value = await fixture();
    const runAlias = join(value.directory, "run-alias.json");
    const outputAlias = join(value.evaluationDirectory, "output-alias");
    await Promise.all([symlink(value.runPath, runAlias), symlink(value.runDirectory, outputAlias, "dir")]);
    await expect(value.prepare({ run: runAlias, output: join(outputAlias, "manifest.json") })).rejects.toMatchObject({ code: 1 });
    await expectNoOutput(join(value.runDirectory, "manifest.json"));
  });

  it("拒绝实际存放在运行目录的真值或归档，即使通过外部符号链接读取", async () => {
    const value = await fixture();
    const runTruth = join(value.runDirectory, "truth.json");
    const truthAlias = join(value.evaluationDirectory, "truth-alias.json");
    await writeFile(runTruth, JSON.stringify(value.truth));
    await symlink(runTruth, truthAlias);
    await expect(value.prepare({ truth: truthAlias })).rejects.toMatchObject({ code: 1 });
    await expectNoOutput(value.outputPath);
    const runArchive = join(value.runDirectory, "truth.tar");
    const archiveAlias = join(value.evaluationDirectory, "archive-alias.tar");
    await writeFile(runArchive, await readFile(value.archivePath));
    await symlink(runArchive, archiveAlias);
    await expect(value.prepare({ archive: archiveAlias })).rejects.toMatchObject({ code: 1 });
    await expectNoOutput(value.outputPath);
  });

  it("拒绝归档真值携带实际 Task/Epoch 标识", async () => {
    const value = await fixture();
    const archivedTruth = JSON.parse(await readFile(value.frozenTruthPath, "utf8"));
    archivedTruth.cases[0].taskId = value.ledger.cases[0]!.taskId;
    archivedTruth.cases[0].epochId = value.ledger.cases[0]!.epochId;
    await writeFile(value.frozenTruthPath, JSON.stringify(archivedTruth));
    await run("tar", ["-cf", value.archivePath, "-C", value.frozenDirectory, "truth.json"]);
    value.truth.truthSet!.archiveSha256 = createHash("sha256").update(await readFile(value.archivePath)).digest("hex");
    await writeFile(value.truthPath, JSON.stringify(value.truth));
    await expect(value.prepare()).rejects.toMatchObject({ code: 1 });
    await expectNoOutput(value.outputPath);
  });

  it("DEVELOPMENT 无需正式归档且不会覆盖已有评分清单", async () => {
    const value = await fixture("DEVELOPMENT");
    await value.prepare();
    const original = await readFile(value.outputPath, "utf8");
    expect(JSON.parse(original)).toEqual({ ...value.truth, cases: [{ ...value.truth.cases[0], taskId: value.ledger.cases[0]!.taskId, epochId: value.ledger.cases[0]!.epochId }] });
    await expect(value.prepare()).rejects.toMatchObject({ code: 1 });
    expect(await readFile(value.outputPath, "utf8")).toBe(original);
  });
});
