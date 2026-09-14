import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const run = promisify(execFile);
const directories: string[] = [];
afterEach(async () => await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))));

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-release-qualification-"));
  directories.push(directory);
  const commit = (await run("git", ["rev-parse", "HEAD"], { cwd: process.cwd() })).stdout.trim();
  const helperSha256 = createHash("sha256").update(await readFile(join(process.cwd(), "host-helper/huntwarden_helper.py"))).digest("hex");
  const operationalScriptSha256 = createHash("sha256").update(await readFile(join(process.cwd(), "acceptance/operational/qualify-host.sh"))).digest("hex");
  const writeEvidence = async (name: string, value: unknown) => {
    const path = join(directory, name);
    await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    const digest = createHash("sha256").update(await readFile(path)).digest("hex");
    return { path: basename(path), sha256: digest };
  };
  const providerContract = await writeEvidence("provider-contract.json", {
    schemaVersion: 1, status: "PASS", evaluationKind: "PROTOCOL_FIXTURE", endpointClass: "LOOPBACK", commit, manifestVersion: "3.0.0",
    protocols: [
      { protocol: "openai-completions", toolCallVerified: true, usage: { input: 1, output: 1 } },
      { protocol: "openai-responses", toolCallVerified: true, usage: { input: 1, output: 1 } },
    ],
    faults: { retry: { attempts: [{ status: 429 }, { status: 200 }] }, stall: { stopReason: "aborted", httpStatus: 200, runtimeClassification: "PROVIDER_FAILURE" }, empty: { rejected: true } },
  });
  const taskProof = (taskId: string, checks: string[], extra: Record<string, unknown> = {}) => ({
    taskId, epochId: `${taskId}-EPOCH`, taskStatus: "COMPLETED", epochStatus: "COMPLETED", investigationStatus: "CLOSED_WITH_FINDINGS",
    checks, entryMode: "ZERO_IOC", iocCount: 0, completeDiscoveryCheckpoints: 1, providerHttpAttempts: 1, successfulProviderHttpAttempts: 1,
    modelProposalToolCalls: 2, modelActions: 1, successfulModelActionAttempts: 1, modelAssessments: 1, reports: 1,
    duplicatePrimitiveExecutions: 0, invalidToolCalls: 0, controllerCommit: commit, controllerTreeClean: true,
    controllerCommitAtFinish: commit, controllerTreeCleanAtFinish: true, helperSha256, ...extra,
  });
  const provider = await writeEvidence("provider.json", {
    schemaVersion: 2, status: "PASS", evaluationKind: "REAL_PROVIDER", commit, manifestVersion: "3.0.0", networkEndpointClass: "REMOTE_VENDOR", helperSha256,
    endpointResolution: { beforeCount: 2, afterCount: 2, allPublic: true, stable: true },
    provider: "vendor", model: "tool-model", protocol: "openai-responses", toolCallObserved: true, failureFallbackVerified: true, javaEvidenceReferenced: true,
    smoke: { usage: { input: 1, output: 1 } },
    faultContract: { sha256: providerContract.sha256, endpointClass: "LOOPBACK", protocolsVerified: 2, retryStatuses: [429, 200], stallAborted: true, emptyResponseRejected: true },
    tasks: { linuxZeroIoc: taskProof("TASK-LINUX", ["linux_intrusion_triage", "linux_persistence"]), javaRuntime: taskProof("TASK-JAVA", ["java_memory_shell"], { javaBytecodeEvidence: 1, javaEvidenceReferencedByModel: 1 }) },
    failures: [],
  });
  const blindEvaluation = await writeEvidence("blind.json", {
    schemaVersion: 2, status: "PASS", evaluationMode: "BLIND_RELEASE", environment: { commit, manifestVersion: "3.0.0" },
    qualificationFailures: [],
    runIdentity: { evaluationMode: "BLIND_RELEASE", commit, clean: true, helperSha256, startedAt: "2026-09-08T00:00:00.000Z", finishedAt: "2026-09-08T01:00:00.000Z" },
    truthSet: {
      archiveSha256: "d".repeat(64), frozenAt: "2026-09-07T00:00:00.000Z", curator: "independent-curator", runner: "release-runner", independentFromTuning: true,
      isolation: { targetAuthorizationContainsTruth: false, helperReceivesTruth: false, modelReceivesTruth: false },
    },
    population: { firstRunCases: 201, retryCases: 0, maliciousFirstRunCases: 100, benignFirstRunCases: 100, limitedFirstRunCases: 1 },
    cases: Array.from({ length: 201 }, (_, index) => ({
      caseId: `case-${index}`, taskId: `TASK-${index}`, epochId: `EPOCH-${index}`, runKind: "FIRST", disposition: index < 100 ? "MALICIOUS" : index < 200 ? "BENIGN" : "LIMITED",
      epochs: [{ epochId: `EPOCH-${index}`, controllerCommit: commit, controllerTreeClean: true, controllerCommitAtFinish: commit, controllerTreeCleanAtFinish: true, helperSha256 }],
    })),
    metrics: { collectionRecall: { rate: 0.95 }, discoveryRecall: { rate: 0.95 }, evidencePreservation: { rate: 0.96 }, benignFalsePositive: { rate: 0.05 } },
  });
  const businessJvm = await writeEvidence("business-jvm.json", {
    schemaVersion: 2, status: "PASS", commit, manifestVersion: "3.0.0", sourceManifestSha256: "1".repeat(64), helperSha256, hostKeyOutOfBandVerified: true,
    environment: { fixture: false, workloadKind: "BUSINESS_APPLICATION", workloadDeclarationSha256: "2".repeat(64), attestorDigest: "3".repeat(64) },
    attach: { attempts: 12, componentMisses: 0, invalidProbeCosts: 0, incompleteInventories: 0, requiredComponentDigests: ["4".repeat(64)], wallTimeMs: Array(12).fill(10), maxWallTimeMs: 10 },
    traffic: { baselineRequests: 20, loadedRequests: 100, failures: [], failureRate: 0, baselineP95Ms: 5, loadedP95Ms: 6, loadedMaxMs: 8, postAttachHealthVerified: true },
    identityStable: true, failures: [],
  });
  const operational = await writeEvidence("operational.json", {
    schemaVersion: 1, status: "PASS", commit, runtimeSchemaVersion: 6, helperSha256,
    evaluatedAt: "2026-09-10T00:00:00.000Z",
    host: {
      schemaVersion: 1, status: "PASS", commit, helperSha256, scriptSha256: operationalScriptSha256,
      evaluatedAt: "2026-09-10T00:00:00.000Z", platform: { distribution: "ubuntu", version: "24.04", architecture: "x86_64" },
      install: { freshInstall: true, upgrade: true, permissions: true, componentDigests: true, receiptPreserved: true },
      uninstall: { defaultPreservedState: true, purgeRemovedState: true, credentialsAbsent: true, targetJobsAbsent: true }, failures: [],
    },
    migration: { fromVersion: 5, toVersion: 6, backupSha256: "c".repeat(64), oldTaskReadable: true, rollbackVerified: true },
    evidenceExport: { evidenceCount: 1, artifactCount: 1, manifestSha256: "d".repeat(64), checksumsVerified: true, sensitiveFieldsAbsent: true },
    failures: [],
  });
  const platformIds = [
    "ubuntu-24.04-arm64", "ubuntu-24.04-x86_64", "debian-12-systemd-x86_64",
    "rocky-or-alma-9-x86_64-selinux-enforcing", "amazon-linux-2023-x86_64",
  ];
  const platforms = [];
  for (const platformId of platformIds) {
    const artifact = await writeEvidence(`${platformId}.json`, {
      schemaVersion: 2, status: "PASS", commit, manifestVersion: "3.0.0", sourceManifestSha256: "5".repeat(64), helperSha256, hostKeyOutOfBandVerified: true,
      environment: {
        platformId,
        distribution: platformId.startsWith("ubuntu") ? "ubuntu" : platformId.startsWith("debian") ? "debian" : platformId.startsWith("rocky") ? "rocky" : "amzn",
        version: platformId.startsWith("ubuntu") ? "24.04" : platformId.startsWith("debian") ? "12" : platformId.startsWith("rocky") ? "9.6" : "2023",
        architecture: platformId.endsWith("arm64") ? "aarch64" : "x86_64", kernel: "6.8.0", timezone: "UTC", init: "systemd", selinux: platformId.includes("selinux") ? "Enforcing" : "Unavailable",
        officialImageDigest: "6".repeat(64), imageIdentityDigest: "7".repeat(64), imageAttestorDigest: "8".repeat(64),
      },
      capabilities: { verified: true, digest: "9".repeat(64), namespaces: 23, verbs: 8, matchers: ["literal"], probes: [] },
      evidence: { verified: true, bytes: 10, sha256: "a".repeat(64), sourceIdentityDigest: "b".repeat(64) },
      recovery: { verified: true, reconnects: 1, hostIdentityStable: true, capabilitiesStable: true },
      cleanup: { verified: true, releaseRequiredAfterDownload: false, finalAbsent: true }, failures: [],
    });
    platforms.push({ platformId, artifact });
  }
  const qualificationPath = join(directory, "qualification.json");
  const qualification = { schemaVersion: 1, commit, manifestVersion: "3.0.0", evidence: { provider, providerContract, blindEvaluation, businessJvm, operational, platforms } };
  await writeFile(qualificationPath, `${JSON.stringify(qualification, null, 2)}\n`, "utf8");
  return { directory, qualificationPath, qualification, writeEvidence };
}

describe("发布资格硬门禁", () => {
  it("只接受与当前提交绑定的 Provider、首跑盲测、真实业务 JVM、运维演练和五平台证据", async () => {
    const value = await fixture();
    const result = await run("node", ["scripts/release-qualification-check.mjs", "--qualification", value.qualificationPath], { cwd: process.cwd() });
    expect(result.stdout).toContain("发布资格校验通过");
  });

  it("摘要有效但 Provider 来自本机协议夹具时失败关闭", async () => {
    const value = await fixture();
    value.qualification.evidence.provider = await value.writeEvidence("provider.json", {
      schemaVersion: 2, status: "PASS", evaluationKind: "REAL_PROVIDER", commit: value.qualification.commit, manifestVersion: "3.0.0", networkEndpointClass: "LOOPBACK",
      provider: "fixture", model: "fixture", protocol: "openai-responses",
      toolCallObserved: true, failureFallbackVerified: true, javaEvidenceReferenced: true, failures: [],
    });
    await writeFile(value.qualificationPath, `${JSON.stringify(value.qualification, null, 2)}\n`, "utf8");
    await expect(run("node", ["scripts/release-qualification-check.mjs", "--qualification", value.qualificationPath], { cwd: process.cwd() }))
      .rejects.toMatchObject({ stderr: expect.stringContaining("不能使用本机或夹具端点") });
  });

  it("拒绝摘要正确但实际盲测 Epoch 的 Helper 不一致", async () => {
    const value = await fixture();
    const blind = JSON.parse(await readFile(join(value.directory, "blind.json"), "utf8"));
    blind.cases[0].epochs[0].helperSha256 = "0".repeat(64);
    value.qualification.evidence.blindEvaluation = await value.writeEvidence("blind.json", blind);
    await writeFile(value.qualificationPath, JSON.stringify(value.qualification));
    await expect(run("node", ["scripts/release-qualification-check.mjs", "--qualification", value.qualificationPath], { cwd: process.cwd() })).rejects.toMatchObject({ code: 1 });
  });

  it("运维证据没有完成数据库回退时失败关闭", async () => {
    const value = await fixture();
    const operational = JSON.parse(await readFile(join(value.directory, "operational.json"), "utf8")) as Record<string, unknown>;
    operational.migration = { ...(operational.migration as Record<string, unknown>), rollbackVerified: false };
    value.qualification.evidence.operational = await value.writeEvidence("operational.json", operational);
    await writeFile(value.qualificationPath, `${JSON.stringify(value.qualification, null, 2)}\n`, "utf8");
    await expect(run("node", ["scripts/release-qualification-check.mjs", "--qualification", value.qualificationPath], { cwd: process.cwd() }))
      .rejects.toMatchObject({ stderr: expect.stringContaining("数据库迁移、旧任务读取、事务前备份或回退演练未通过") });
  });
});
