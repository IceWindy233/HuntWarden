#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import process from "node:process";

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const qualificationPath = option("--qualification");
if (!qualificationPath) {
  console.error("用法: node scripts/release-qualification-check.mjs --qualification <qualification.json>");
  process.exit(2);
}

const root = resolve(new URL("..", import.meta.url).pathname);
const absoluteQualification = resolve(qualificationPath);
const qualificationDirectory = dirname(absoluteQualification);
const failures = [];
const requiredPlatforms = new Set([
  "ubuntu-24.04-arm64",
  "ubuntu-24.04-x86_64",
  "debian-12-systemd-x86_64",
  "rocky-or-alma-9-x86_64-selinux-enforcing",
  "amazon-linux-2023-x86_64",
]);

function object(value) { return value && typeof value === "object" && !Array.isArray(value) ? value : undefined; }
function sha256(path) { return createHash("sha256").update(readFileSync(path)).digest("hex"); }
function readJson(path, label) {
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch (error) { failures.push(`${label} 无法读取或解析: ${error instanceof Error ? error.message : String(error)}`); return {}; }
}
function evidence(reference, label) {
  const value = object(reference);
  if (!value || typeof value.path !== "string" || !/^[a-f0-9]{64}$/.test(value.sha256 ?? "")) {
    failures.push(`${label} 引用必须包含 path 与 SHA-256`);
    return {};
  }
  if (value.path.startsWith("/") || value.path.split(/[\\/]/).includes("..")) {
    failures.push(`${label} 路径必须相对于资格清单且不能越界`);
    return {};
  }
  const path = resolve(qualificationDirectory, value.path);
  try {
    const actual = sha256(path);
    if (actual !== value.sha256) failures.push(`${label} 摘要不匹配`);
  } catch (error) {
    failures.push(`${label} 文件不可读: ${error instanceof Error ? error.message : String(error)}`);
    return {};
  }
  return readJson(path, label);
}
function assert(condition, message) { if (!condition) failures.push(message); }

const qualification = readJson(absoluteQualification, "发布资格清单");
const currentCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const currentHelperSha256 = sha256(resolve(root, "host-helper/huntwarden_helper.py"));
assert(qualification.schemaVersion === 1, "发布资格清单 schemaVersion 必须为 1");
assert(qualification.commit === currentCommit, `发布资格清单提交与当前 HEAD 不一致: ${qualification.commit ?? "缺失"} / ${currentCommit}`);
assert(qualification.manifestVersion === "3.0.0", "发布资格清单必须绑定 Manifest 3.0.0");
const evidenceSet = object(qualification.evidence) ?? {};

const provider = evidence(evidenceSet.provider, "真实 Provider 证据");
const providerContractReference = object(evidenceSet.providerContract);
const providerContract = evidence(providerContractReference, "Provider 协议故障契约");
assert(provider.status === "PASS" && provider.evaluationKind === "REAL_PROVIDER", "真实 Provider 证据必须是 PASS/REAL_PROVIDER");
assert(provider.schemaVersion === 2 && Array.isArray(provider.failures) && provider.failures.length === 0, "真实 Provider 证据必须由 schema v2 生成器无失败地产生");
assert(provider.manifestVersion === qualification.manifestVersion, "真实 Provider 证据 Manifest 不一致");
assert(provider.commit === currentCommit, "真实 Provider 证据提交与当前 HEAD 不一致");
assert(typeof provider.provider === "string" && provider.provider.length > 0 && typeof provider.model === "string" && provider.model.length > 0 && typeof provider.protocol === "string" && provider.protocol.length > 0, "真实 Provider 证据缺少 Provider、模型或协议身份");
assert(provider.networkEndpointClass === "REMOTE_VENDOR", "真实 Provider 证据不能使用本机或夹具端点");
assert(provider.endpointResolution?.beforeCount > 0 && provider.endpointResolution?.afterCount > 0
  && provider.endpointResolution?.allPublic === true && provider.endpointResolution?.stable === true, "真实 Provider 缺少冒烟前后稳定的全公网 DNS 证明");
assert(provider.helperSha256 === currentHelperSha256, "真实 Provider 证据未绑定当前 Helper 源码");
assert(provider.toolCallObserved === true && provider.failureFallbackVerified === true && provider.javaEvidenceReferenced === true, "真实 Provider 证据缺少 Tool Call、故障降级或 Java Evidence 联合验收");
assert(provider.smoke?.usage?.input > 0 && provider.smoke?.usage?.output > 0, "真实 Provider 冒烟缺少非零 usage");
assert(providerContract.status === "PASS" && providerContract.evaluationKind === "PROTOCOL_FIXTURE" && providerContract.endpointClass === "LOOPBACK", "Provider 协议故障契约身份无效");
assert(providerContract.commit === currentCommit && providerContract.manifestVersion === qualification.manifestVersion, "Provider 协议故障契约提交或 Manifest 不一致");
assert(Array.isArray(providerContract.protocols) && providerContract.protocols.length === 2
  && new Set(providerContract.protocols.map((item) => item?.protocol)).size === 2
  && providerContract.protocols.every((item) => item?.toolCallVerified === true && item?.usage?.input > 0 && item?.usage?.output > 0), "Provider 协议故障契约未完整验证两种协议、Tool Call 和 usage");
assert(JSON.stringify(providerContract.faults?.retry?.attempts?.map((item) => item?.status)) === "[429,200]", "Provider 协议故障契约缺少 429→200 轨迹");
assert(providerContract.faults?.stall?.stopReason === "aborted" && providerContract.faults?.stall?.runtimeClassification === "PROVIDER_FAILURE" && providerContract.faults?.stall?.httpStatus === 200, "Provider 协议故障契约缺少流中停滞归类");
assert(providerContract.faults?.empty?.rejected === true, "Provider 协议故障契约没有拒绝空响应");
assert(provider.faultContract?.sha256 === providerContractReference?.sha256 && provider.faultContract?.endpointClass === "LOOPBACK"
  && provider.faultContract?.protocolsVerified === 2 && JSON.stringify(provider.faultContract?.retryStatuses) === "[429,200]"
  && provider.faultContract?.stallAborted === true && provider.faultContract?.emptyResponseRejected === true, "真实 Provider 结果没有绑定已核验的故障契约");
const linuxProof = provider.tasks?.linuxZeroIoc;
const javaProof = provider.tasks?.javaRuntime;
const closed = new Set(["CLOSED_WITH_FINDINGS", "CLOSED_NO_OBSERVED_FINDING"]);
for (const [label, proof] of [["Linux 零 IOC", linuxProof], ["Java 运行态", javaProof]]) {
  assert(typeof proof?.taskId === "string" && proof.taskId.length > 0 && typeof proof?.epochId === "string" && proof.epochId.length > 0, `${label} Provider 证据缺少任务或 Epoch 引用`);
  assert(proof?.taskStatus === "COMPLETED" && proof?.epochStatus === "COMPLETED" && closed.has(proof?.investigationStatus), `${label} Provider 任务没有完整闭合`);
  assert(proof?.completeDiscoveryCheckpoints > 0 && proof?.successfulProviderHttpAttempts > 0, `${label} Provider 任务缺少发现检查点或成功 HTTP 审计`);
  assert(proof?.modelProposalToolCalls >= 2 && proof?.modelActions > 0 && proof?.successfulModelActionAttempts > 0 && proof?.modelAssessments > 0, `${label} Provider 任务缺少真实模型提案、动作、尝试或裁定`);
  assert(proof?.reports > 0 && proof?.duplicatePrimitiveExecutions === 0 && proof?.invalidToolCalls === 0, `${label} Provider 任务缺少有效报告或存在重复/非法执行`);
  assert(proof?.controllerCommit === currentCommit && proof?.controllerTreeClean === true
    && proof?.controllerCommitAtFinish === currentCommit && proof?.controllerTreeCleanAtFinish === true
    && proof?.helperSha256 === currentHelperSha256, `${label} Provider 任务未在起止阶段绑定当前干净控制端提交或 Helper 源码`);
}
assert(linuxProof?.taskId !== javaProof?.taskId && linuxProof?.entryMode === "ZERO_IOC" && linuxProof?.iocCount === 0
  && linuxProof?.checks?.includes("linux_intrusion_triage") && linuxProof?.checks?.includes("linux_persistence"), "Linux Provider 验收不是独立的零 IOC 入侵分诊/持久化任务");
assert(javaProof?.checks?.includes("java_memory_shell") && javaProof?.javaBytecodeEvidence > 0 && javaProof?.javaEvidenceReferencedByModel > 0, "Java Provider 验收缺少类字节 Evidence 或模型引用");

const blind = evidence(evidenceSet.blindEvaluation, "独立盲测证据");
assert(blind.status === "PASS" && blind.evaluationMode === "BLIND_RELEASE", "独立盲测证据必须是 PASS/BLIND_RELEASE");
assert(blind.environment?.commit === currentCommit && blind.environment?.manifestVersion === qualification.manifestVersion, "独立盲测证据版本或提交不一致");
assert(/^[a-f0-9]{64}$/.test(blind.truthSet?.archiveSha256 ?? "") && blind.truthSet?.independentFromTuning === true, "独立盲测结果缺少冻结真值摘要或独立性声明");
assert(typeof blind.truthSet?.curator === "string" && typeof blind.truthSet?.runner === "string" && blind.truthSet.curator.toLowerCase() !== blind.truthSet.runner.toLowerCase(), "独立盲测结果缺少相互独立的维护者与运行者");
assert(blind.truthSet?.isolation?.targetAuthorizationContainsTruth === false && blind.truthSet?.isolation?.helperReceivesTruth === false && blind.truthSet?.isolation?.modelReceivesTruth === false, "独立盲测结果缺少答案隔离证明");
assert(blind.population?.maliciousFirstRunCases >= 100 && blind.population?.benignFirstRunCases >= 100 && blind.population?.limitedFirstRunCases >= 1, "独立盲测首跑总体不足");
assert(blind.metrics?.discoveryRecall?.rate >= 0.95 && blind.metrics?.evidencePreservation?.rate >= 0.95 && blind.metrics?.benignFalsePositive?.rate <= 0.05, "独立盲测发布指标未达到冻结阈值");

const businessJvm = evidence(evidenceSet.businessJvm, "真实业务 JVM 证据");
assert(businessJvm.status === "PASS" && businessJvm.environment?.fixture === false && businessJvm.environment?.workloadKind === "BUSINESS_APPLICATION", "真实业务 JVM 证据必须来自非夹具业务应用");
assert(businessJvm.schemaVersion === 2 && Array.isArray(businessJvm.failures) && businessJvm.failures.length === 0, "真实业务 JVM 证据必须由 schema v2 执行器无失败地产生");
assert(businessJvm.manifestVersion === qualification.manifestVersion, "真实业务 JVM 证据 Manifest 不一致");
assert(businessJvm.commit === currentCommit, "真实业务 JVM 证据提交与当前 HEAD 不一致");
assert(businessJvm.helperSha256 === currentHelperSha256, "真实业务 JVM 证据未绑定当前 Helper 源码");
assert(/^[a-f0-9]{64}$/.test(businessJvm.sourceManifestSha256 ?? "") && /^[a-f0-9]{64}$/.test(businessJvm.environment?.workloadDeclarationSha256 ?? "")
  && /^[a-f0-9]{64}$/.test(businessJvm.environment?.attestorDigest ?? "") && businessJvm.hostKeyOutOfBandVerified === true, "真实业务 JVM 缺少清单、工作负载声明或带外 Host Key 绑定");
assert(businessJvm.attach?.attempts >= 12 && businessJvm.attach?.componentMisses === 0 && businessJvm.attach?.invalidProbeCosts === 0
  && businessJvm.attach?.incompleteInventories === 0 && Array.isArray(businessJvm.attach?.wallTimeMs)
  && businessJvm.attach.wallTimeMs.length === businessJvm.attach.attempts && businessJvm.attach.maxWallTimeMs === Math.max(...businessJvm.attach.wallTimeMs)
  && Array.isArray(businessJvm.attach?.requiredComponentDigests) && businessJvm.attach.requiredComponentDigests.length > 0
  && businessJvm.attach.requiredComponentDigests.every((item) => /^[a-f0-9]{64}$/.test(item)) && businessJvm.identityStable === true, "真实业务 JVM 的 Attach、组件、成本、完整性或身份验收不完整");
assert(Array.isArray(businessJvm.traffic?.failures) && businessJvm.traffic.failures.length === 0, "真实业务 JVM 流量存在失败或未记录失败数组");
assert(businessJvm.traffic?.baselineRequests >= 20 && businessJvm.traffic?.loadedRequests >= 100 && businessJvm.traffic?.failureRate === 0
  && Number.isFinite(businessJvm.traffic?.baselineP95Ms) && Number.isFinite(businessJvm.traffic?.loadedP95Ms)
  && Number.isFinite(businessJvm.traffic?.loadedMaxMs) && businessJvm.traffic?.postAttachHealthVerified === true, "真实业务 JVM 流量、延迟或 Attach 后健康验收不完整");

const platformReferences = Array.isArray(evidenceSet.platforms) ? evidenceSet.platforms : [];
const seenPlatforms = new Set();
for (const reference of platformReferences) {
  const platformId = typeof reference?.platformId === "string" ? reference.platformId : "";
  if (!requiredPlatforms.has(platformId)) { failures.push(`发布资格清单包含未知平台: ${platformId || "缺失"}`); continue; }
  if (seenPlatforms.has(platformId)) { failures.push(`发布资格清单平台重复: ${platformId}`); continue; }
  seenPlatforms.add(platformId);
  const result = evidence(reference.artifact, `平台 ${platformId} 证据`);
  assert(result.status === "PASS" && result.environment?.platformId === platformId, `平台 ${platformId} 证据身份或状态无效`);
  assert(result.schemaVersion === 2 && Array.isArray(result.failures) && result.failures.length === 0, `平台 ${platformId} 证据必须由 schema v2 执行器无失败地产生`);
  assert(result.manifestVersion === qualification.manifestVersion, `平台 ${platformId} Manifest 不一致`);
  assert(result.commit === currentCommit, `平台 ${platformId} 提交与当前 HEAD 不一致`);
  assert(result.helperSha256 === currentHelperSha256, `平台 ${platformId} 证据未绑定当前 Helper 源码`);
  assert(result.hostKeyOutOfBandVerified === true, `平台 ${platformId} 未确认带外 Host Key`);
  assert(/^[a-f0-9]{64}$/.test(result.sourceManifestSha256 ?? "") && /^[a-f0-9]{64}$/.test(result.environment?.officialImageDigest ?? "")
    && /^[a-f0-9]{64}$/.test(result.environment?.imageIdentityDigest ?? "") && /^[a-f0-9]{64}$/.test(result.environment?.imageAttestorDigest ?? ""), `平台 ${platformId} 缺少清单或官方镜像声明摘要`);
  assert(result.environment?.init === "systemd" && typeof result.environment?.kernel === "string" && result.environment.kernel.length > 0
    && typeof result.environment?.timezone === "string" && result.environment.timezone.length > 0, `平台 ${platformId} 缺少 PID 1、内核或时区观测`);
  assert(result.capabilities?.verified === true && /^[a-f0-9]{64}$/.test(result.capabilities?.digest ?? "")
    && result.capabilities?.verbs >= 8 && result.capabilities?.namespaces >= 2, `平台 ${platformId} 八原语能力不完整`);
  assert(result.evidence?.verified === true && result.evidence?.bytes > 0 && /^[a-f0-9]{64}$/.test(result.evidence?.sha256 ?? "")
    && /^[a-f0-9]{64}$/.test(result.evidence?.sourceIdentityDigest ?? ""), `平台 ${platformId} Evidence 传输证据无效`);
  assert(result.recovery?.verified === true && result.recovery?.reconnects >= 1 && result.recovery?.hostIdentityStable === true && result.recovery?.capabilitiesStable === true, `平台 ${platformId} SSH 重连恢复验收不完整`);
  assert(result.cleanup?.verified === true && result.cleanup?.finalAbsent === true, `平台 ${platformId} Artifact 清理未证实`);
  if (platformId.startsWith("ubuntu-24.04")) assert(result.environment?.distribution === "ubuntu" && String(result.environment?.version).startsWith("24.04"), `平台 ${platformId} 发行版观测不一致`);
  if (platformId === "ubuntu-24.04-arm64") assert(["aarch64", "arm64"].includes(String(result.environment?.architecture).toLowerCase()), "Ubuntu ARM64 平台架构不一致");
  else assert(["x86_64", "amd64"].includes(String(result.environment?.architecture).toLowerCase()), `平台 ${platformId} 不是 x86_64`);
  if (platformId === "debian-12-systemd-x86_64") assert(result.environment?.init === "systemd", "Debian 平台未在完整 systemd VM 验收");
  if (platformId === "debian-12-systemd-x86_64") assert(result.environment?.distribution === "debian" && String(result.environment?.version).startsWith("12"), "Debian 平台发行版观测不一致");
  if (platformId === "rocky-or-alma-9-x86_64-selinux-enforcing") assert(["rocky", "almalinux"].includes(result.environment?.distribution) && String(result.environment?.version).startsWith("9") && result.environment?.selinux === "Enforcing", "Rocky/Alma 平台发行版或 SELinux Enforcing 验收不一致");
  if (platformId === "amazon-linux-2023-x86_64") assert(result.environment?.distribution === "amzn" && String(result.environment?.version).startsWith("2023"), "Amazon Linux 2023 平台发行版观测不一致");
}
for (const platformId of requiredPlatforms) assert(seenPlatforms.has(platformId), `缺少目标平台证据: ${platformId}`);

if (failures.length > 0) {
  console.error(`HuntWarden 发布资格校验失败:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`HuntWarden 发布资格校验通过：commit=${currentCommit}，Provider/盲测/真实业务 JVM/${requiredPlatforms.size} 个平台证据完整`);
