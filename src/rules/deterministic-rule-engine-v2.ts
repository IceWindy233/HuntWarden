import { randomUUID } from "node:crypto";
import type { CheckCategory, Severity } from "../domain/types.js";
import type { Assessment, AssessmentVerdict, FactRecord } from "../protocol-v2/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";

interface V2Rule {
  ruleId: string;
  version: string;
  category: CheckCategory;
  namespace: FactRecord["namespace"];
  verdict: Extract<AssessmentVerdict, "SUSPICIOUS" | "HIGHLY_SUSPICIOUS">;
  severity: Severity;
  confidence: number;
  matches(payload: Record<string, unknown>): boolean;
  rationale(payload: Record<string, unknown>): string;
}

export const DETERMINISTIC_RULES_V2: readonly V2Rule[] = [
  {
    ruleId: "HW2-ACCOUNT-UID0-001", version: "2.0.0", category: "backdoor_account", namespace: "account",
    verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.8,
    matches: (payload) => Number(payload.uid) === 0 && payload.username !== "root",
    rationale: (payload) => `账户 ${String(payload.username)} 使用 UID 0；需结合授权来源、SSH trust 和登录事件裁定。`,
  },
  {
    ruleId: "HW2-PROCESS-TEMP-001", version: "2.0.0", category: "linux_intrusion_triage", namespace: "process",
    verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.7,
    matches: (payload) => typeof payload.exe === "string" && ["/tmp/", "/var/tmp/", "/dev/shm/"].some((prefix) => String(payload.exe).startsWith(prefix)),
    rationale: (payload) => `进程可执行文件位于临时目录：${String(payload.exe)}；需关联父子链、socket 与文件基线。`,
  },
  {
    ruleId: "HW2-PERSIST-DOWNLOAD-001", version: "2.0.0", category: "linux_persistence", namespace: "persistence",
    verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.72,
    matches: (payload) => typeof payload.command === "string" && /\b(?:curl|wget)\b.*(?:\||&&|;)\s*(?:ba|z|da)?sh\b/i.test(payload.command),
    rationale: () => "持久化命令包含下载后直接交给解释器执行的组合；需读取来源并固化完整 Evidence。",
  },
  {
    ruleId: "HW2-WEB-EXECUTABLE-001", version: "2.0.0", category: "webshell", namespace: "file",
    verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.62,
    matches: (payload) => typeof payload.path === "string" && /\.(?:php\d*|phtml|jsp|jspx|asp|aspx)$/i.test(payload.path),
    rationale: (payload) => `Web 范围内发现可执行脚本候选：${String(payload.path)}；文件类型本身不是恶意结论，需 match/read/日志关联。`,
  },
  {
    ruleId: "HW2-ACCOUNT-PRIVILEGED-001", version: "2.1.0", category: "backdoor_account", namespace: "account",
    verdict: "SUSPICIOUS", severity: "LOW", confidence: 0.58,
    matches: (payload) => Number(payload.uid) !== 0 && Array.isArray(payload.groups) && payload.groups.some((group) => ["sudo", "wheel", "admin"].includes(String(group).toLowerCase())),
    rationale: (payload) => `非 root 账户 ${String(payload.username)} 属于高权限组；需结合账户基线、SSH trust 与登录事件复核授权来源。`,
  },
  {
    ruleId: "HW2-PERSIST-TEMP-EXEC-001", version: "2.1.0", category: "linux_persistence", namespace: "unit",
    verdict: "HIGHLY_SUSPICIOUS", severity: "HIGH", confidence: 0.82,
    matches: (payload) => typeof payload.execStart === "string" && /(?:^|\s)(?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/.test(payload.execStart),
    rationale: (payload) => `systemd 单元 ${String(payload.name)} 从临时目录启动程序；需固化 unit 文件与目标文件。`,
  },
  {
    ruleId: "HW2-CRON-TEMP-EXEC-001", version: "2.1.0", category: "linux_persistence", namespace: "cron_entry",
    verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.76,
    matches: (payload) => typeof payload.command === "string" && /(?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/.test(payload.command),
    rationale: (payload) => `Cron 来源 ${String(payload.source)} 执行临时目录内容；需复核来源文件、文件身份与执行历史。`,
  },
  {
    ruleId: "HW2-JAVA-CLASS-SOURCE-001", version: "2.1.0", category: "java_memory_shell", namespace: "class",
    verdict: "SUSPICIOUS", severity: "HIGH", confidence: 0.78,
    matches: (payload) => payload.modifiable === true && (typeof payload.codeSource !== "string" || payload.codeSource.length === 0 || /(?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/.test(payload.codeSource)),
    rationale: (payload) => `可修改类 ${String(payload.className)} 的代码来源缺失或位于临时目录；需结合组件映射和 bytecode SHA-256 裁定。`,
  },
  {
    ruleId: "HW2-EXEC-TEMP-001", version: "2.1.0", category: "linux_intrusion_triage", namespace: "exec_event",
    verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.7,
    matches: (payload) => typeof payload.executable === "string" && ["/tmp/", "/var/tmp/", "/dev/shm/"].some((prefix) => String(payload.executable).startsWith(prefix)),
    rationale: (payload) => `执行事件显示临时目录程序：${String(payload.executable)}；需关联进程身份、文件与网络连接。`,
  },
  {
    ruleId: "HW2-DELEGATION-NOPASSWD-ALL-001", version: "2.2.0", category: "backdoor_account", namespace: "delegation_rule",
    verdict: "HIGHLY_SUSPICIOUS", severity: "HIGH", confidence: 0.84,
    matches: (payload) => payload.mechanism === "sudo" && typeof payload.statement === "string" && /\bNOPASSWD\s*:\s*ALL(?:\s|$)/i.test(payload.statement),
    rationale: (payload) => `委派配置 ${String(payload.source)}:${String(payload.line)} 授予无密码执行任意命令；需确认主体、来源和变更授权。`,
  },
  {
    ruleId: "HW2-SSH-ROOT-LOGIN-001", version: "2.2.0", category: "backdoor_account", namespace: "ssh_trust_config",
    verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.74,
    matches: (payload) => payload.effective === true && payload.directive === "permitrootlogin" && payload.value === "yes",
    rationale: () => "sshd 有效配置允许 root 直接登录；需结合 root 授权密钥、认证方式和登录事件复核。",
  },
  {
    ruleId: "HW2-PACKAGE-INTEGRITY-001", version: "2.2.0", category: "linux_intrusion_triage", namespace: "file",
    verdict: "HIGHLY_SUSPICIOUS", severity: "HIGH", confidence: 0.88,
    matches: (payload) => payload.baseline === "package_db" && payload.baselineStatus === "MISMATCH",
    rationale: (payload) => `文件 ${String(payload.path)} 与软件包数据库基线不一致；需固化 Evidence 并关联进程、持久化和执行事件。`,
  },
];

/**
 * 规则入口强制使用当前 PresetRun Fact；调用方无法传入任意 Fact Query（INV-15）。
 */
export class DeterministicRuleEngineV2 {
  constructor(private readonly store: RuntimeStore, private readonly registry: readonly V2Rule[] = DETERMINISTIC_RULES_V2) {}

  evaluate(taskId: string, epochId: string, presetRunPrefix: string): Assessment[] {
    const task = this.store.getTask(taskId);
    if (!task || task.activeEpochId !== epochId) return [];
    const facts = this.store.listFacts(taskId, epochId, { sourceKind: "PRESET" })
      .filter((fact) => fact.source.presetRunId === presetRunPrefix);
    const created: Assessment[] = [];
    for (const rule of this.registry) {
      if (!task.checks.includes(rule.category)) continue;
      for (const fact of facts.filter((item) => item.namespace === rule.namespace && rule.matches(item.privatePayload))) {
        const assessment: Assessment = {
          assessmentId: `ASM-${randomUUID()}`, taskId, epochId, authorType: "RULE", category: rule.category,
          subjectRef: fact.subjectRef, scope: "SUBJECT", verdict: rule.verdict, severity: rule.severity,
          confidence: fact.completeness === "PARTIAL" ? Math.min(rule.confidence, 0.65) : rule.confidence,
          rationale: `${rule.ruleId}@${rule.version}: ${rule.rationale(fact.modelPayload)}${fact.completeness === "PARTIAL" ? " 输入为 PARTIAL，未覆盖范围必须继续调查。" : ""}`,
          evidenceRefs: [], factRefs: [fact.factId], queryRefs: [], createdAt: new Date().toISOString(),
        };
        this.store.putAssessment(assessment); created.push(assessment);
      }
    }
    return created;
  }
}
