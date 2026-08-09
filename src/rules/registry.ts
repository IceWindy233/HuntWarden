import type { DeterministicRuleDefinition } from "./types.js";

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

const persistenceSteps = ["cron", "systemd", "ssh-persistence", "shell-startup"] as const;
const strongPersistenceFeatures = new Set(["download_execute", "encoded_payload", "network_listener", "temporary_execution"]);

export const DETERMINISTIC_RULES: readonly DeterministicRuleDefinition[] = [
  {
    ruleId: "HW-WEB-MINIMUM-001",
    ruleVersion: "1.0.0",
    category: "webshell",
    requiredStepIds: ["web-roots", "web-candidates"],
    evaluate: (context) => {
      const roots = context.items("web-roots");
      const candidates = context.items("web-candidates");
      if (roots.length === 0 || candidates.length > 0) return undefined;
      return {
        status: "NO_FINDING",
        severity: "INFO",
        confidence: 0.55,
        title: "最低 WebShell 规则未发现近期候选脚本",
        basis: [`已发现 ${roots.length} 个 Web Root`, "限定时间窗内近期脚本候选数为 0"],
        counterEvidence: ["仅覆盖配置发现的 Web Root 与限定时间窗，不代表历史文件或未识别目录绝对安全"],
        evidenceRefs: context.evidenceRefs(["web-roots", "web-candidates"]),
      };
    },
  },
  {
    ruleId: "HW-ACCOUNT-UID0-001",
    ruleVersion: "1.0.0",
    category: "backdoor_account",
    requiredStepIds: ["privileged-accounts"],
    evaluate: (context) => {
      const accounts = context.items("privileged-accounts");
      const extraUidZero = accounts.filter((account) => Number(account.uid) === 0 && text(account.username) !== "root");
      const refs = context.evidenceRefs(["privileged-accounts"]);
      if (extraUidZero.length > 0) {
        return {
          status: "SUSPICIOUS",
          severity: "MEDIUM",
          confidence: 0.8,
          title: "发现非 root 名称的 UID 0 账户",
          basis: extraUidZero.slice(0, 20).map((account) => `账户 ${text(account.username) || "<unknown>"} 的 UID 为 0`),
          counterEvidence: ["尚未结合账户创建来源、授权变更单、SSH Key 与登录历史，基础规则不提升为高危"],
          evidenceRefs: refs,
          recommendation: "核验账户创建来源，并使用 accountRef 继续检查账户状态、SSH Key 指纹和登录历史。",
        };
      }
      return {
        status: "NO_FINDING",
        severity: "INFO",
        confidence: 0.6,
        title: "最低账户规则未发现额外 UID 0 账户",
        basis: [`已枚举 ${accounts.length} 个特权或低 UID 交互账户`, "未发现用户名非 root 的 UID 0 账户"],
        counterEvidence: ["sudo/wheel 成员、SSH Key 和登录行为仍需按引用深入核验"],
        evidenceRefs: refs,
      };
    },
  },
  {
    ruleId: "HW-PERSIST-CONTEXT-001",
    ruleVersion: "1.0.0",
    category: "linux_persistence",
    requiredStepIds: persistenceSteps,
    evaluate: (context) => {
      const risky: { stepId: string; item: Record<string, unknown>; features: string[] }[] = [];
      for (const stepId of persistenceSteps) {
        for (const item of context.items(stepId)) {
          const features = array(item.features).map(text).filter((feature) => strongPersistenceFeatures.has(feature));
          if (features.length > 0) risky.push({ stepId, item, features });
        }
      }
      const refs = context.evidenceRefs(persistenceSteps);
      if (risky.length > 0) {
        return {
          status: "SUSPICIOUS",
          severity: "MEDIUM",
          confidence: 0.72,
          title: "持久化执行上下文包含强异常特征",
          basis: risky.slice(0, 20).map(({ stepId, item, features }) => `${stepId}: ${text(item.path) || text(item.unit) || "<item>"} 命中 ${features.join(",")}`),
          counterEvidence: ["规则同时要求固定持久化上下文与强特征，但尚未验证命令来源、文件内容和关联进程，因此不提升为高危"],
          evidenceRefs: refs,
          recommendation: "使用 persistenceRef 检查原始项、关联进程与连接，并在结论升级前采集原始文件。",
        };
      }
      const count = persistenceSteps.reduce((total, stepId) => total + context.items(stepId).length, 0);
      return {
        status: "NO_FINDING",
        severity: "INFO",
        confidence: 0.55,
        title: "最低持久化规则未命中强异常组合",
        basis: [`四类持久化源共枚举 ${count} 项`, "未发现持久化上下文叠加下载执行、编码载荷、监听或临时目录执行特征"],
        counterEvidence: ["未知 SSH Key 需要可信指纹基线；普通解释器关键词不会单独定性；每个持久化项尚未全部深度检查"],
        evidenceRefs: refs,
      };
    },
  },
  {
    ruleId: "HW-TRIAGE-PROCESS-001",
    ruleVersion: "1.0.0",
    category: "linux_intrusion_triage",
    requiredStepIds: ["suspicious-processes"],
    evaluate: (context) => {
      const processes = context.items("suspicious-processes");
      const refs = context.evidenceRefs(["suspicious-processes"]);
      if (processes.length > 0) {
        return {
          status: "SUSPICIOUS",
          severity: "MEDIUM",
          confidence: 0.78,
          title: "发现具有固定结构异常信号的运行进程",
          basis: processes.slice(0, 20).map((process) => `PID ${String(process.pid ?? "?")} ${text(process.exePath) || text(process.comm) || "<unknown>"}: ${array(process.signals).map(text).join(",")}`),
          counterEvidence: ["基础规则只确认进程结构异常，尚未结合父子链、文件来源、内存映射与网络事实，不提升为高危"],
          evidenceRefs: refs,
          recommendation: "通过 processRef 继续检查进程树、FD、内存映射、网络连接并采集可执行文件。",
        };
      }
      return {
        status: "NO_FINDING",
        severity: "INFO",
        confidence: 0.55,
        title: "最低进程分诊规则未发现结构异常进程",
        basis: ["固定范围进程枚举完成", "未发现删除后运行、临时/隐藏可执行文件、异常可执行映射等结构信号"],
        counterEvidence: ["仅覆盖当前易失性进程视图，不包含历史执行、完整文件完整性或全部认证行为"],
        evidenceRefs: refs,
      };
    },
  },
];
