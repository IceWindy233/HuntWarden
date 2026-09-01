import type { AppConfig } from "../src/config/schema.js";
import type { TaskContext, TaskMode } from "../src/domain/types.js";

export function testConfig(baseDir: string): AppConfig {
  return {
    schemaVersion: 2,
    protocolV2: {
      remoteBudget: {
        preset: { remoteCalls: 100, nodes: 50_000, bytes: 256 * 1024 * 1024, wallTimeMs: 3_600_000, probeCalls: 100 },
        model: { remoteCalls: 100, nodes: 50_000, bytes: 256 * 1024 * 1024, wallTimeMs: 3_600_000, probeCalls: 100 },
      },
      localQueryBudget: { calls: 500, rows: 100_000, wallTimeMs: 3_600_000 },
      externalIntelBudget: { calls: 500, iocs: 10_000, wallTimeMs: 3_600_000 },
      dataPolicy: { modelContentBytes: 4 * 1024 * 1024, evidenceBytes: 256 * 1024 * 1024, defaultTextClass: "SENSITIVE_TEXT" },
      grants: { maxRequests: 20, pendingExpiresOnInterruption: true },
    },
    agent: { maxTurns: 30, contextRetainTurns: 3, providerMaxRetries: 2, providerTimeoutSeconds: 600, defaultMode: "SCAN", promptVersion: "test-v2" },
    model: { source: "builtin", provider: "openai", model: "gpt-5.6-terra", thinkingLevel: "medium" },
    executor: {
      type: "ssh", timeoutSeconds: 30, helperPath: "/usr/local/libexec/huntwarden-helper",
      knownHostsPath: `${baseDir}/known_hosts`, privateKeyPath: `${baseDir}/id_ed25519`,
    },
    storage: { baseDir, databaseFile: "runtime.db" },
    llmData: { maxTextBytes: 65_536 },
    webshell: {
      modifiedWithinHours: 168, maxCandidateFiles: 500, maxFileSizeBytes: 10 * 1024 * 1024,
      maxScriptExcerptBytes: 65_536, maxAccessLogLines: 500,
      yaraRuleDir: `${baseDir}/rules`,
    },
    java: { supportedContainers: ["tomcat"], allowClassDump: true, allowRuntimeModification: false, probeJar: `${baseDir}/probe.jar` },
    account: { checkAuthorizedKeys: true, checkLoginHistory: true, maxLoginHistoryEntries: 100 },
    persistence: { maxItemsPerSource: 500, includeUserScope: true },
    triage: { maxProcesses: 2_000, maxConnections: 5_000, maxFiles: 5_000, maxTimelineEvents: 5_000, maxArtifactBytes: 10 * 1024 * 1024, maxProcessTreeDepth: 12 },
    threatIntel: {
      enabled: false, provider: "dbapp-ti", baseUrl: "https://ti.dbappsecurity.com.cn/oapi/v1/",
      apiKeyEnv: "DBAPP_TI_API_KEY", timeoutSeconds: 15, maxBatchSize: 100, cacheTtlSeconds: 3_600,
      autoEnrichConnections: true, includePrivateAddresses: false,
    },
    remediation: { requireApproval: true, allowedTools: ["quarantine_file", "disable_account"], quarantineRoot: "/var/lib/huntwarden/quarantine" },
  };
}

export function testTask(mode: TaskMode = "SCAN"): TaskContext {
  const now = new Date().toISOString();
  return {
    taskId: "TASK-00000000-0000-4000-8000-000000000001",
    request: "执行主机安全检测",
    target: {
      host: "127.0.0.1", port: 2222, username: "secagent",
      hostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", privateKeyPath: "/tmp/id_ed25519", knownHostsPath: "/tmp/known_hosts",
    },
    mode, status: "CREATED", modelProvider: "openai", modelId: "gpt-5.6-terra",
    promptVersion: "test-v2", checks: ["webshell", "java_memory_shell", "backdoor_account"],
    createdAt: now, updatedAt: now, turnCount: 0, toolCallCount: 0,
  };
}
