import type { AppConfig } from "../src/config/schema.js";
import type { TaskContext, TaskMode } from "../src/domain/types.js";

export function testConfig(baseDir: string): AppConfig {
  return {
    agent: { maxTurns: 30, maxToolCalls: 100, defaultMode: "SCAN", promptVersion: "test-v1" },
    model: { source: "builtin", provider: "openai", model: "gpt-5.6-terra", thinkingLevel: "medium" },
    executor: {
      type: "ssh", timeoutSeconds: 30, helperPath: "/usr/local/libexec/huntwarden-helper",
      knownHostsPath: `${baseDir}/known_hosts`, privateKeyPath: `${baseDir}/id_ed25519`,
    },
    storage: { baseDir, databaseFile: "runtime.db" },
    llmData: { maxTextBytes: 65_536 },
    webshell: { modifiedWithinHours: 168, maxCandidateFiles: 500, maxFileSizeBytes: 10 * 1024 * 1024, yaraRuleDir: `${baseDir}/rules` },
    java: { supportedContainers: ["tomcat"], allowClassDump: true, allowRuntimeModification: false, probeJar: `${baseDir}/probe.jar` },
    account: { checkAuthorizedKeys: true, checkLoginHistory: true },
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
    promptVersion: "test-v1", checks: ["webshell", "java_memory_shell", "backdoor_account"],
    coverage: {}, createdAt: now, updatedAt: now, turnCount: 0, toolCallCount: 0,
  };
}
