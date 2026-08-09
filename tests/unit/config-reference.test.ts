import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Value } from "typebox/value";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig, normalizeConfig } from "../../src/config/load-config.js";
import { ConfigSchema } from "../../src/config/schema.js";
import { validateTargetConfig } from "../../src/domain/validation.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createModelBundle } from "../../src/agent/model.js";
import { createReference, requireReference } from "../../src/tools/reference-utils.js";
import { testConfig, testTask } from "../helpers.js";
import YAML from "yaml";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("配置与不透明引用", () => {
  it("加载并校验默认 YAML，保留 OpenAI 默认模型与安全处置开关", async () => {
    const config = await loadConfig(resolve("config/default.yaml"));
    expect(Value.Check(ConfigSchema, config)).toBe(true);
    expect(config.model).toMatchObject({ source: "builtin", provider: "openai", model: "gpt-5.6-terra", thinkingLevel: "medium" });
    expect(config.remediation.requireApproval).toBe(true);
    expect(config.java.allowRuntimeModification).toBe(false);
    expect(config.storage.baseDir).toBe(resolve("data"));
  });

  it("加载 DeepSeek V4 配置档并匹配 Pi Tool Call Provider", async () => {
    const config = await loadConfig(resolve("config/deepseek.yaml"));
    expect(config.model).toMatchObject({
      source: "builtin", provider: "deepseek", model: "deepseek-v4-flash", thinkingLevel: "high",
    });
    const { model } = createModelBundle(config);
    expect(model).toMatchObject({ api: "openai-completions", baseUrl: "https://api.deepseek.com", reasoning: true });
  });

  it("为旧 Profile 纯增量注入持久化与入侵分诊预算默认值", () => {
    const legacy = testConfig("/tmp/huntwarden-config-migration") as unknown as Record<string, unknown>;
    delete legacy.persistence;
    delete legacy.triage;
    const migrated = normalizeConfig(legacy, "/tmp/huntwarden-config-migration/profile.yaml");
    expect(migrated.persistence).toEqual({ maxItemsPerSource: 500, includeUserScope: true, maxConnections: 500 });
    expect(migrated.triage).toEqual({ maxProcesses: 2_000, maxConnections: 5_000, maxFiles: 10_000, maxTimelineEvents: 10_000, maxArtifactBytes: 10_485_760 });
  });

  it("拒绝关闭审批，并允许选择 Pi 内置 Provider", () => {
    const config = testConfig("/tmp/huntwarden-config-test");
    expect(Value.Check(ConfigSchema, { ...config, remediation: { ...config.remediation, requireApproval: false } })).toBe(false);
    const anthropic = { ...config, model: { source: "builtin", provider: "anthropic", model: "claude-sonnet-4-5", thinkingLevel: "medium" } };
    expect(Value.Check(ConfigSchema, anthropic)).toBe(true);
    expect(createModelBundle(anthropic as typeof config).model.api).toBe("anthropic-messages");
    expect(() => createModelBundle({ ...config, model: { source: "builtin", provider: "not-installed", model: "model", thinkingLevel: "off" } })).toThrow(/不支持内置 Provider/);
  });

  it("创建自定义 OpenAI 兼容 Provider，凭据只从指定环境变量解析", async () => {
    const config = testConfig("/tmp/huntwarden-config-test");
    config.model = {
      source: "custom", provider: "company-gateway", model: "security-model", thinkingLevel: "off",
      protocol: "openai-completions", baseUrl: "https://llm.example.test/v1",
      authentication: { type: "api-key-env", apiKeyEnv: "HUNTWARDEN_TEST_LLM_KEY" },
      reasoning: false, contextWindow: 131_072, maxTokens: 16_384,
      compatibility: { supportsDeveloperRole: false, supportsReasoningEffort: false, supportsStrictMode: false },
    };
    process.env.HUNTWARDEN_TEST_LLM_KEY = "test-secret-not-real";
    try {
      const { models, model } = createModelBundle(config);
      expect(model).toMatchObject({ provider: "company-gateway", api: "openai-completions", baseUrl: "https://llm.example.test/v1" });
      const auth = await models.getAuth(model);
      expect(auth?.source).toBe("HUNTWARDEN_TEST_LLM_KEY");
      expect(auth?.auth.apiKey).toBe("test-secret-not-real");
    } finally {
      delete process.env.HUNTWARDEN_TEST_LLM_KEY;
    }
  });

  it("自定义端点拒绝远程 HTTP、URL 内凭据和远程无认证", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-model-config-"));
    directories.push(directory);
    const path = join(directory, "config.yaml");
    const config = testConfig(directory);
    const custom = {
      source: "custom", provider: "custom", model: "model", thinkingLevel: "off",
      protocol: "openai-completions", baseUrl: "http://llm.example.test/v1",
      authentication: { type: "api-key-env", apiKeyEnv: "HUNTWARDEN_TEST_LLM_KEY" },
      reasoning: false, contextWindow: 8192, maxTokens: 2048,
    } as const;
    await writeFile(path, YAML.stringify({ ...config, model: custom }));
    await expect(loadConfig(path)).rejects.toThrow(/必须使用 HTTPS/);
    await writeFile(path, YAML.stringify({ ...config, model: { ...custom, baseUrl: "https://user:secret@llm.example.test/v1" } }));
    await expect(loadConfig(path)).rejects.toThrow(/禁止包含凭据/);
    await writeFile(path, YAML.stringify({ ...config, model: { ...custom, baseUrl: "https://llm.example.test/v1", authentication: { type: "none" } } }));
    await expect(loadConfig(path)).rejects.toThrow(/无认证.*本机/);
  });

  it("引用严格绑定任务与类型", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-ref-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    store.createTask(task);
    const reference = createReference(store, task.taskId, "account", "account", { username: "labroot" });
    expect(requireReference(store, task.taskId, reference.ref, "account").value).toEqual({ username: "labroot" });
    expect(() => requireReference(store, "TASK-other", reference.ref, "account")).toThrow(/跨任务/);
    expect(() => requireReference(store, task.taskId, reference.ref, "candidate")).toThrow(/跨任务/);
    const persistence = createReference(store, task.taskId, "persistence", "persistence", { kind: "cron", path: "/etc/crontab" });
    expect(requireReference(store, task.taskId, persistence.ref, "persistence").value).toMatchObject({ kind: "cron" });
    expect(() => requireReference(store, "TASK-other", persistence.ref, "persistence")).toThrow(/跨任务/);
    store.close();
  });

  it("校验目标、用户名、指纹与本地路径", () => {
    const target = testTask().target;
    expect(() => validateTargetConfig(target)).not.toThrow();
    expect(() => validateTargetConfig({ ...target, username: "root;id" })).toThrow(/用户名/);
    expect(() => validateTargetConfig({ ...target, port: 70_000 })).toThrow(/端口/);
    expect(() => validateTargetConfig({ ...target, knownHostsPath: "relative/known_hosts" })).toThrow(/绝对路径/);
  });
});
