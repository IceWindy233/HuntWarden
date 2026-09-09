import { resolve } from "node:path";
import { Value } from "typebox/value";
import { describe, expect, it } from "vitest";
import { loadConfig, normalizeConfig } from "../../src/config/load-config.js";
import { ConfigSchema } from "../../src/config/schema.js";
import { testConfig } from "../helpers.js";

const SOURCE = "/tmp/huntwarden-config-budget/profile.yaml";

function legacyProfile(): Record<string, unknown> {
  const config = testConfig("/tmp/huntwarden-config-budget") as unknown as Record<string, unknown>;
  return {
    ...config,
    agent: { ...(config.agent as unknown as Record<string, unknown>), maxToolCalls: 100, plannerToolCallShare: 0.5 },
    webshell: {
      ...(config.webshell as unknown as Record<string, unknown>), remoteRulePath: "/tmp/model-selected.yar",
      maxCandidateFiles: 500, maxFileSizeBytes: 10_485_760, maxScriptExcerptBytes: 65_536, maxAccessLogLines: 500,
      yaraRuleDir: "/tmp/rules",
    },
    java: { supportedContainers: ["tomcat"], allowClassDump: true, allowRuntimeModification: false, probeJar: "/tmp/probe.jar" },
    account: { checkAuthorizedKeys: true, checkLoginHistory: true, maxLoginHistoryEntries: 100 },
    persistence: { maxItemsPerSource: 500, includeUserScope: true, maxConnections: 500 },
    triage: { maxProcesses: 10_000, maxConnections: 20_000, maxFiles: 50_000, maxTimelineEvents: 50_000, maxArtifactBytes: 10_485_760 },
    threatIntel: { ...(config.threatIntel as Record<string, unknown>), autoEnrichConnections: true, includePrivateAddresses: false },
  };
}

describe("V2 配置面", () => {
  it("只接受真正生效的预算和数据策略字段", () => {
    const config = testConfig("/tmp/huntwarden-config-budget");
    expect(Value.Check(ConfigSchema, config)).toBe(true);
    expect(Value.Check(ConfigSchema, { ...config, triage: { maxProcesses: 5_000 } })).toBe(false);
    expect(Value.Check(ConfigSchema, { ...config, protocolV2: { ...config.protocolV2, unknownBudget: 1 } })).toBe(false);
    expect(Value.Check(ConfigSchema, { ...config, webshell: { modifiedWithinHours: 8_761 } })).toBe(false);
  });

  it("出厂配置仅包含规范 V2 配置", async () => {
    for (const path of ["config/default.yaml", "config/deepseek.yaml"]) {
      const config = await loadConfig(resolve(path));
      expect(Value.Check(ConfigSchema, config)).toBe(true);
      expect(Object.keys(config)).not.toEqual(expect.arrayContaining(["java", "account", "persistence", "triage"]));
      expect(config.webshell).toEqual({ modifiedWithinHours: 168 });
      expect(config.protocolV2.remoteBudget.preset.remoteCalls).toBeGreaterThan(0);
    }
  });

  it("旧 Profile 的检测细分旋钮和路径字段在保存前被删除", () => {
    const migrated = normalizeConfig(legacyProfile(), SOURCE);
    expect(Object.keys(migrated)).not.toEqual(expect.arrayContaining(["java", "account", "persistence", "triage"]));
    expect(migrated.webshell).toEqual({ modifiedWithinHours: 168 });
    expect(Object.keys(migrated.threatIntel)).not.toEqual(expect.arrayContaining(["autoEnrichConnections", "includePrivateAddresses"]));
  });

  it("schemaVersion 1 Profile 会注入 V2 预算并同时清理退役配置", () => {
    const legacy = legacyProfile();
    legacy.schemaVersion = 1;
    delete legacy.protocolV2;
    const migrated = normalizeConfig(legacy, SOURCE);
    expect(migrated.schemaVersion).toBe(2);
    expect(migrated.protocolV2.remoteBudget.preset).toMatchObject({ remoteCalls: 80, nodes: 20_000, probeCalls: 64 });
    expect(Object.keys(migrated)).not.toEqual(expect.arrayContaining(["java", "account", "persistence", "triage"]));
  });

  it("旧 Profile 的 V1 Tool Call/Planner 键会被删除", () => {
    const migrated = normalizeConfig(legacyProfile(), SOURCE);
    expect(Object.keys(migrated.agent)).not.toEqual(expect.arrayContaining(["maxToolCalls", "plannerToolCallShare"]));
  });

  it("除明确迁移的退役键外，未知配置始终 fail-close", () => {
    expect(() => normalizeConfig({ ...legacyProfile(), unknownTopLevel: true }, SOURCE)).toThrow(/unknownTopLevel|Unexpected property/);
    const config = testConfig("/tmp/huntwarden-config-budget") as unknown as Record<string, unknown>;
    config.webshell = { ...(config.webshell as Record<string, unknown>), unknownWindow: 24 };
    expect(() => normalizeConfig(config, SOURCE)).toThrow(/unknownWindow|Unexpected property/);
  });
});
