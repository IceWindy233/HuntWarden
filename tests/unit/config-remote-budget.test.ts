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
    webshell: { ...(config.webshell as unknown as Record<string, unknown>), remoteRulePath: "/tmp/model-selected.yar" },
    persistence: { maxItemsPerSource: 500, includeUserScope: true, maxConnections: 500 },
    triage: { maxProcesses: 10_000, maxConnections: 20_000, maxFiles: 50_000, maxTimelineEvents: 50_000, maxArtifactBytes: 10_485_760 },
  };
}

describe("采集数量上限与传输预算对齐", () => {
  it("triage 上限收敛到 5000，超限配置被拒绝", () => {
    const config = testConfig("/tmp/huntwarden-config-budget");
    for (const key of ["maxProcesses", "maxConnections", "maxFiles", "maxTimelineEvents"] as const) {
      expect(Value.Check(ConfigSchema, { ...config, triage: { ...config.triage, [key]: 5_000 } })).toBe(true);
      expect(Value.Check(ConfigSchema, { ...config, triage: { ...config.triage, [key]: 5_001 } })).toBe(false);
    }
  });

  it("出厂配置档的采集上限都在预算内", async () => {
    for (const path of ["config/default.yaml", "config/deepseek.yaml"]) {
      const config = await loadConfig(resolve(path));
      expect(config.triage.maxProcesses).toBeLessThanOrEqual(5_000);
      expect(config.triage.maxConnections).toBeLessThanOrEqual(5_000);
      expect(config.triage.maxFiles).toBeLessThanOrEqual(5_000);
      expect(config.triage.maxTimelineEvents).toBeLessThanOrEqual(5_000);
    }
  });

  it("旧 Profile 的超限预算被收敛而不是拒绝加载", () => {
    const migrated = normalizeConfig(legacyProfile(), SOURCE);
    expect(migrated.triage).toMatchObject({
      maxProcesses: 5_000, maxConnections: 5_000, maxFiles: 5_000, maxTimelineEvents: 5_000,
    });
  });

  it("退役的 persistence.maxConnections 被清除，进程连接预算只来自 triage", () => {
    const migrated = normalizeConfig(legacyProfile(), SOURCE);
    expect(migrated.persistence).toEqual({ maxItemsPerSource: 500, includeUserScope: true });
    expect(Object.keys(migrated.persistence)).not.toContain("maxConnections");
  });
});

describe("v2 退役配置迁移", () => {
  it("目标端 YARA 路径不可配置，出厂配置只保留内置 RuleSet 资产目录", async () => {
    for (const path of ["config/default.yaml", "config/deepseek.yaml"]) {
      const config = await loadConfig(resolve(path));
      expect(config.webshell.yaraRuleDir).toBe(resolve("rules/yara"));
      expect(Object.keys(config.webshell)).not.toContain("remoteRulePath");
    }
  });

  it("旧 Profile 的 V1 Tool Call/Planner 与远程规则路径键会被删除", () => {
    const migrated = normalizeConfig(legacyProfile(), SOURCE);
    expect(Object.keys(migrated.agent)).not.toEqual(expect.arrayContaining(["maxToolCalls", "plannerToolCallShare"]));
    expect(Object.keys(migrated.webshell)).not.toContain("remoteRulePath");
  });
});
