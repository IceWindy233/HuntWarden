import { resolve } from "node:path";
import { Value } from "typebox/value";
import { describe, expect, it } from "vitest";
import { loadConfig, normalizeConfig } from "../../src/config/load-config.js";
import { ConfigSchema } from "../../src/config/schema.js";
import { testConfig } from "../helpers.js";

const SOURCE = "/tmp/huntwarden-config-budget/profile.yaml";

function legacyProfile(): Record<string, unknown> {
  const config = testConfig("/tmp/huntwarden-config-budget") as unknown as Record<string, unknown>;
  const webshell = { ...(config.webshell as Record<string, unknown>) };
  delete webshell.remoteRulePath;
  return {
    ...config,
    webshell,
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

describe("目标端 YARA 规则路径配置化", () => {
  it("出厂配置档提供目标端规则路径，且不参与控制端本地路径解析", async () => {
    for (const path of ["config/default.yaml", "config/deepseek.yaml"]) {
      const config = await loadConfig(resolve(path));
      expect(config.webshell.remoteRulePath).toBe("/opt/huntwarden/rules/webshell.yar");
      expect(config.webshell.yaraRuleDir).toBe(resolve("rules/yara"));
    }
  });

  it("旧 Profile 缺失时注入出厂目标端路径", () => {
    const migrated = normalizeConfig(legacyProfile(), SOURCE);
    expect(migrated.webshell.remoteRulePath).toBe("/opt/huntwarden/rules/webshell.yar");
  });

  it("拒绝相对路径、目录穿越与空字符", () => {
    const base = legacyProfile();
    const withPath = (remoteRulePath: string) => ({
      ...base,
      webshell: { ...(base.webshell as Record<string, unknown>), remoteRulePath },
    });
    expect(() => normalizeConfig(withPath("rules/webshell.yar"), SOURCE)).toThrow(/remoteRulePath 必须是目标端绝对路径/);
    expect(() => normalizeConfig(withPath("/opt/huntwarden/../etc/shadow"), SOURCE)).toThrow(/remoteRulePath 必须是目标端绝对路径/);
    expect(() => normalizeConfig(withPath("/opt/huntwarden/rules/webshell.yar\0"), SOURCE)).toThrow(/remoteRulePath 必须是目标端绝对路径/);
    expect(() => normalizeConfig(withPath(""), SOURCE)).toThrow(/配置校验失败/);
  });
});
