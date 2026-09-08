import { describe, expect, it } from "vitest";
import { optionValue } from "../../src/cli/options.js";
import { parseQualificationTarget } from "../../src/cli/qualification-target.js";

describe("验收 CLI 参数", () => {
  it("读取显式 --config 并拒绝缺值或重复参数", () => {
    expect(optionValue(["--config", "/tmp/profile.yaml"], "--config")).toBe("/tmp/profile.yaml");
    expect(() => optionValue(["--config"], "--config")).toThrow(/缺少参数值/);
    expect(() => optionValue(["--config", "a", "--config", "b"], "--config")).toThrow(/不能重复/);
    expect(() => optionValue([], "--config", true)).toThrow(/缺少必需参数/);
  });

  it("严格解析目标 YAML", () => {
    const valid = `
host: 192.0.2.10
port: 22
username: analyst
hostFingerprint: SHA256:abcdefghijklmnopqrstuvwxyz1234567890ABCD
privateKeyPath: /tmp/operator_ed25519
knownHostsPath: /tmp/known_hosts
`;
    expect(parseQualificationTarget(valid, "target.yaml")).toMatchObject({ host: "192.0.2.10", port: 22, username: "analyst" });
    expect(() => parseQualificationTarget(`${valid}\npassword: secret\n`, "target.yaml")).toThrow(/未知字段/);
    expect(() => parseQualificationTarget(valid.replace("/tmp/operator_ed25519", "relative-key"), "target.yaml")).toThrow(/绝对路径/);
  });
});
