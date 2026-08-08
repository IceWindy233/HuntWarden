import { describe, expect, it } from "vitest";
import { appConfig, exactObject, newTaskInput, text } from "../../src/desktop/ipc-validation.js";
import { testConfig, testTask } from "../helpers.js";

describe("桌面 IPC 参数边界", () => {
  it("拒绝额外字段、空字符串、NUL 与配置秘密", () => {
    expect(() => exactObject({ taskId: "A", command: "id" }, ["taskId"], "任务")).toThrow(/未知字段.*command/);
    expect(() => text("\0", "名称")).toThrow();
    expect(() => appConfig({ ...testConfig("/tmp/huntwarden"), apiKey: "secret" })).toThrow(/禁止包含秘密字段/);
  });

  it("任务输入去重检测项并执行目标注入校验", () => {
    const target = testTask().target;
    const parsed = newTaskInput({ request: "调查", mode: "SCAN", checks: ["webshell", "webshell"], target });
    expect(parsed.checks).toEqual(["webshell"]);
    expect(() => newTaskInput({ request: "调查", mode: "SCAN", checks: ["webshell"], target: { ...target, username: "secagent;id" } })).toThrow(/用户名/);
    expect(() => newTaskInput({ request: "调查", mode: "SCAN", checks: ["webshell"], target: { ...target, privateKeyPath: "relative/key" } })).toThrow(/绝对路径/);
  });
});
