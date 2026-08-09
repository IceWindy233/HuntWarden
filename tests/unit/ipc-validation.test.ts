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
    expect(newTaskInput({ request: "持久化调查", mode: "SCAN", checks: ["linux_persistence"], target }).checks).toEqual(["linux_persistence"]);
    expect(newTaskInput({ request: "入侵分诊", mode: "SCAN", checks: ["linux_intrusion_triage"], target }).checks).toEqual(["linux_intrusion_triage"]);
    expect(() => newTaskInput({ request: "调查", mode: "SCAN", checks: ["webshell"], target: { ...target, username: "secagent;id" } })).toThrow(/用户名/);
    expect(() => newTaskInput({ request: "调查", mode: "SCAN", checks: ["webshell"], target: { ...target, privateKeyPath: "relative/key" } })).toThrow(/绝对路径/);
  });

  it("规范化扫描预设、时间窗和五类 IOC", () => {
    const parsed = newTaskInput({
      request: "按 IOC 分诊",
      mode: "SCAN",
      checks: ["linux_intrusion_triage"],
      profile: "DEEP",
      timeWindowHours: 720,
      iocs: {
        hash: ["A".repeat(64), "a".repeat(64)],
        domain: ["Example.COM"],
        ip: ["2001:DB8::1"],
        path: ["/tmp/suspicious"],
        processName: ["sys-helper"],
      },
      target: testTask().target,
    });
    expect(parsed).toMatchObject({
      profile: "DEEP",
      timeWindowHours: 720,
      iocs: {
        hash: ["a".repeat(64)], domain: ["example.com"], ip: ["2001:db8::1"],
        path: ["/tmp/suspicious"], processName: ["sys-helper"],
      },
    });
  });

  it("拒绝越界预设、时间窗和非法或过量 IOC", () => {
    const base = { request: "入侵分诊", mode: "SCAN", checks: ["linux_intrusion_triage"], target: testTask().target };
    expect(() => newTaskInput({ ...base, profile: "TURBO" })).toThrow(/扫描预设/);
    expect(() => newTaskInput({ ...base, timeWindowHours: 1.5 })).toThrow(/时间窗/);
    expect(() => newTaskInput({ ...base, iocs: { ip: ["1.2.3.999"] } })).toThrow(/IOC ip/);
    expect(() => newTaskInput({ ...base, iocs: { path: ["relative/path"] } })).toThrow(/IOC path/);
    expect(() => newTaskInput({ ...base, iocs: { processName: ["bad/process"] } })).toThrow(/IOC processName/);
    expect(() => newTaskInput({ ...base, iocs: { domain: Array.from({ length: 101 }, (_, index) => `ioc${index}.example`) } })).toThrow(/不能超过 100/);
    expect(() => newTaskInput({ ...base, iocs: { domain: Array.from({ length: 100 }, (_, index) => `ioc${index}.example`), path: Array.from({ length: 100 }, (_, index) => `/tmp/${index}`), ip: ["192.0.2.1"] } })).toThrow(/总数不能超过 200/);
  });
});
