import { describe, expect, it } from "vitest";
import { SSHExecutor, sshFingerprint } from "../../src/executor/ssh-executor.js";
import { testTask } from "../helpers.js";

describe("SSHExecutor", () => {
  it("按 OpenSSH SHA-256 格式计算主机指纹", () => {
    expect(sshFingerprint(Buffer.from("host-key"))).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
  });

  it("拒绝辅助程序路径注入和目录穿越", () => {
    const target = testTask().target;
    expect(() => new SSHExecutor(target, "/usr/local/helper;id")).toThrow();
    expect(() => new SSHExecutor(target, "/usr/local/../bin/helper")).toThrow();
  });

  it("运行时也拒绝伪造的 HostOperation", async () => {
    const executor = new SSHExecutor(testTask().target, "/usr/local/libexec/huntwarden-helper");
    await expect(executor.invoke({ operation: "get_host_info;id", params: {} } as never)).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });
});
