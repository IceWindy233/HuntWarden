import { describe, expect, it } from "vitest";
import { SSHExecutor, sshFingerprint, validateRemoteArtifactMetadata } from "../../src/executor/ssh-executor.js";
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

  it("控制端执行器只暴露 v2 Capability、Wire 与制品接口", () => {
    const executor = new SSHExecutor(testTask().target, "/usr/local/libexec/huntwarden-helper");
    expect("invoke" in executor).toBe(false);
    expect(typeof executor.invokeV2).toBe("function");
    expect(typeof executor.invokeMaintenanceV2).toBe("function");
  });

  it("Artifact 元数据不使用控制端墙钟拒绝时钟漂移的目标", () => {
    const artifact = {
      artifactToken: "a".repeat(64), sha256: "b".repeat(64), size: 123,
      expiresAt: "2020-01-01T00:00:00.000Z",
    };
    expect(() => validateRemoteArtifactMetadata(artifact)).not.toThrow();
    expect(() => validateRemoteArtifactMetadata({ ...artifact, expiresAt: "not-a-time" })).toThrow(/expiresAt/);
  });
});
