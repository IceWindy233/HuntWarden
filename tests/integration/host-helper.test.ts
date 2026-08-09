import { spawnSync } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const helper = resolve(projectRoot, "host-helper/huntwarden_helper.py");

function invoke(operation: string, input: unknown) {
  const result = spawnSync("python3", [helper, operation], { input: JSON.stringify(input), encoding: "utf8" });
  return { ...result, envelope: JSON.parse(result.stdout) as { ok: boolean; result?: unknown; error?: { code: string } } };
}

describe("目标辅助程序边界", () => {
  it("返回版本化能力清单并声明 Artifact 传输", () => {
    const result = invoke("get_capabilities", {});
    expect(result.status).toBe(0);
    expect(result.envelope).toMatchObject({ ok: true, result: {
      protocolVersion: 1,
      helper: { name: "huntwarden-helper" },
      artifactTransfer: { supported: true, protocolVersion: 1 },
      runtime: { euid: expect.any(Number), currentUser: expect.any(String), rootHelper: expect.any(Boolean) },
      securityContext: { hidepid: expect.any(String), pidNamespace: expect.any(String) },
      featureStatus: { linuxProc: { status: expect.stringMatching(/^(SUPPORTED|PARTIAL|UNSUPPORTED|PERMISSION_DENIED)$/), reason: expect.any(String) } },
    } });
    expect((result.envelope.result as { operations: string[] }).operations).toContain("collect_file");
    expect((result.envelope.result as { operations: string[] }).operations).toEqual(expect.arrayContaining([
      "capture_volatile_snapshot", "list_suspicious_processes", "inspect_process_tree",
      "inspect_process_fds", "inspect_process_memory_maps", "collect_process_executable",
      "list_recent_executables", "list_privileged_files", "verify_package_integrity",
      "inspect_dynamic_loader", "query_auth_events", "query_exec_events", "build_incident_timeline",
    ]));
  });

  it("采集文件只返回 Artifact Token，并可一次性释放", async () => {
    const source = resolve(projectRoot, "package.json");
    const result = invoke("collect_file", { path: source, maxBytes: 1024 * 1024 });
    expect(result.status).toBe(0);
    const output = result.envelope.result as { dataBase64?: string; artifact: { artifactToken: string; sha256: string; size: number } };
    expect(output.dataBase64).toBeUndefined();
    expect(output.artifact.artifactToken).toMatch(/^[a-f0-9]{64}$/);
    const staged = resolve(tmpdir(), "huntwarden-artifacts", `${output.artifact.artifactToken}.artifact`);
    expect((await readFile(staged)).length).toBe(output.artifact.size);
    expect(invoke("release_artifact", { artifactToken: output.artifact.artifactToken }).envelope).toMatchObject({ ok: true, result: { released: true } });
    await expect(access(staged)).rejects.toThrow();
  });

  it("不接受任意操作名", () => {
    const result = invoke("bash", { command: "id" });
    expect(result.status).toBe(2);
    expect(result.envelope).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
  });

  it("拒绝目录穿越", () => {
    const result = invoke("collect_file", { path: "/tmp/../etc/passwd", maxBytes: 1024 });
    expect(result.status).toBe(1);
    expect(result.envelope).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
  });

  it("拒绝危险用户名", () => {
    const result = invoke("inspect_account", { username: "root;id" });
    expect(result.status).toBe(1);
    expect(result.envelope).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
  });

  it("拒绝越界分诊预算和不完整的稳定进程身份", () => {
    const limit = invoke("capture_volatile_snapshot", { maxProcesses: 10001, maxConnections: 10 });
    expect(limit.envelope).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });

    const identity = invoke("inspect_process_fds", { pid: 1, bootId: "invalid", maxItems: 10 });
    expect(identity.envelope).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
  });

  it("包完整性核验拒绝目录穿越和非固定目录", () => {
    const traversal = invoke("verify_package_integrity", {
      path: "/tmp/../etc/passwd", expectedInode: "1", expectedSha256: "0".repeat(64),
    });
    expect(traversal.envelope).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });

    const outside = invoke("verify_package_integrity", {
      path: "/etc/passwd", expectedInode: "1", expectedSha256: "0".repeat(64),
    });
    expect(outside.envelope).toMatchObject({ ok: false, error: { code: "PERMISSION_DENIED" } });
  });
});
