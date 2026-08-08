import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const helper = resolve(projectRoot, "host-helper/huntwarden_helper.py");

function invoke(operation: string, input: unknown) {
  const result = spawnSync("python3", [helper, operation], { input: JSON.stringify(input), encoding: "utf8" });
  return { ...result, envelope: JSON.parse(result.stdout) as { ok: boolean; error?: { code: string } } };
}

describe("目标辅助程序边界", () => {
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
});
