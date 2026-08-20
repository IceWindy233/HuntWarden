import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const projectRoot = resolve(import.meta.dirname, "../..");

describe("Artifact spool 权限不变量", () => {
  it("安装期允许 SSH 用户穿越状态根目录，但继续保护 Action Receipt", async () => {
    const installer = await readFile(resolve(projectRoot, "host-helper/install-helper.sh"), "utf8");
    expect(installer).toContain('readonly STATE_ROOT_MODE="0711"');
    expect(installer).toContain(`install -d -o root -g root -m "\${STATE_ROOT_MODE}" "\${DEFAULT_STATE_ROOT}"`);
    expect(installer).toContain(`install -d -o root -g root -m 0700 "\${DEFAULT_STATE_ROOT}/actions"`);
  });

  it("运行期修复旧安装的父目录权限，避免 Artifact 文件可读但路径不可穿越", async () => {
    const helper = await readFile(resolve(projectRoot, "host-helper/huntwarden_helper.py"), "utf8");
    expect(helper).toContain("os.chmod(state_root, 0o711)");
    expect(helper).toContain("os.chmod(ARTIFACT_DIR, 0o711)");
    expect(helper).toContain("os.chmod(destination, 0o400)");
  });
});
