import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const helperPath = resolve(import.meta.dirname, "../../host-helper/huntwarden_helper.py");

describe("Helper 可选 Linux 配置路径语义", () => {
  it("缺失的 doas/Polkit 配置不降低账户调查覆盖，真实 I/O 错误仍会记录", async () => {
    const helper = await readFile(helperPath, "utf8");
    expect(helper).toContain("except FileNotFoundError:\n        return \"unavailable\"");
    expect(helper).toContain("except OSError:\n        ledger.add(SKIP_UNREADABLE)");
    expect(helper).toContain("if optional_path_kind(root, ledger, follow=True) == \"directory\"");
    expect(helper).toContain("if optional_path_kind(path, ledger) != \"file\"");
  });
});
