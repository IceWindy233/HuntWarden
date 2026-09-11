import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

interface EmbeddedBuildIdentity {
  schemaVersion: 1;
  commit: string;
  clean: true;
}

const commitPattern = /^[a-f0-9]{40}$/;
export interface ControllerBuildIdentity { commit: string; clean: boolean }

/**
 * 返回可审计的控制端提交。发布包读取构建时写入的身份文件；源码运行读取
 * HUNTWARDEN_BUILD_COMMIT 或当前 Git HEAD。无法证明时返回 undefined。
 */
export function resolveControllerBuildIdentity(): ControllerBuildIdentity | undefined {
  const declared = process.env.HUNTWARDEN_BUILD_COMMIT;
  if (declared !== undefined) {
    if (!commitPattern.test(declared)) throw new Error("HUNTWARDEN_BUILD_COMMIT 必须是完整 40 位小写 Git SHA-1");
    return { commit: declared, clean: process.env.HUNTWARDEN_BUILD_CLEAN === "true" };
  }

  const moduleRoot = fileURLToPath(new URL("../../", import.meta.url));
  try {
    const embedded = JSON.parse(readFileSync(resolve(moduleRoot, "build-identity.json"), "utf8")) as Partial<EmbeddedBuildIdentity>;
    if (embedded.schemaVersion === 1 && embedded.clean === true && typeof embedded.commit === "string" && commitPattern.test(embedded.commit)) {
      return { commit: embedded.commit, clean: true };
    }
  } catch {
    // 源码运行通常没有嵌入文件，继续读取 Git。
  }

  for (const directory of [moduleRoot, resolve(moduleRoot, ".."), process.cwd()]) {
    try {
      const value = execFileSync("git", ["rev-parse", "HEAD"], { cwd: directory, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      if (commitPattern.test(value)) {
        const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: directory, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
        return { commit: value, clean: dirty.length === 0 };
      }
    } catch {
      // 尝试下一个可能的项目根目录。
    }
  }
  return undefined;
}

export function resolveControllerCommit(): string | undefined {
  return resolveControllerBuildIdentity()?.commit;
}
