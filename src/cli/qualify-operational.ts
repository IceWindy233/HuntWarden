import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { optionValue } from "./options.js";
import { parseOperationalHostResult, runOperationalReadiness } from "../qualification/operational-readiness.js";

const args = process.argv.slice(2);
const dataDir = resolve(optionValue(args, "--data-dir", true)!);
const databaseFile = optionValue(args, "--database", true)!;
const taskId = optionValue(args, "--task", true)!;
const exportDirectory = resolve(optionValue(args, "--export-directory", true)!);
const hostResultPath = resolve(optionValue(args, "--host-result", true)!);
const outputPath = resolve(optionValue(args, "--output", true)!);
if (isAbsolute(databaseFile) || dirname(databaseFile) !== ".") throw new Error("--database 必须是 --data-dir 下的文件名");
if (outputPath.startsWith(`${dataDir}/`) || exportDirectory.startsWith(`${dataDir}/`)) throw new Error("输出和 Evidence 导出目录必须位于受管数据目录之外");
const root = fileURLToPath(new URL("../..", import.meta.url));
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" }).trim();
if (dirty) throw new Error("运维发布资格证据只能从干净固定提交生成；请先提交或移除工作树修改");
const sha256 = async (path: string) => createHash("sha256").update(await readFile(path)).digest("hex");
const host = parseOperationalHostResult(JSON.parse(await readFile(hostResultPath, "utf8")) as unknown);
const result = await runOperationalReadiness({
  commit,
  expectedHelperSha256: await sha256(resolve(root, "host-helper/huntwarden_helper.py")),
  expectedScriptSha256: await sha256(resolve(root, "acceptance/operational/qualify-host.sh")),
  baseDir: dataDir,
  databaseFile,
  taskId,
  outputDirectory: exportDirectory,
  host,
});
await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
if (result.status !== "PASS") {
  process.stderr.write(`运维资格验收失败:\n- ${result.failures.join("\n- ")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`运维资格验收通过:schema v${result.migration.fromVersion}->v${result.migration.toVersion},结果已写入 ${outputPath}\n`);
}
