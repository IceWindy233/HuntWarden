import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { evaluateInvestigation, parseInvestigationEvaluationManifest, type InvestigationEvaluationQualification } from "../evaluation/investigation-evaluator.js";
import { RuntimeStore } from "../storage/runtime-store.js";
import { optionValue } from "./options.js";

const args = process.argv.slice(2);
if (!args[0] || args[0].startsWith("--")) throw new Error("用法: npm run eval:investigation -- <manifest.json> [result.json] [--run run-result.json --truth-archive truth.tar.gz]");
const manifestPath = resolve(args[0]);
const outputPath = args[1] && !args[1].startsWith("--") ? resolve(args[1]) : undefined;
const options = args.slice(outputPath ? 2 : 1);
const seen = new Set<string>();
for (let index = 0; index < options.length; index += 2) {
  const name = options[index]!;
  if (!["--run", "--truth-archive"].includes(name) || seen.has(name) || !options[index + 1] || options[index + 1]!.startsWith("--")) throw new Error("评分选项无效、重复或缺少值");
  seen.add(name);
}
const manifest = parseInvestigationEvaluationManifest(JSON.parse(await readFile(manifestPath, "utf8")));
let qualification: InvestigationEvaluationQualification | undefined;
if (manifest.evaluationMode === "BLIND_RELEASE") {
  const runPath = resolve(optionValue(options, "--run", true)!);
  const archivePath = resolve(optionValue(options, "--truth-archive", true)!);
  const archiveSha256 = createHash("sha256").update(await readFile(archivePath)).digest("hex");
  if (archiveSha256 !== manifest.truthSet?.archiveSha256) throw new Error("独立真值归档 SHA-256 不一致");
  const { stdout } = await promisify(execFile)("tar", ["-xOf", archivePath, "truth.json"], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  qualification = { run: JSON.parse(await readFile(runPath, "utf8")), archivedTruth: JSON.parse(stdout), archiveSha256 };
} else if (options.length > 0) {
  throw new Error("DEVELOPMENT 不接受正式资格归档或运行账本");
}
const baseDir = resolve(process.env.HUNTWARDEN_DATA_DIR ?? "data");
const store = await RuntimeStore.open(baseDir, process.env.HUNTWARDEN_DATABASE_FILE ?? "runtime.db");
try {
  const result = evaluateInvestigation(store, manifest, qualification);
  const text = `${JSON.stringify(result, null, 2)}\n`;
  if (outputPath) await writeFile(outputPath, text, { mode: 0o600, flag: "wx" }); else process.stdout.write(text);
  if (result.status !== "PASS") process.exitCode = 1;
} finally { store.close(); }
