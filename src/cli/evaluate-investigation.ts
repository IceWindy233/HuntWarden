import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { evaluateInvestigation, parseInvestigationEvaluationManifest } from "../evaluation/investigation-evaluator.js";
import { RuntimeStore } from "../storage/runtime-store.js";

if (!process.argv[2]) throw new Error("用法: npm run eval:investigation -- <manifest.json> [result.json]");
const manifestPath = resolve(process.argv[2]);
const outputPath = process.argv[3] ? resolve(process.argv[3]) : undefined;
const manifest = parseInvestigationEvaluationManifest(JSON.parse(await readFile(manifestPath, "utf8")));
const baseDir = resolve(process.env.HUNTWARDEN_DATA_DIR ?? "data");
const store = await RuntimeStore.open(baseDir, process.env.HUNTWARDEN_DATABASE_FILE ?? "runtime.db");
try {
  const result = evaluateInvestigation(store, manifest);
  const text = `${JSON.stringify(result, null, 2)}\n`;
  if (outputPath) await writeFile(outputPath, text, { mode: 0o600 }); else process.stdout.write(text);
  if (result.status !== "PASS") process.exitCode = 1;
} finally { store.close(); }
