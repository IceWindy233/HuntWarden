#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const args = process.argv.slice(2);
const index = args.indexOf("--output");
if (index < 0 || !args[index + 1]) throw new Error("用法: node scripts/write-build-identity.mjs --output <path>");
const root = resolve(new URL("..", import.meta.url).pathname);
const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" }).trim();
if (dirty) throw new Error("拒绝为非干净工作树写入发布构建身份");
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error("无法取得完整 Git 提交身份");
const output = resolve(args[index + 1]);
mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
writeFileSync(output, `${JSON.stringify({ schemaVersion: 1, commit, clean: true })}\n`, { encoding: "utf8", mode: 0o600 });
