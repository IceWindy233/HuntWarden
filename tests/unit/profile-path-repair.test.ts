import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findLocalLabStateDir, isInvalidPackagedLabCredentialPath, repairProfilePaths } from "../../src/config/profile-path-repair.js";
import { testConfig } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("Profile path repair", () => {
  it("从打包应用祖先目录定位外部 Lab 状态", async () => {
    const root = await mkdtemp(join(tmpdir(), "huntwarden-path-repair-"));
    directories.push(root);
    const state = join(root, "labs", ".lab-state");
    await mkdir(state, { recursive: true });
    await Promise.all([writeFile(join(state, "id_ed25519"), "key"), writeFile(join(state, "known_hosts"), "host")]);
    const appPath = join(root, "out", "HuntWarden-darwin-arm64", "HuntWarden.app", "Contents", "Resources", "app.asar");
    expect(await findLocalLabStateDir({ appPath, cwd: "/" })).toBe(state);
  });

  it("修复旧包与当前 app.asar 中不可用的 Lab 凭据路径", () => {
    const config = testConfig("/tmp/runtime");
    config.executor.privateKeyPath = "/workspace/SecHostAgent/out/SecHostAgent.app/Contents/Resources/app.asar/labs/.lab-state/id_ed25519";
    config.executor.knownHostsPath = "/workspace/HuntWarden/out/HuntWarden.app/Contents/Resources/app.asar/labs/.lab-state/known_hosts";
    expect(repairProfilePaths(config, { appPath: "/workspace/HuntWarden/app.asar", currentUserData: "/data/HuntWarden", labStateDir: "/workspace/HuntWarden/labs/.lab-state" })).toBe(true);
    expect(config.executor.privateKeyPath).toBe("/workspace/HuntWarden/labs/.lab-state/id_ed25519");
    expect(config.executor.knownHostsPath).toBe("/workspace/HuntWarden/labs/.lab-state/known_hosts");
    expect(isInvalidPackagedLabCredentialPath("/Applications/HuntWarden.app/Contents/Resources/app.asar/labs/.lab-state/id_ed25519")).toBe(true);
  });
});
