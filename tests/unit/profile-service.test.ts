import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ConfigProfileService } from "../../src/config/profile-service.js";
import { testConfig } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("ConfigProfileService", () => {
  it("原子保存、激活、导出并保持严格文件权限", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-profile-"));
    directories.push(directory);
    const service = new ConfigProfileService(join(directory, "configuration"));
    const first = await service.save({ profileId: "deepseek", name: "DeepSeek", config: testConfig(join(directory, "runtime")) });
    const second = await service.save({ profileId: "openai", name: "OpenAI", config: { ...testConfig(join(directory, "runtime")), model: { source: "builtin", provider: "openai", model: "gpt-5.6-terra", thinkingLevel: "medium" } } });

    expect(first.active).toBe(true);
    expect(second.active).toBe(false);
    await service.activate("openai");
    expect((await service.getActive())?.profileId).toBe("openai");
    expect((await service.list())[0]).toMatchObject({ profileId: "openai", active: true });

    const destination = join(directory, "export.yaml");
    await service.export("openai", destination);
    expect(await readFile(destination, "utf8")).toContain("gpt-5.6-terra");
    expect((await stat(service.rootDir)).mode & 0o777).toBe(0o700);
    expect((await stat(join(service.profilesDir, "openai.yaml"))).mode & 0o777).toBe(0o600);
    expect((await stat(destination)).mode & 0o777).toBe(0o600);
  });

  it("拒绝非法 ID、损坏索引和删除活动 Profile", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-profile-invalid-"));
    directories.push(directory);
    const service = new ConfigProfileService(join(directory, "configuration"));
    await expect(service.save({ profileId: "../escape", name: "bad", config: testConfig(directory) })).rejects.toThrow(/ID 格式无效/);
    await service.save({ profileId: "valid", name: "valid", config: testConfig(directory) });
    await expect(service.delete("valid")).rejects.toThrow(/活动 Profile/);
    await writeFile(join(service.rootDir, "settings.json"), "not-json", "utf8");
    await expect(service.list()).rejects.toThrow(/索引损坏/);
  });
});
