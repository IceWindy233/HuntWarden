import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DesktopCredentialStore, EncryptedCredentialStore, type SecretCipher } from "../../src/credentials/credential-store.js";

class TestCipher implements SecretCipher {
  constructor(private readonly secure = true) {}
  async encrypt(value: string): Promise<string> { return Buffer.from(value, "utf8").toString("base64").split("").reverse().join(""); }
  async decrypt(value: string): Promise<string> { return Buffer.from(value.split("").reverse().join(""), "base64").toString("utf8"); }
  async isSecure(): Promise<boolean> { return this.secure; }
  async backend(): Promise<string> { return this.secure ? "test-secure" : "test-insecure"; }
}

class RotatedTestCipher extends TestCipher {
  override async decrypt(value: string): Promise<string> {
    if (value === "legacy-app-ciphertext") throw new Error("旧应用安全存储无法解密");
    return await super.decrypt(value);
  }
}

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("DesktopCredentialStore", () => {
  it("持久化密钥只写入密文并可覆盖、查询和删除", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-credential-"));
    directories.push(directory);
    const path = join(directory, "secure", "credentials.enc.json");
    const persistent = new EncryptedCredentialStore(path, new TestCipher());
    const store = new DesktopCredentialStore(persistent);
    await persistent.initialize();
    await store.saveApiKey("deepseek", "sk-secret-value", true);

    expect(await store.read("deepseek")).toEqual({ type: "api_key", key: "sk-secret-value" });
    expect(await readFile(path, "utf8")).not.toContain("sk-secret-value");
    expect(await store.status("deepseek")).toMatchObject({ configured: true, persistent: true, backend: "test-secure" });
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await stat(join(directory, "secure"))).mode & 0o777).toBe(0o700);

    await store.saveApiKey("deepseek", "session-only", false);
    expect(await store.status("deepseek")).toMatchObject({ configured: true, persistent: false, source: "当前会话" });
    expect(await store.read("deepseek")).toEqual({ type: "api_key", key: "session-only" });
    await store.delete("deepseek");
    expect((await store.status("deepseek")).configured).toBe(false);
  });

  it("不安全后端拒绝持久化，但允许仅会话凭据", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-credential-insecure-"));
    directories.push(directory);
    const persistent = new EncryptedCredentialStore(join(directory, "credentials.enc.json"), new TestCipher(false));
    const store = new DesktopCredentialStore(persistent);
    await persistent.initialize();
    await expect(store.saveApiKey("deepseek", "persist-me", true)).rejects.toThrow(/拒绝持久化/);
    await store.saveApiKey("deepseek", "session-ok", false);
    expect(await store.read("deepseek")).toEqual({ type: "api_key", key: "session-ok" });
  });

  it("重新保存时备份并替换旧应用不可解密的密文", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-credential-rotated-"));
    directories.push(directory);
    const path = join(directory, "credentials.enc.json");
    await writeFile(path, `${JSON.stringify({ version: 1, entries: { deepseek: "legacy-app-ciphertext" } }, null, 2)}\n`, { mode: 0o600 });
    const persistent = new EncryptedCredentialStore(path, new RotatedTestCipher());
    const store = new DesktopCredentialStore(persistent);

    expect(await store.status("deepseek")).toMatchObject({ configured: false, persistent: false, persistentIssue: expect.stringMatching(/重新输入/) });
    const result = await store.saveApiKey("deepseek", "new-key", true);

    expect(result.recoveredUnreadableEntry).toBe(true);
    expect(await store.read("deepseek")).toEqual({ type: "api_key", key: "new-key" });
    const backups = (await readdir(directory)).filter((name) => name.startsWith("credentials.enc.json.unreadable-") && name.endsWith(".bak"));
    expect(backups).toHaveLength(1);
    expect(await readFile(join(directory, backups[0]!), "utf8")).toContain("legacy-app-ciphertext");
    expect((await stat(join(directory, backups[0]!))).mode & 0o777).toBe(0o600);
  });
});
