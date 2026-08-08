import { randomUUID } from "node:crypto";
import { chmod, copyFile, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  InMemoryCredentialStore,
  type AuthOperationOptions,
  type Credential,
  type CredentialInfo,
  type CredentialStore,
} from "@earendil-works/pi-ai";

export interface SecretCipher {
  encrypt(plainText: string): Promise<string>;
  decrypt(cipherText: string): Promise<string>;
  isSecure(): Promise<boolean>;
  backend(): Promise<string>;
}

interface CredentialFile {
  version: 1;
  entries: Record<string, string>;
}

export interface CredentialReplacementResult {
  recoveredUnreadableEntry: boolean;
  backupPath?: string;
}

async function atomicWrite(path: string, content: string): Promise<void> {
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temp, content, { encoding: "utf8", mode: 0o600 });
  await chmod(temp, 0o600);
  try { await rename(temp, path); } catch (error) { await unlink(temp).catch(() => undefined); throw error; }
  await chmod(path, 0o600);
}

export class EncryptedCredentialStore implements CredentialStore {
  private readonly chains = new Map<string, Promise<unknown>>();

  constructor(readonly path: string, private readonly cipher: SecretCipher) {
    this.path = resolve(path);
  }

  async initialize(): Promise<void> {
    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
    try { await readFile(this.path, "utf8"); await chmod(this.path, 0o600); } catch { await this.writeFile({ version: 1, entries: {} }); }
  }

  async read(providerId: string, options?: AuthOperationOptions): Promise<Credential | undefined> {
    options?.signal?.throwIfAborted();
    const file = await this.readFile();
    const encrypted = file.entries[providerId];
    if (!encrypted) return undefined;
    let plainText: string;
    try {
      plainText = await this.cipher.decrypt(encrypted);
    } catch {
      throw new Error(`无法解密 ${providerId} 的已保存凭据；如果该凭据来自旧版应用，请重新输入并保存 Key`);
    }
    options?.signal?.throwIfAborted();
    try {
      return JSON.parse(plainText) as Credential;
    } catch {
      throw new Error(`${providerId} 的已保存凭据内容无效；请重新输入并保存 Key`);
    }
  }

  async replace(providerId: string, credential: Credential, options?: AuthOperationOptions): Promise<CredentialReplacementResult> {
    return await this.enqueue(providerId, async () => {
      options?.signal?.throwIfAborted();
      if (!(await this.cipher.isSecure())) throw new Error(`系统安全存储不可用（${await this.cipher.backend()}），拒绝持久化凭据`);

      const file = await this.readFile();
      let backupPath: string | undefined;
      const existing = file.entries[providerId];
      if (existing) {
        try {
          JSON.parse(await this.cipher.decrypt(existing));
        } catch {
          backupPath = await this.backupUnreadableFile();
        }
      }

      options?.signal?.throwIfAborted();
      file.entries[providerId] = await this.cipher.encrypt(JSON.stringify(credential));
      await this.writeFile(file);
      return {
        recoveredUnreadableEntry: Boolean(backupPath),
        ...(backupPath ? { backupPath } : {}),
      };
    });
  }

  async list(options?: AuthOperationOptions): Promise<readonly CredentialInfo[]> {
    options?.signal?.throwIfAborted();
    const file = await this.readFile();
    const result: CredentialInfo[] = [];
    for (const providerId of Object.keys(file.entries)) {
      const credential = await this.read(providerId, options);
      if (credential) result.push({ providerId, type: credential.type });
    }
    return result;
  }

  async modify(
    providerId: string,
    fn: (current: Credential | undefined) => Promise<Credential | undefined>,
    options?: AuthOperationOptions,
  ): Promise<Credential | undefined> {
    return await this.enqueue(providerId, async () => {
      options?.signal?.throwIfAborted();
      const current = await this.read(providerId, options);
      const next = await fn(current);
      if (next === undefined) return current;
      if (!(await this.cipher.isSecure())) throw new Error(`系统安全存储不可用（${await this.cipher.backend()}），拒绝持久化凭据`);
      const file = await this.readFile();
      file.entries[providerId] = await this.cipher.encrypt(JSON.stringify(next));
      await this.writeFile(file);
      return next;
    });
  }

  async delete(providerId: string, options?: AuthOperationOptions): Promise<void> {
    await this.enqueue(providerId, async () => {
      options?.signal?.throwIfAborted();
      const file = await this.readFile();
      delete file.entries[providerId];
      await this.writeFile(file);
    });
  }

  async getBackend(): Promise<{ secure: boolean; backend: string }> {
    return { secure: await this.cipher.isSecure(), backend: await this.cipher.backend() };
  }

  private async enqueue<T>(providerId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.chains.get(providerId) ?? Promise.resolve();
    const current = previous.catch(() => undefined).then(operation);
    this.chains.set(providerId, current);
    try { return await current; } finally { if (this.chains.get(providerId) === current) this.chains.delete(providerId); }
  }

  private async readFile(): Promise<CredentialFile> {
    await this.initializeDirectory();
    try {
      const value = JSON.parse(await readFile(this.path, "utf8")) as CredentialFile;
      if (value.version !== 1 || !value.entries || typeof value.entries !== "object") throw new Error("版本无效");
      return value;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, entries: {} };
      throw new Error(`凭据存储损坏: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async writeFile(file: CredentialFile): Promise<void> {
    await this.initializeDirectory();
    await atomicWrite(this.path, `${JSON.stringify(file, null, 2)}\n`);
  }

  private async backupUnreadableFile(): Promise<string> {
    const backupPath = `${this.path}.unreadable-${Date.now()}-${randomUUID()}.bak`;
    await copyFile(this.path, backupPath);
    await chmod(backupPath, 0o600);
    return backupPath;
  }

  private async initializeDirectory(): Promise<void> {
    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
  }
}

export class DesktopCredentialStore implements CredentialStore {
  private readonly session = new InMemoryCredentialStore();

  constructor(readonly persistent: EncryptedCredentialStore) {}

  async read(providerId: string, options?: AuthOperationOptions): Promise<Credential | undefined> {
    return await this.session.read(providerId, options) ?? await this.persistent.read(providerId, options);
  }

  async list(options?: AuthOperationOptions): Promise<readonly CredentialInfo[]> {
    const [session, persistent] = await Promise.all([this.session.list(options), this.persistent.list(options)]);
    const merged = new Map(persistent.map((item) => [item.providerId, item]));
    for (const item of session) merged.set(item.providerId, item);
    return [...merged.values()];
  }

  async modify(
    providerId: string,
    fn: (current: Credential | undefined) => Promise<Credential | undefined>,
    options?: AuthOperationOptions,
  ): Promise<Credential | undefined> {
    const inSession = await this.session.read(providerId, options);
    return inSession
      ? await this.session.modify(providerId, fn, options)
      : await this.persistent.modify(providerId, fn, options);
  }

  async delete(providerId: string, options?: AuthOperationOptions): Promise<void> {
    await Promise.all([this.session.delete(providerId, options), this.persistent.delete(providerId, options)]);
  }

  async saveApiKey(providerId: string, key: string, persist: boolean): Promise<CredentialReplacementResult> {
    const normalized = key.trim();
    if (!normalized || normalized.length > 16_384) throw new Error("API Key 不能为空且不能超过 16384 字符");
    if (persist) {
      const result = await this.persistent.replace(providerId, { type: "api_key", key: normalized });
      await this.session.delete(providerId);
      return result;
    }
    await this.session.modify(providerId, async () => ({ type: "api_key", key: normalized }));
    await this.persistent.delete(providerId);
    return { recoveredUnreadableEntry: false };
  }

  async status(providerId: string): Promise<{ configured: boolean; persistent: boolean; source?: string; backend: string; secure: boolean; persistentIssue?: string }> {
    const session = await this.session.read(providerId);
    let persistent: Credential | undefined;
    let persistentIssue: string | undefined;
    try { persistent = await this.persistent.read(providerId); }
    catch (error) { persistentIssue = error instanceof Error ? error.message : String(error); }
    const backend = await this.persistent.getBackend();
    return {
      configured: Boolean(session ?? persistent),
      persistent: Boolean(persistent),
      ...(session ? { source: "当前会话" } : persistent ? { source: "系统安全存储" } : {}),
      ...(persistentIssue ? { persistentIssue } : {}),
      backend: backend.backend,
      secure: backend.secure,
    };
  }
}
