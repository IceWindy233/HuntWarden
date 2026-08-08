import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import type { AppConfig } from "./schema.js";
import { loadConfig, normalizeConfig, parseConfig, serializeConfig } from "./load-config.js";
import type { ConfigProfile, ConfigProfileSummary } from "../gui/contracts.js";

const PROFILE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

interface ProfileMetadata {
  profileId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

interface ProfileIndex {
  version: 1;
  activeProfileId?: string;
  profiles: ProfileMetadata[];
}

async function atomicWrite(path: string, content: string): Promise<void> {
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temp, content, { encoding: "utf8", mode: 0o600 });
  await chmod(temp, 0o600);
  try { await rename(temp, path); } catch (error) { await unlink(temp).catch(() => undefined); throw error; }
  await chmod(path, 0o600);
}

export class ConfigProfileService {
  readonly profilesDir: string;
  private readonly indexPath: string;

  constructor(readonly rootDir: string) {
    this.rootDir = resolve(rootDir);
    this.profilesDir = join(this.rootDir, "profiles");
    this.indexPath = join(this.rootDir, "settings.json");
  }

  async initialize(): Promise<void> {
    await mkdir(this.rootDir, { recursive: true, mode: 0o700 });
    await mkdir(this.profilesDir, { recursive: true, mode: 0o700 });
    await Promise.all([chmod(this.rootDir, 0o700), chmod(this.profilesDir, 0o700)]);
    try { await readFile(this.indexPath, "utf8"); } catch { await this.writeIndex({ version: 1, profiles: [] }); }
  }

  async seed(input: { profileId: string; name: string; configPath: string; active?: boolean }): Promise<void> {
    await this.initialize();
    const index = await this.readIndex();
    if (index.profiles.some((item) => item.profileId === input.profileId)) return;
    const config = await loadConfig(input.configPath);
    await this.save({ profileId: input.profileId, name: input.name, config });
    if (input.active || !index.activeProfileId) await this.activate(input.profileId);
  }

  async list(): Promise<ConfigProfileSummary[]> {
    const index = await this.readIndex();
    const summaries = await Promise.all(index.profiles.map(async (metadata) => {
      const config = await loadConfig(this.profilePath(metadata.profileId));
      return {
        profileId: metadata.profileId,
        name: metadata.name,
        provider: config.model.provider,
        model: config.model.model,
        active: index.activeProfileId === metadata.profileId,
        updatedAt: metadata.updatedAt,
      } satisfies ConfigProfileSummary;
    }));
    return summaries.sort((a, b) => Number(b.active) - Number(a.active) || b.updatedAt.localeCompare(a.updatedAt));
  }

  async get(profileId: string): Promise<ConfigProfile> {
    this.assertProfileId(profileId);
    const index = await this.readIndex();
    const metadata = index.profiles.find((item) => item.profileId === profileId);
    if (!metadata) throw new Error(`配置 Profile 不存在: ${profileId}`);
    const path = this.profilePath(profileId);
    const yamlPreview = await readFile(path, "utf8");
    const config = parseConfig(yamlPreview, path);
    return {
      profileId,
      name: metadata.name,
      provider: config.model.provider,
      model: config.model.model,
      active: index.activeProfileId === profileId,
      updatedAt: metadata.updatedAt,
      config,
      yamlPreview,
    };
  }

  async getActive(): Promise<ConfigProfile | undefined> {
    const index = await this.readIndex();
    return index.activeProfileId ? await this.get(index.activeProfileId) : undefined;
  }

  async save(input: { profileId?: string; name: string; config: AppConfig }): Promise<ConfigProfile> {
    await this.initialize();
    const profileId = input.profileId ?? `profile-${randomUUID()}`;
    this.assertProfileId(profileId);
    const name = input.name.trim();
    if (!name || name.length > 80) throw new Error("Profile 名称不能为空且不能超过 80 字符");
    const path = this.profilePath(profileId);
    const config = normalizeConfig(input.config, path);
    await atomicWrite(path, serializeConfig(config));
    const index = await this.readIndex();
    const now = new Date().toISOString();
    const existing = index.profiles.find((item) => item.profileId === profileId);
    if (existing) { existing.name = name; existing.updatedAt = now; }
    else index.profiles.push({ profileId, name, createdAt: now, updatedAt: now });
    if (!index.activeProfileId) index.activeProfileId = profileId;
    await this.writeIndex(index);
    return await this.get(profileId);
  }

  async activate(profileId: string): Promise<void> {
    this.assertProfileId(profileId);
    const index = await this.readIndex();
    if (!index.profiles.some((item) => item.profileId === profileId)) throw new Error(`配置 Profile 不存在: ${profileId}`);
    index.activeProfileId = profileId;
    await this.writeIndex(index);
  }

  async delete(profileId: string): Promise<void> {
    this.assertProfileId(profileId);
    const index = await this.readIndex();
    if (index.activeProfileId === profileId) throw new Error("不能删除当前活动 Profile，请先切换");
    const before = index.profiles.length;
    index.profiles = index.profiles.filter((item) => item.profileId !== profileId);
    if (index.profiles.length === before) throw new Error(`配置 Profile 不存在: ${profileId}`);
    await unlink(this.profilePath(profileId)).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
    await this.writeIndex(index);
  }

  async import(path: string, name = basename(path).replace(/\.ya?ml$/i, "")): Promise<ConfigProfile> {
    const config = await loadConfig(path);
    return await this.save({ name, config });
  }

  async export(profileId: string, destination: string): Promise<void> {
    const profile = await this.get(profileId);
    await atomicWrite(resolve(destination), serializeConfig(profile.config));
  }

  private profilePath(profileId: string): string { return join(this.profilesDir, `${profileId}.yaml`); }

  private assertProfileId(profileId: string): void {
    if (!PROFILE_ID.test(profileId)) throw new Error("Profile ID 格式无效");
  }

  private async readIndex(): Promise<ProfileIndex> {
    await this.initializeDirectoriesOnly();
    try {
      const value = JSON.parse(await readFile(this.indexPath, "utf8")) as ProfileIndex;
      if (value.version !== 1 || !Array.isArray(value.profiles)) throw new Error("版本无效");
      return value;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, profiles: [] };
      throw new Error(`Profile 索引损坏: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async writeIndex(index: ProfileIndex): Promise<void> {
    await this.initializeDirectoriesOnly();
    await atomicWrite(this.indexPath, `${JSON.stringify(index, null, 2)}\n`);
  }

  private async initializeDirectoriesOnly(): Promise<void> {
    await mkdir(this.rootDir, { recursive: true, mode: 0o700 });
    await mkdir(this.profilesDir, { recursive: true, mode: 0o700 });
    await Promise.all([chmod(this.rootDir, 0o700), chmod(this.profilesDir, 0o700)]);
  }
}
