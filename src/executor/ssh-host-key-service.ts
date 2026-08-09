import { createHash, createHmac, randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { chmod, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { Client } from "ssh2";
import { InvalidArgumentError, TargetUnavailableError } from "../common/errors.js";

export type HostKeyTrustStatus = "TRUSTED" | "UNKNOWN" | "CHANGED" | "REVOKED";

export interface SshHostKeyDiscovery {
  host: string;
  port: number;
  resolvedAddresses: { address: string; family: 4 | 6 }[];
  algorithm: string;
  fingerprint: string;
  keySummary: string;
  trustStatus: HostKeyTrustStatus;
  knownHostsPath: string;
  knownHostsExists: boolean;
  matchedHostTokens: string[];
  existingFingerprints: string[];
}

interface DiscoveredKey extends SshHostKeyDiscovery { publicKey: Buffer }

interface KnownHostEntry {
  marker?: string;
  hosts: string[];
  algorithm: string;
  publicKey: Buffer;
}

const HOST = /^[^\s\0]{1,253}$/;
const HASHED_HOST = /^\|1\|([^|]+)\|([^|]+)$/;

export function knownHostToken(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${port}`;
}

export function hostKeyFingerprint(publicKey: Buffer): string {
  return `SHA256:${createHash("sha256").update(publicKey).digest("base64").replace(/=+$/, "")}`;
}

function parseSshString(value: Buffer): string {
  if (value.length < 4) throw new Error("Host Key 数据过短");
  const length = value.readUInt32BE(0);
  if (length < 1 || length > value.length - 4 || length > 256) throw new Error("Host Key 算法字段无效");
  return value.subarray(4, 4 + length).toString("ascii");
}

function parseKnownHosts(text: string): KnownHostEntry[] {
  const entries: KnownHostEntry[] = [];
  for (const raw of text.split(/\r?\n/u)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const fields = line.split(/\s+/u);
    const marker = fields[0]?.startsWith("@") ? fields.shift() : undefined;
    const hostField = fields.shift();
    const algorithm = fields.shift();
    const encoded = fields.shift();
    if (!hostField || !algorithm || !encoded) continue;
    try {
      const publicKey = Buffer.from(encoded, "base64");
      if (publicKey.length === 0 || parseSshString(publicKey) !== algorithm) continue;
      entries.push({ ...(marker ? { marker } : {}), hosts: hostField.split(","), algorithm, publicKey });
    } catch { /* malformed lines do not become trusted entries */ }
  }
  return entries;
}

function wildcardMatches(pattern: string, candidate: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/gu, "\\$&").replace(/\*/gu, ".*").replace(/\?/gu, ".");
  return new RegExp(`^${escaped}$`, "iu").test(candidate);
}

function hashedHostMatches(pattern: string, candidate: string): boolean {
  const match = HASHED_HOST.exec(pattern);
  if (!match) return false;
  try {
    const salt = Buffer.from(match[1]!, "base64");
    const expected = Buffer.from(match[2]!, "base64");
    const actual = createHmac("sha1", salt).update(candidate).digest();
    return expected.length === actual.length && expected.equals(actual);
  } catch { return false; }
}

function hostPatternMatches(pattern: string, candidates: string[]): boolean {
  return candidates.some((candidate) => pattern.startsWith("|1|")
    ? hashedHostMatches(pattern, candidate)
    : wildcardMatches(pattern, candidate));
}

function entryMatches(entry: KnownHostEntry, candidates: string[]): boolean {
  if (entry.hosts.some((pattern) => pattern.startsWith("!") && hostPatternMatches(pattern.slice(1), candidates))) return false;
  return entry.hosts.some((pattern) => !pattern.startsWith("!") && hostPatternMatches(pattern, candidates));
}

export function evaluateKnownHosts(
  text: string,
  host: string,
  port: number,
  resolvedAddresses: string[],
  publicKey: Buffer,
): Pick<SshHostKeyDiscovery, "trustStatus" | "matchedHostTokens" | "existingFingerprints"> {
  const tokens = [...new Set([knownHostToken(host, port), ...resolvedAddresses.map((address) => knownHostToken(address, port))])];
  const entries = parseKnownHosts(text).filter((entry) => entry.marker !== "@cert-authority" && entryMatches(entry, tokens));
  const matchedHostTokens = entries.flatMap((entry) => entry.hosts);
  const sameKey = entries.filter((entry) => entry.publicKey.equals(publicKey));
  const existingFingerprints = [...new Set(entries.map((entry) => hostKeyFingerprint(entry.publicKey)))];
  if (sameKey.some((entry) => entry.marker === "@revoked")) return { trustStatus: "REVOKED", matchedHostTokens, existingFingerprints };
  if (sameKey.some((entry) => entry.marker !== "@revoked")) return { trustStatus: "TRUSTED", matchedHostTokens, existingFingerprints };
  if (entries.length > 0) return { trustStatus: "CHANGED", matchedHostTokens, existingFingerprints };
  return { trustStatus: "UNKNOWN", matchedHostTokens: [], existingFingerprints: [] };
}

export class SshHostKeyService {
  constructor(private readonly timeoutMs = 10_000) {}

  async discover(input: { host: string; port: number; knownHostsPath: string }, signal?: AbortSignal): Promise<SshHostKeyDiscovery> {
    return this.publicResult(await this.discoverKey(input, signal));
  }

  async confirm(input: { host: string; port: number; knownHostsPath: string; expectedFingerprint: string }, signal?: AbortSignal): Promise<SshHostKeyDiscovery> {
    const found = await this.discoverKey(input, signal);
    if (found.fingerprint !== input.expectedFingerprint) throw new Error("确认期间 Host Key 已变化，已阻止写入 known_hosts");
    if (found.trustStatus === "CHANGED" || found.trustStatus === "REVOKED") throw new Error("known_hosts 已存在冲突或撤销的 Host Key，禁止自动覆盖");
    if (found.trustStatus === "TRUSTED") return this.publicResult(found);
    await this.atomicAppend(input.knownHostsPath, `${knownHostToken(input.host, input.port)} ${found.algorithm} ${found.publicKey.toString("base64")} huntwarden-confirmed\n`);
    const verified = evaluateKnownHosts(
      await readFile(input.knownHostsPath, "utf8"), input.host, input.port,
      found.resolvedAddresses.map((item) => item.address), found.publicKey,
    );
    if (verified.trustStatus !== "TRUSTED") throw new Error("known_hosts 写入后核验失败");
    return this.publicResult({ ...found, knownHostsExists: true, ...verified });
  }

  private async discoverKey(input: { host: string; port: number; knownHostsPath: string }, signal?: AbortSignal): Promise<DiscoveredKey> {
    this.validateInput(input);
    const resolvedAddresses = await lookup(input.host, { all: true, verbatim: true })
      .then((values) => values.map((value) => ({ address: value.address, family: value.family as 4 | 6 })))
      .catch((error) => { throw new TargetUnavailableError(`无法解析目标主机: ${error instanceof Error ? error.message : String(error)}`); });
    const publicKey = await this.fetchKey(input.host, input.port, signal);
    const algorithm = parseSshString(publicKey);
    const fingerprint = hostKeyFingerprint(publicKey);
    let knownHosts = "";
    let knownHostsExists = true;
    try { knownHosts = await readFile(input.knownHostsPath, "utf8"); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      knownHostsExists = false;
    }
    const trust = evaluateKnownHosts(knownHosts, input.host, input.port, resolvedAddresses.map((item) => item.address), publicKey);
    const encoded = publicKey.toString("base64");
    return {
      host: input.host, port: input.port, resolvedAddresses, algorithm, fingerprint,
      keySummary: encoded.length <= 28 ? encoded : `${encoded.slice(0, 16)}…${encoded.slice(-8)}`,
      knownHostsPath: input.knownHostsPath, knownHostsExists, ...trust, publicKey,
    };
  }

  private fetchKey(host: string, port: number, signal?: AbortSignal): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const client = new Client();
      let captured: Buffer | undefined;
      let settled = false;
      const finish = (error?: Error, key?: Buffer) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        client.end();
        if (error) reject(error); else resolve(key!);
      };
      const abort = () => finish(new TargetUnavailableError("Host Key 发现已中止"));
      const timer = setTimeout(() => finish(new TargetUnavailableError(`Host Key 发现超过 ${this.timeoutMs}ms`)), this.timeoutMs);
      signal?.addEventListener("abort", abort, { once: true });
      client.on("error", (error) => {
        if (!settled && captured) finish(undefined, captured);
        else if (!settled) finish(new TargetUnavailableError(`Host Key 发现失败: ${error.message}`, { cause: error }));
      });
      try {
        client.connect({
          host, port, username: "huntwarden-host-key-discovery", readyTimeout: this.timeoutMs,
          authHandler: [],
          hostVerifier: (key: Buffer) => {
            captured = Buffer.from(key);
            return false;
          },
        });
      } catch (error) {
        finish(new TargetUnavailableError(`Host Key 发现失败: ${error instanceof Error ? error.message : String(error)}`));
      }
    });
  }

  private validateInput(input: { host: string; port: number; knownHostsPath: string }): void {
    if (!HOST.test(input.host)) throw new InvalidArgumentError("目标主机格式无效");
    if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65_535) throw new InvalidArgumentError("SSH 端口无效");
    if (!isAbsolute(input.knownHostsPath) || input.knownHostsPath.includes("\0")) throw new InvalidArgumentError("known_hosts 必须使用绝对路径");
  }

  private async atomicAppend(path: string, line: string): Promise<void> {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    let current = "";
    try {
      const info = await lstat(path);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error("known_hosts 必须是常规文件，不能是符号链接");
      current = await readFile(path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const temp = join(dirname(path), `.${randomUUID()}.known-hosts.tmp`);
    const handle = await open(temp, "wx", 0o600);
    try {
      const prefix = current && !current.endsWith("\n") ? `${current}\n` : current;
      await handle.writeFile(prefix + line, "utf8");
      await handle.sync();
      await handle.close();
      await rename(temp, path);
      await chmod(path, 0o600);
    } catch (error) {
      await handle.close().catch(() => undefined);
      await unlink(temp).catch(() => undefined);
      throw error;
    }
  }

  private publicResult(value: DiscoveredKey): SshHostKeyDiscovery {
    const { publicKey: _publicKey, ...result } = value;
    return result;
  }
}
