import { createHmac, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Server } from "ssh2";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateKnownHosts, hostKeyFingerprint, knownHostToken, SshHostKeyService } from "../../src/executor/ssh-host-key-service.js";

function sshString(value: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length);
  return Buffer.concat([length, value]);
}

function ed25519Blob(seed: number): Buffer {
  return Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(Buffer.alloc(32, seed))]);
}

function line(host: string, key: Buffer, marker = ""): string {
  return `${marker ? `${marker} ` : ""}${host} ssh-ed25519 ${key.toString("base64")}\n`;
}

const servers: Server[] = [];
afterEach(async () => await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))));

describe("SSH Host Key 发现与 known_hosts 核验", () => {
  it("支持标准、非标准端口、hashed host、变化和撤销状态", () => {
    const key = ed25519Blob(1);
    const other = ed25519Blob(2);
    expect(evaluateKnownHosts(line("server.example", key), "server.example", 22, [], key).trustStatus).toBe("TRUSTED");
    expect(evaluateKnownHosts(line("[server.example]:2222", key), "server.example", 2222, [], key).trustStatus).toBe("TRUSTED");

    const token = knownHostToken("server.example", 2222);
    const salt = Buffer.alloc(20, 7);
    const digest = createHmac("sha1", salt).update(token).digest();
    const hashed = `|1|${salt.toString("base64")}|${digest.toString("base64")}`;
    expect(evaluateKnownHosts(line(hashed, key), "server.example", 2222, [], key).trustStatus).toBe("TRUSTED");
    expect(evaluateKnownHosts(line(token, other), "server.example", 2222, [], key)).toMatchObject({
      trustStatus: "CHANGED", existingFingerprints: [hostKeyFingerprint(other)],
    });
    expect(evaluateKnownHosts(line(token, key, "@revoked"), "server.example", 2222, [], key).trustStatus).toBe("REVOKED");
  });

  it("无凭据发现未知 Key，显式确认后原子写入并变为可信", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const server = new Server({ hostKeys: [privateKey.export({ format: "pem", type: "pkcs1" })] }, (client) => {
      client.on("error", () => undefined);
      client.on("authentication", (context) => context.reject());
    });
    servers.push(server);
    await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("测试 SSH 端口无效");
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-host-key-"));
    const path = join(directory, "known_hosts");
    const service = new SshHostKeyService(5_000);

    const unknown = await service.discover({ host: "127.0.0.1", port: address.port, knownHostsPath: path });
    expect(unknown).toMatchObject({ trustStatus: "UNKNOWN", algorithm: "ssh-rsa", knownHostsExists: false });
    expect(unknown).not.toHaveProperty("publicKey");

    const trusted = await service.confirm({
      host: "127.0.0.1", port: address.port, knownHostsPath: path, expectedFingerprint: unknown.fingerprint,
    });
    expect(trusted.trustStatus).toBe("TRUSTED");
    expect(await readFile(path, "utf8")).toMatch(new RegExp(`^\\[127\\.0\\.0\\.1\\]:${address.port} ssh-rsa `));
    expect((await service.discover({ host: "127.0.0.1", port: address.port, knownHostsPath: path })).trustStatus).toBe("TRUSTED");
  });

  it("已有冲突 Key 时禁止确认和覆盖", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const server = new Server({ hostKeys: [privateKey.export({ format: "pem", type: "pkcs1" })] }, (client) => {
      client.on("error", () => undefined);
      client.on("authentication", (context) => context.reject());
    });
    servers.push(server);
    await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("测试 SSH 端口无效");
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-host-key-conflict-"));
    const path = join(directory, "known_hosts");
    const original = line(knownHostToken("127.0.0.1", address.port), ed25519Blob(9));
    await writeFile(path, original, { mode: 0o600 });
    const service = new SshHostKeyService(5_000);
    const changed = await service.discover({ host: "127.0.0.1", port: address.port, knownHostsPath: path });
    expect(changed.trustStatus).toBe("CHANGED");
    await expect(service.confirm({
      host: "127.0.0.1", port: address.port, knownHostsPath: path, expectedFingerprint: changed.fingerprint,
    })).rejects.toThrow(/禁止自动覆盖/);
    expect(await readFile(path, "utf8")).toBe(original);
  });
});
